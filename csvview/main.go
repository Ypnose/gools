package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
)

const (
	defaultBufSize  = 256
	searchBatchSize = 64
)

type colInfo struct {
	width    int
	startPos int
}

// Clean reader for stdin to handle gpg output
type cleanReader struct {
	r io.Reader
}

type Table struct {
	data        [][]string
	cols        []colInfo
	currentRow  int
	currentCol  int
	scrollRow   int
	editMode    bool
	editBuf     strings.Builder
	separator   rune
	width       int
	height      int
	fromStdin   bool
	modified    bool
	saveMsg     string
	saveMsgTime int64
	search      struct {
		active  bool
		results [][2]int
		current int
		pattern string
		buf     strings.Builder
	}
	sort struct {
		col int
		asc bool
	}
	// Reusable buffers
	statusBuf strings.Builder
	formatBuf strings.Builder
	screen    tcell.Screen
}

func NewTable(separator rune, screen tcell.Screen) (*Table, error) {
	fi, _ := os.Stdin.Stat()
	fromStdin := (fi.Mode() & os.ModeCharDevice) == 0

	var input io.Reader
	if fromStdin {
		input = os.Stdin
	} else if len(flag.Args()) != 1 {
		return nil, fmt.Errorf("Please provide a CSV filename")
	} else if file, err := os.Open(flag.Args()[0]); err != nil {
		return nil, err
	} else {
		defer file.Close()
		input = file
	}

	reader := csv.NewReader(input)
	reader.LazyQuotes = true
	reader.FieldsPerRecord = -1
	reader.Comma = separator

	// Read and clean BOM if present
	data, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("Empty data")
	}

	// Remove BOM from the first cell if present
	if len(data[0]) > 0 && strings.HasPrefix(data[0][0], "\ufeff") {
		data[0][0] = strings.TrimPrefix(data[0][0], "\ufeff")
	}

	t := &Table{
		data:      data,
		fromStdin: fromStdin,
		separator: separator,
		screen:    screen,
		sort: struct {
			col int
			asc bool
		}{-1, true},
	}

	t.statusBuf.Grow(defaultBufSize)
	t.formatBuf.Grow(defaultBufSize)
	t.editBuf.Grow(defaultBufSize)
	t.search.buf.Grow(defaultBufSize)

	t.updateLayout()
	return t, nil
}

func (cr *cleanReader) Read(p []byte) (n int, err error) {
	n, err = cr.r.Read(p)
	for i := 0; i < n; i++ {
		if p[i] < 32 && p[i] != 9 && p[i] != 10 && p[i] != 13 {
			p[i] = ' '
		}
	}
	return n, err
}

func (t *Table) updateLayout() {
	t.width, t.height = t.screen.Size()

	// Find max columns and calculate widths
	maxCols := 0
	for _, row := range t.data {
		if len(row) > maxCols {
			maxCols = len(row)
		}
	}

	// Resize or create column info
	if cap(t.cols) < maxCols {
		t.cols = make([]colInfo, maxCols)
	} else {
		t.cols = t.cols[:maxCols]
		for i := range t.cols {
			t.cols[i] = colInfo{}
		}
	}

	// Normalize data and calculate column widths
	for i := range t.data {
		if len(t.data[i]) < maxCols {
			t.data[i] = append(t.data[i], make([]string, maxCols-len(t.data[i]))...)
		}
		for j, cell := range t.data[i] {
			if w := utf8.RuneCountInString(cell); w > t.cols[j].width {
				t.cols[j].width = w
			}
		}
	}

	// Calculate column positions
	pos := 0
	for i := range t.cols {
		t.cols[i].startPos = pos
		pos += t.cols[i].width + 2
	}
}

func (t *Table) draw() {
	t.updateLayout()
	t.screen.Clear()

	// Calculate visible columns
	startCol := t.findFirstVisibleColumn()
	maxRows := t.height - 2

	// Draw rows
	for i := 0; i < maxRows && i+t.scrollRow < len(t.data); i++ {
		t.drawRow(i, t.data[i+t.scrollRow], startCol)
	}

	t.drawStatus()
	t.screen.Show()
}

func (t *Table) findFirstVisibleColumn() int {
	// If current column fits on screen, try to show from beginning
	availWidth := t.width - 1

	if t.currentCol == 0 {
		return 0
	}

	totalWidth := t.cols[t.currentCol].width + 2
	startCol := t.currentCol

	for i := t.currentCol - 1; i >= 0; i-- {
		width := t.cols[i].width + 2
		if totalWidth+width > availWidth {
			break
		}
		totalWidth += width
		startCol = i
	}

	return startCol
}

func (t *Table) drawRow(y int, row []string, startCol int) {
	x := 0
	availWidth := t.width - 1

	for i := startCol; i < len(row); i++ {
		if i == t.currentCol && x >= availWidth {
			x = availWidth - min(t.cols[i].width+2, availWidth)
		}
		if x >= availWidth && i != t.currentCol {
			break
		}

		cell := row[i]
		style := tcell.StyleDefault
		if t.currentRow == y+t.scrollRow && t.currentCol == i {
			style = style.Reverse(true)
		}

		remainingWidth := availWidth - x
		colWidth := t.cols[i].width + 2

		if remainingWidth < colWidth {
			if i == t.currentCol {
				w := utf8.RuneCountInString(cell)
				if w > remainingWidth {
					runes := []rune(cell)
					if remainingWidth > 3 {
						cell = string(runes[:remainingWidth-3]) + "..."
					} else {
						cell = string(runes[:remainingWidth])
					}
				}
			} else {
				break
			}
		}

		// Show visual indicator for empty cells
		displayCell := cell
		if displayCell == "" {
			displayCell = "◌"
		}

		w := utf8.RuneCountInString(displayCell)
		drawString(t.screen, x, y, displayCell, style)
		if pad := min(t.cols[i].width-w, remainingWidth-w); pad > 0 {
			drawSpaces(t.screen, x+w, y, pad, style)
		}

		x += min(colWidth, remainingWidth)
	}
}

func (t *Table) drawStatus() {
	t.statusBuf.Reset()
	fmt.Fprintf(&t.statusBuf, "Row: %d/%d Col: %d/%d | ",
		t.currentRow+1, len(t.data),
		t.currentCol+1, len(t.cols))

	if t.fromStdin {
		t.statusBuf.WriteString("Press 'q' to quit")
	} else {
		t.statusBuf.WriteString("Press 'e' to edit, 's' to save, 'q' to quit")
	}

	if len(t.search.results) > 0 {
		fmt.Fprintf(&t.statusBuf, " | Match: %d/%d", t.search.current+1, len(t.search.results))
	}
	if t.sort.col >= 0 {
		order := "↑"
		if !t.sort.asc {
			order = "↓"
		}
		fmt.Fprintf(&t.statusBuf, " | Sorted by col %d %s", t.sort.col+1, order)
	}

	status := t.statusBuf.String()
	if w := utf8.RuneCountInString(status); w > t.width {
		status = string([]rune(status)[:t.width])
	}
	drawString(t.screen, 0, t.height-1, status, tcell.StyleDefault)

	if t.editMode || t.search.active || (t.saveMsg != "" && time.Now().Unix()-t.saveMsgTime < 2) {
		t.drawInputLine()
	}
}

func (t *Table) drawInputLine() {
	t.statusBuf.Reset()
	if t.editMode {
		t.statusBuf.WriteString("Editing: ")
		t.statusBuf.WriteString(t.editBuf.String())
	} else if t.search.active {
		t.statusBuf.WriteString("Search: ")
		t.statusBuf.WriteString(t.search.buf.String())
	} else if t.saveMsg != "" && time.Now().Unix()-t.saveMsgTime < 2 {
		t.statusBuf.WriteString(t.saveMsg)
	}

	line := t.statusBuf.String()
	if w := utf8.RuneCountInString(line); w > t.width {
		line = string([]rune(line)[:t.width])
	}
	drawString(t.screen, 0, t.height-2, line, tcell.StyleDefault)
}

func drawString(screen tcell.Screen, x, y int, s string, style tcell.Style) {
	for _, r := range s {
		screen.SetContent(x, y, r, nil, style)
		x++
	}
}

func drawSpaces(screen tcell.Screen, x, y, count int, style tcell.Style) {
	for i := range count {
		screen.SetContent(x+i, y, ' ', nil, style)
	}
}

func (t *Table) handleInput() bool {
	ev := t.screen.PollEvent()
	switch ev := ev.(type) {
	case *tcell.EventKey:
		if t.search.active {
			return t.handleSearch(ev)
		}
		if t.editMode && !t.fromStdin {
			return t.handleEditMode(ev)
		}
		return t.handleNavigation(ev)
	case *tcell.EventResize:
		t.screen.Sync()
		t.updateLayout()
	}
	return true
}

func (t *Table) handleSearch(ev *tcell.EventKey) bool {
	switch ev.Key() {
	case tcell.KeyEnter:
		t.performSearch()
		t.search.active = false
		t.search.buf.Reset()
	case tcell.KeyEscape:
		t.search.active = false
		t.search.buf.Reset()
		t.search.results = nil
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if t.search.buf.Len() > 0 {
			str := t.search.buf.String()
			t.search.buf.Reset()
			t.search.buf.WriteString(str[:len(str)-1])
		}
	default:
		if r := ev.Rune(); r != 0 {
			t.search.buf.WriteRune(r)
		}
	}
	return true
}

func (t *Table) performSearch() {
	pattern := t.search.buf.String()
	if pattern == "" {
		t.search.results = nil
		return
	}

	pattern = strings.ToLower(pattern)
	results := make([][2]int, 0, searchBatchSize)

	for i, row := range t.data {
		for j, cell := range row {
			if strings.Contains(strings.ToLower(cell), pattern) {
				results = append(results, [2]int{i, j})
			}
		}
	}

	t.search.pattern = pattern
	t.search.results = results
	t.search.current = 0

	if len(results) > 0 {
		t.jumpToResult(0)
	}
}

func (t *Table) jumpToResult(idx int) {
	if len(t.search.results) == 0 {
		return
	}

	idx = (idx + len(t.search.results)) % len(t.search.results)
	t.search.current = idx
	t.currentRow = t.search.results[idx][0]
	t.currentCol = t.search.results[idx][1]

	if t.currentRow < t.scrollRow {
		t.scrollRow = t.currentRow
	} else if t.currentRow >= t.scrollRow+t.height-2 {
		t.scrollRow = t.currentRow - (t.height - 3)
	}
}

func (t *Table) handleEditMode(ev *tcell.EventKey) bool {
	switch ev.Key() {
	case tcell.KeyEnter:
		t.data[t.currentRow][t.currentCol] = t.editBuf.String()
		t.editMode = false
		t.editBuf.Reset()
		t.modified = true
	case tcell.KeyEscape:
		t.editMode = false
		t.editBuf.Reset()
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if t.editBuf.Len() > 0 {
			str := t.editBuf.String()
			t.editBuf.Reset()
			t.editBuf.WriteString(str[:len(str)-1])
		}
	default:
		if r := ev.Rune(); r != 0 {
			t.editBuf.WriteRune(r)
		}
	}
	return true
}

func (t *Table) confirmQuit() bool {
	if !t.modified || t.fromStdin {
		return true
	}

	t.statusBuf.Reset()
	t.statusBuf.WriteString("Save changes? (y/n)")
	drawString(t.screen, 0, t.height-2, t.statusBuf.String(), tcell.StyleDefault)
	t.screen.Show()

	for {
		ev := t.screen.PollEvent()
		switch ev := ev.(type) {
		case *tcell.EventKey:
			switch ev.Rune() {
			case 'y', 'Y':
				t.saveFile()
				return true
			case 'n', 'N':
				return true
			case 'q':
				return false
			}
			if ev.Key() == tcell.KeyCtrlC {
				return false
			}
		}
	}
}

func (t *Table) handleNavigation(ev *tcell.EventKey) bool {
	switch ev.Key() {
	case tcell.KeyLeft:
		if t.currentCol > 0 {
			t.currentCol--
		}
	case tcell.KeyRight:
		if t.currentCol < len(t.cols)-1 {
			t.currentCol++
		}
	case tcell.KeyUp:
		if t.currentRow > 0 {
			t.currentRow--
			if t.currentRow < t.scrollRow {
				t.scrollRow--
			}
		}
	case tcell.KeyDown:
		if t.currentRow < len(t.data)-1 {
			t.currentRow++
			if t.currentRow-t.scrollRow > t.height-3 {
				t.scrollRow++
			}
		}
	case tcell.KeyPgUp:
		t.currentRow -= (t.height - 2)
		if t.currentRow < 0 {
			t.currentRow = 0
		}
		t.scrollRow = t.currentRow
	case tcell.KeyPgDn:
		t.currentRow += (t.height - 2)
		if t.currentRow >= len(t.data) {
			t.currentRow = len(t.data) - 1
		}
		t.scrollRow = t.currentRow - (t.height - 3)
		if t.scrollRow < 0 {
			t.scrollRow = 0
		}
	case tcell.KeyHome:
		t.currentRow = 0
		t.scrollRow = 0
	case tcell.KeyEnd:
		t.currentRow = len(t.data) - 1
		t.scrollRow = max(0, t.currentRow-(t.height-3))
	case tcell.KeyCtrlA:
		t.currentCol = 0
	case tcell.KeyCtrlE:
		t.currentCol = len(t.cols) - 1
	case tcell.KeyCtrlF:
		t.search.active = true
		t.search.buf.Reset()
	case tcell.KeyCtrlI:
		for i := range t.data {
			t.data[i] = append(t.data[i][:t.currentCol+1],
				append([]string{""},
					t.data[i][t.currentCol+1:]...)...)
		}
		t.updateLayout()
		t.modified = true
	case tcell.KeyCtrlN:
		newRow := make([]string, len(t.cols))
		t.data = append(t.data[:t.currentRow+1],
			append([][]string{newRow},
				t.data[t.currentRow+1:]...)...)
		t.currentRow++
		t.modified = true
	case tcell.KeyCtrlS:
		t.sortCurrentColumn()
	case tcell.KeyCtrlC, tcell.KeyEscape:
		if t.confirmQuit() {
			return false // Exit
		}
		return true
	}

	switch ev.Rune() {
	case 'q':
		if t.confirmQuit() {
			return false // Exit
		}
		return true // Continue if user cancelled
	case 'e':
		if !t.fromStdin {
			t.editMode = true
			t.editBuf.Reset()
			t.editBuf.WriteString(t.data[t.currentRow][t.currentCol])
		}
	case 's':
		if !t.fromStdin {
			t.saveFile()
		}
	case 'n':
		if len(t.search.results) > 0 {
			t.jumpToResult(t.search.current + 1)
		}
	case 'N':
		if len(t.search.results) > 0 {
			t.jumpToResult(t.search.current - 1)
		}
	}
	return true
}

func (t *Table) sortCurrentColumn() {
	if t.sort.col == t.currentCol {
		t.sort.asc = !t.sort.asc
	} else {
		t.sort.col = t.currentCol
		t.sort.asc = true
	}

	sort.Slice(t.data, func(i, j int) bool {
		a, b := t.data[i][t.currentCol], t.data[j][t.currentCol]
		if t.sort.asc {
			return a < b
		}
		return a > b
	})
}

func (t *Table) saveFile() error {
	if t.fromStdin {
		return nil
	}

	file, err := os.Create(flag.Args()[0])
	if err != nil {
		t.saveMsg = "Error: " + err.Error()
		return err
	}
	defer file.Close()

	for _, row := range t.data {
		for j, field := range row {
			if j > 0 {
				file.WriteString(string(t.separator))
			}

			// Special handling for fields starting with =
			if strings.HasPrefix(field, "=") && strings.Contains(field, "\"") {
				// Write it exactly as is - these are likely formula fields
				file.WriteString(field)
			} else if strings.ContainsRune(field, t.separator) ||
				strings.Contains(field, "\"") ||
				strings.Contains(field, "\n") {
				file.WriteString("\"")
				file.WriteString(strings.ReplaceAll(field, "\"", "\"\""))
				file.WriteString("\"")
			} else {
				file.WriteString(field)
			}
		}
		file.WriteString("\n")
	}

	t.saveMsg = "File saved successfully"
	t.saveMsgTime = time.Now().Unix()
	t.modified = false
	return nil
}

func isDataFromStdin() bool {
	fi, _ := os.Stdin.Stat()
	return (fi.Mode() & os.ModeCharDevice) == 0
}

func printUsage() {
	const usage = `CSV viewer and editor

Usage: %s [options] filename
   or: %s [options] < input.csv

Options:
  -help           Show this help message
  -separator      Field separator character (default ";")

Navigation:
Arrow keys   Move cursor
PgUp/PgDn    Page up/down
Home/End     First/last row
Ctrl+A/E     Start/end of row
Ctrl+F       Search
n/N          Next/previous match
Ctrl+I       Insert new column at cursor position
Ctrl+N       Add new row after current position
Ctrl+S       Sort by column
q            Quit

Examples:
  %s data.csv
  %s -separator "," data.txt
  %s -separator $'\t' data.tsv
  %s < data.csv
`
	fmt.Printf(usage+"\n", os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func main() {
	help := flag.Bool("help", false, "Show help message")
	separatorFlag := flag.String("separator", ";", "Field separator character (default \";\")")
	flag.Usage = printUsage
	flag.Parse()

	// Show help if requested or no arguments
	if *help || (flag.NArg() == 0 && !isDataFromStdin()) {
		printUsage()
		os.Exit(0)
	}

	separator, _ := utf8.DecodeRuneInString(*separatorFlag)
	if separator == utf8.RuneError {
		fmt.Fprintf(os.Stderr, "Error: Invalid separator character\n")
		os.Exit(1)
	}

	screen, err := tcell.NewScreen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize screen: %v\n", err)
		os.Exit(1)
	}
	if err := screen.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize screen: %v\n", err)
		os.Exit(1)
	}
	defer screen.Fini()

	screen.SetStyle(tcell.StyleDefault)
	screen.Clear()

	table, err := NewTable(separator, screen)
	if err != nil {
		screen.Fini()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	for {
		table.draw()
		if !table.handleInput() {
			break
		}
	}
}
