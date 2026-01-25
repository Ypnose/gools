package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

var (
	contentFile     string
	prefix          string
	encryptPassword string
	mu              sync.Mutex
	sessions        = make(map[string]*Session)
	sessionMu       sync.Mutex
	limiter         = &rateLimiter{attempts: make(map[string][]time.Time)}
)

type Session struct {
	encryptedSecrets []byte
	sessionKey       []byte
	cacheMu          sync.RWMutex
	expiresAt        time.Time
}

type rateLimiter struct {
	attempts map[string][]time.Time
	mu       sync.Mutex
}

const sessionTimeout = 2 * time.Minute

type TOTPEntry struct {
	Label string `json:"label"`
}

type TOTPCode struct {
	Code      string `json:"code"`
	Remaining int    `json:"remaining"`
}

var pageTemplate *template.Template

func isEncrypted(data []byte) bool {
	// Check for magic header "VAULT1"
	return len(data) >= 6 && string(data[:6]) == "VAULT1"
}

func normalizeFilename(filename string) string {
	return filepath.Clean(strings.TrimSpace(filename))
}

func timeoutMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		next(w, r.WithContext(ctx))
	}
}

func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		next(w, r)
	}
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 4, 64*1024, 2, 32)
}

// deriveSessionKey derives a session key from master key using RFC 5869 HKDF
func deriveSessionKey(masterKey []byte, info string) []byte {
	hkdfReader := hkdf.New(sha256.New, masterKey, nil, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		panic(err) // Should never happen with HKDF
	}
	return key
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("invalid data")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func decryptWithPassword(data []byte, password string) ([]byte, []byte, error) {
	// Check magic header and minimum size: "VAULT1" (6) + salt (32) + nonce (12) + tag (16)
	if len(data) < 66 {
		return nil, nil, fmt.Errorf("invalid data")
	}

	// Verify magic header
	if string(data[:6]) != "VAULT1" {
		return nil, nil, fmt.Errorf("invalid vault format")
	}

	// Extract salt and encrypted data
	salt := data[6:38]
	encryptedData := data[38:]

	key := deriveKey(password, salt)
	defer zeroBytes(key)

	decrypted, err := decrypt(encryptedData, key)
	if err != nil {
		if decrypted != nil {
			zeroBytes(decrypted)
		}
		return nil, nil, err
	}

	return decrypted, salt, nil
}

func encryptFile(inputFile, password string) error {
	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generating salt: %w", err)
	}

	key := deriveKey(password, salt)
	defer zeroBytes(key)

	encrypted, err := encrypt(plaintext, key)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	// Format: "VAULT1" (6 bytes) + salt (32 bytes) + encrypted data
	result := make([]byte, 0, 6+32+len(encrypted))
	result = append(result, []byte("VAULT1")...)
	result = append(result, salt...)
	result = append(result, encrypted...)

	if err := os.WriteFile(inputFile, result, 0400); err != nil {
		return fmt.Errorf("writing encrypted file: %w", err)
	}

	// Explicitly set permissions (WriteFile doesn't always respect mode on existing files)
	if err := os.Chmod(inputFile, 0400); err != nil {
		return fmt.Errorf("setting permissions: %w", err)
	}

	return nil
}

func createSession(encryptedContent []byte, sessionKey []byte) (string, error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if len(sessions) >= 100 {
		return "", fmt.Errorf("too many sessions")
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	token := fmt.Sprintf("%x", tokenBytes)

	encCopy := make([]byte, len(encryptedContent))
	copy(encCopy, encryptedContent)

	keyCopy := make([]byte, len(sessionKey))
	copy(keyCopy, sessionKey)

	sessions[token] = &Session{
		encryptedSecrets: encCopy,
		sessionKey:       keyCopy,
		expiresAt:        time.Now().Add(sessionTimeout),
	}

	return token, nil
}

func (s *Session) clearSession() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	zeroBytes(s.encryptedSecrets)
	zeroBytes(s.sessionKey)
}

func (s *Session) getSecret(label string) ([]byte, error) {
	s.cacheMu.RLock()
	encryptedCopy := make([]byte, len(s.encryptedSecrets))
	copy(encryptedCopy, s.encryptedSecrets)

	keyCopy := make([]byte, len(s.sessionKey))
	copy(keyCopy, s.sessionKey)
	s.cacheMu.RUnlock()

	decrypted, err := decrypt(encryptedCopy, keyCopy)
	zeroBytes(keyCopy)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(decrypted)

	secret := extractSecretBytes(decrypted, label)
	if secret == nil {
		return nil, fmt.Errorf("label not found")
	}

	return secret, nil
}

func extractSecretBytes(content []byte, label string) []byte {
	labelBytes := []byte(label)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		if len(line) == 0 || (len(line) > 0 && line[0] == '#') {
			continue
		}

		start := bytes.IndexByte(line, '[')
		end := bytes.IndexByte(line, ']')
		if start == -1 || end == -1 || end <= start+1 {
			continue
		}

		lineLabel := bytes.TrimSpace(line[start+1 : end])
		if !bytes.Equal(lineLabel, labelBytes) {
			continue
		}

		rest := bytes.TrimSpace(line[end+1:])
		if len(rest) == 0 {
			continue
		}

		if isValidBase32(rest) {
			secret := make([]byte, len(rest))
			copy(secret, rest)
			return secret
		}
	}

	if err := scanner.Err(); err != nil {
		return nil
	}

	return nil
}

func isValidBase32(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7') || c == ' ') {
			return false
		}
	}
	return true
}

func cleanupSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sessionMu.Lock()
		now := time.Now()
		for token, session := range sessions {
			if now.After(session.expiresAt) {
				session.clearSession()
				delete(sessions, token)
			}
		}
		sessionMu.Unlock()
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Hour)

	attempts := rl.attempts[ip]
	validAttempts := make([]time.Time, 0, len(attempts))
	for _, t := range attempts {
		if t.After(cutoff) {
			validAttempts = append(validAttempts, t)
		}
	}

	if len(validAttempts) >= 5 {
		rl.attempts[ip] = validAttempts
		return false
	}

	rl.attempts[ip] = append(validAttempts, now)
	return true
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-time.Hour)

		for ip, attempts := range rl.attempts {
			validAttempts := make([]time.Time, 0)
			for _, t := range attempts {
				if t.After(cutoff) {
					validAttempts = append(validAttempts, t)
				}
			}

			if len(validAttempts) == 0 {
				delete(rl.attempts, ip)
			} else {
				rl.attempts[ip] = validAttempts
			}
		}
		rl.mu.Unlock()
	}
}

func getRemoteIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func generateTOTP(secret []byte) (string, error) {
	cleaned := make([]byte, 0, len(secret))
	for _, b := range secret {
		if b == ' ' {
			continue
		}
		if b >= 'a' && b <= 'z' {
			cleaned = append(cleaned, b-32)
		} else {
			cleaned = append(cleaned, b)
		}
	}

	// Add padding if needed (Base32 requires length to be multiple of 8)
	cleanedStr := string(cleaned)
	if remainder := len(cleanedStr) % 8; remainder != 0 {
		cleanedStr += strings.Repeat("=", 8-remainder)
	}

	key, err := base32.StdEncoding.DecodeString(cleanedStr)
	if err != nil {
		return "", err
	}
	defer zeroBytes(key)

	counter := time.Now().Unix() / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	h := hmac.New(sha1.New, key)
	h.Write(buf)
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	code := binary.BigEndian.Uint32(hash[offset:]) & 0x7fffffff
	code = code % 1000000

	return fmt.Sprintf("%03d %03d", code/1000, code%1000), nil
}

func parseEntriesBytes(content []byte) []TOTPEntry {
	var entries []TOTPEntry
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		if len(line) == 0 || (len(line) > 0 && line[0] == '#') {
			continue
		}

		start := bytes.IndexByte(line, '[')
		end := bytes.IndexByte(line, ']')
		if start == -1 || end == -1 || end <= start+1 {
			continue
		}

		label := string(bytes.TrimSpace(line[start+1 : end]))
		entries = append(entries, TOTPEntry{Label: label})
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Warning: scanner error while parsing entries: %v", err)
		return entries // Return what we got so far
	}

	return entries
}

func initTemplate() error {
	tmpl := `<!DOCTYPE html>
<html>
<head>
	<title>Vault</title>
	<meta name="viewport" content="width=device-width, initial-scale=1, interactive-widget=resizes-content">
	<style>
		:root {
			--background:#fff;
			--text:#24292e;
			--border:#ced4da;
			--entry-bg:#f6f8fa;
			--button-bg:#0366d6;
			--button-hover:#0256c4;
			--code-bg:#e1f5fe;
			--code-text:#01579b;
			font-size:16px;
		}
		@media (prefers-color-scheme:dark) {
			:root {
				--background:#21292c;
				--text:#c9d1d9;
				--border:#48515c;
				--entry-bg:#161b22;
				--button-bg:#238636;
				--button-hover:#2ea043;
				--code-bg:#1c2e1c;
				--code-text:#7ee787;
			}
			input[type="password"] {
				background-color:var(--background);
				color:#c9d1d9;
			}
		}
		* { box-sizing:border-box; }
		body {
			font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			background:var(--background);
			color:var(--text);
			margin:0;
			padding:0;
			height:100dvh;
			overflow:hidden;
		}
		#login-container {
			display:flex;
			justify-content:center;
			align-items:center;
			flex-direction:column;
			height:100%;
		}
		input[type="password"] {
			font-size:1rem;
			padding:0.5rem;
			margin:0.625rem;
			border:1px solid #ced4da;
		}
		button {
			font-size:1rem;
			padding:0.5rem 1.5rem;
			background:var(--button-bg);
			color:#fff;
			border:none;
			border-radius:6px;
			cursor:pointer;
		}
		button:hover { background:var(--button-hover); }
		#vault-container {
			display:none;
			height:100%;
			flex-direction:column;
		}
		#entries {
			flex:1;
			overflow-y:auto;
			padding:1rem;
		}
		.entry {
			background:var(--entry-bg);
			border:1px solid var(--border);
			padding:1rem;
			margin-bottom:0.75rem;
			display:flex;
			justify-content:space-between;
			align-items:center;
			gap:1rem;
			flex-wrap:wrap;
		}
		.entry-label {
			font-weight:700;
			font-size:1rem;
			word-break:break-word;
			flex:1;
			min-width:0;
		}
		.entry-actions {
			display:flex;
			gap:0.5rem;
			align-items:center;
			flex-wrap:wrap;
		}
		.show-code-btn {
			padding:0.4rem 1rem;
			font-size:0.875rem;
			white-space:nowrap;
		}
		.code-display {
			display:none;
			align-items:center;
			gap:0.75rem;
			flex-wrap:wrap;
		}
		.code-value {
			font-family:ui-monospace, SFMono-Regular, monospace;
			font-size:1.25rem;
			font-weight:600;
			background:var(--code-bg);
			color:var(--code-text);
			padding:0.2rem 0.8rem;
			border-radius:6px;
			letter-spacing:0.1em;
		}
		.progress-ring {
			width:28px;
			height:28px;
			transform:rotate(-90deg);
		}
		.progress-ring-circle {
			stroke:var(--button-bg);
			stroke-width:3;
			fill:none;
			stroke-linecap:round;
		}
		.copy-btn {
			padding:0.4rem 0.8rem;
			font-size:0.875rem;
			white-space:nowrap;
		}
		@media (max-width:480px) {
			#entries { padding:0.5rem; }
			.entry {
				flex-direction:column;
				align-items:flex-start;
				padding:0.75rem;
				margin-bottom:0.5rem;
			}
			.entry-actions {
				width:100%;
				justify-content:flex-start;
			}
		}
	</style>
</head>
<body>
	<div id="login-container">
		<input type="password" id="password" placeholder="Password" onkeydown="if(event.key==='Enter')login()">
		<button onclick="login()">Unlock</button>
	</div>
	<div id="vault-container">
		<div id="entries"></div>
	</div>
	<script>
		const prefix = {{.Prefix}};
		let entries = [], activeTimers = {}, autoHideTimers = {}, currentlyShownIndex = null, inactivityTimer;
		const INACTIVITY_TIMEOUT = 120000;
		function resetInactivity() { clearTimeout(inactivityTimer); inactivityTimer = setTimeout(() => { document.cookie = 'session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=' + (prefix ? prefix + '/' : '/') + ';'; alert('Session expired'); location.reload(); }, INACTIVITY_TIMEOUT); }
		async function login() { const p = document.getElementById('password'), pw = p.value; p.value = ''; const r = await fetch(prefix + '/decrypt/', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'password=' + encodeURIComponent(pw) }); if (r.ok) { entries = await r.json(); document.getElementById('login-container').style.display = 'none'; document.getElementById('vault-container').style.display = 'flex'; renderEntries(); resetInactivity(); ['mousemove','keypress','click'].forEach(e => document.addEventListener(e, resetInactivity)); } else { alert('Invalid password'); p.focus(); } }
		function renderEntries() { const c = document.getElementById('entries'); c.innerHTML = ''; entries.forEach((e, i) => { const d = document.createElement('div'); d.className = 'entry'; d.innerHTML = '<div class="entry-label">' + escapeHtml(e.label) + '</div><div class="entry-actions"><button class="show-code-btn" onclick="toggleCode(' + i + ')">Show code</button><div class="code-display" id="code-' + i + '"><div class="code-value" id="code-value-' + i + '">------</div><svg class="progress-ring"><circle class="progress-ring-circle" cx="14" cy="14" r="11" stroke-dasharray="69.115" stroke-dashoffset="0" id="progress-' + i + '"/></svg><button class="copy-btn" onclick="copyCode(' + i + ')">Copy</button></div></div>'; c.appendChild(d); }); }
		function escapeHtml(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
		async function toggleCode(i) { if (currentlyShownIndex !== null && currentlyShownIndex !== i) hideCode(currentlyShownIndex); const c = document.getElementById('code-' + i), b = document.querySelector('#entries > div:nth-child(' + (i + 1) + ') .show-code-btn'); if (c.style.display === 'flex') { hideCode(i); } else { showCode(i); b.textContent = 'Hide code'; currentlyShownIndex = i; } }
		async function showCode(i) { document.getElementById('code-' + i).style.display = 'flex'; await updateCode(i); activeTimers[i] = setInterval(() => updateCode(i), 1000); autoHideTimers[i] = setTimeout(() => hideCode(i), 30000); }
		function hideCode(i) { document.getElementById('code-' + i).style.display = 'none'; document.querySelector('#entries > div:nth-child(' + (i + 1) + ') .show-code-btn').textContent = 'Show code'; if (activeTimers[i]) { clearInterval(activeTimers[i]); delete activeTimers[i]; } if (autoHideTimers[i]) { clearTimeout(autoHideTimers[i]); delete autoHideTimers[i]; } if (currentlyShownIndex === i) currentlyShownIndex = null; }
		async function updateCode(i) { const r = await fetch(prefix + '/generate/', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'label=' + encodeURIComponent(entries[i].label) }); if (r.ok) { const d = await r.json(); document.getElementById('code-value-' + i).textContent = d.code; const p = document.getElementById('progress-' + i); p.style.strokeDashoffset = 69.115 * (1 - d.remaining / 30); } }
		async function copyCode(i) { await navigator.clipboard.writeText(document.getElementById('code-value-' + i).textContent); const b = document.querySelector('#entries > div:nth-child(' + (i + 1) + ') .copy-btn'), t = b.textContent; b.textContent = 'Copied!'; setTimeout(() => b.textContent = t, 2000); }
		window.onload = () => document.getElementById('password').focus();
	</script>
</body>
</html>`

	var err error
	pageTemplate, err = template.New("page").Parse(tmpl)
	return err
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: vault [-addr string] [-encrypt-password string] [-file string] [-port number] [-prefix string]\n")
		flag.PrintDefaults()
	}

	addr := flag.String("addr", "127.0.0.1", "listening address")
	port := flag.Int("port", 4096, "listening port")
	flag.StringVar(&contentFile, "file", "vault.enc", "encrypted file")
	flag.StringVar(&prefix, "prefix", "", "URL prefix")
	flag.StringVar(&encryptPassword, "encrypt-password", "", "password to encrypt plaintext file (CLI mode)")
	flag.Parse()

	contentFile = normalizeFilename(contentFile)

	// CLI encryption mode
	if encryptPassword != "" {
		fileData, err := os.ReadFile(contentFile)
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}

		if isEncrypted(fileData) {
			log.Fatalf("Error: file is already encrypted")
		}

		if err := encryptFile(contentFile, encryptPassword); err != nil {
			log.Fatalf("%v", err)
		}

		fmt.Printf("Successfully encrypted %s\n", contentFile)
		fmt.Println("File permissions set to 0400 (read-only)")
		return
	}

	fileData, err := os.ReadFile(contentFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: file %s not found\n", contentFile)
			fmt.Fprintf(os.Stderr, "Create a plaintext file with format:\n")
			fmt.Fprintf(os.Stderr, "  [Label] SECRET\n")
			fmt.Fprintf(os.Stderr, "Encrypt it with: vault -encrypt-password 'password' -file %s\n", contentFile)
			os.Exit(1)
		}
		log.Fatalf("Error reading file: %v", err)
	}

	if !isEncrypted(fileData) {
		fmt.Fprintf(os.Stderr, "Error: file %s is not encrypted\n", contentFile)
		fmt.Fprintf(os.Stderr, "Encrypt it with: vault -encrypt-password 'password' -file %s\n", contentFile)
		os.Exit(1)
	}

	// Verify basic structure: "VAULT1" (6) + salt (32) + nonce (12) + ciphertext + tag (16)
	// Minimum valid encrypted vault is empty plaintext: 6 + 32 + 12 + 0 + 16 = 66 bytes
	if len(fileData) < 66 {
		fmt.Fprintf(os.Stderr, "Error: file %s is corrupted or invalid (too small)\n", contentFile)
		os.Exit(1)
	}

	// Check if file size is consistent with GCM structure
	// After magic+salt (38 bytes), remaining should be: nonce (12) + ciphertext + tag (16)
	remainingAfterHeader := len(fileData) - 38
	if remainingAfterHeader < 28 { // minimum: 12 (nonce) + 16 (tag)
		fmt.Fprintf(os.Stderr, "Error: file %s is corrupted or invalid\n", contentFile)
		os.Exit(1)
	}

	// Enforce permissions
	info, err := os.Stat(contentFile)
	if err == nil {
		perm := info.Mode().Perm()
		if perm != 0400 && perm != 0440 && perm != 0444 {
			if err := os.Chmod(contentFile, 0400); err != nil {
				log.Printf("Warning: Could not set permissions to 0400: %v", err)
			}
		}
	}

	if err := initTemplate(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	prefix = strings.TrimSuffix(prefix, "/")
	mux.HandleFunc(prefix+"/", securityHeaders(timeoutMiddleware(handleHome)))
	mux.HandleFunc(prefix+"/decrypt/", securityHeaders(timeoutMiddleware(handleDecrypt)))
	mux.HandleFunc(prefix+"/generate/", securityHeaders(timeoutMiddleware(handleGenerate)))

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", *addr, *port),
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go cleanupSessions()
	go limiter.cleanup()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Printf("Shutting down...")
		sessionMu.Lock()
		for token, sess := range sessions {
			sess.clearSession()
			delete(sessions, token)
		}
		sessionMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	log.Printf("Starting TOTP vault on %s", srv.Addr)

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != prefix+"/" {
		http.Redirect(w, r, prefix+"/", http.StatusFound)
		return
	}
	data := struct{ Prefix template.JS }{Prefix: template.JS(fmt.Sprintf("%q", prefix))}
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		originHost := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
		originHost = strings.Split(originHost, ":")[0]
		requestHost := strings.Split(r.Host, ":")[0]
		if originHost != requestHost {
			http.Error(w, "Invalid origin", http.StatusForbidden)
			return
		}
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	password := r.Form.Get("password")
	if password == "" {
		http.Error(w, "Password required", http.StatusBadRequest)
		return
	}

	remoteIP := getRemoteIP(r)
	if !limiter.allow(remoteIP) {
		log.Printf("Rate limit exceeded from %s", remoteIP)
		http.Error(w, "Too many attempts", http.StatusTooManyRequests)
		return
	}

	mu.Lock()
	encrypted, err := os.ReadFile(contentFile)
	mu.Unlock()

	if err != nil {
		log.Printf("Failed to read file from %s: %v", remoteIP, err)
		http.Error(w, "Read failed", http.StatusInternalServerError)
		return
	}

	cookiePath := "/"
	if prefix != "" {
		cookiePath = prefix + "/"
	}

	decrypted, salt, err := decryptWithPassword(encrypted, password)
	if err != nil {
		// Could be wrong password OR corrupted file - both fail GCM authentication
		log.Printf("Failed login attempt from %s (wrong password or corrupted file)", remoteIP)
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	entries := parseEntriesBytes(decrypted)

	// Derive separate session key from master key (key separation principle)
	// Don't reuse the master key that decrypts the vault
	masterKey := deriveKey(password, salt)
	sessionKey := deriveSessionKey(masterKey, "totp-session-key-v1")
	zeroBytes(masterKey)

	encryptedForSession, err := encrypt(decrypted, sessionKey)
	zeroBytes(decrypted)

	if err != nil {
		zeroBytes(sessionKey)
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	sessionToken, err := createSession(encryptedForSession, sessionKey)
	zeroBytes(sessionKey) // Safe: createSession copies the key internally

	if err != nil {
		http.Error(w, "Session failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     cookiePath,
		MaxAge:   int(sessionTimeout.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	log.Printf("Successful login from %s (%d entries)", remoteIP, len(entries))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if origin := r.Header.Get("Origin"); origin != "" {
		originHost := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
		originHost = strings.Split(originHost, ":")[0]
		requestHost := strings.Split(r.Host, ":")[0]
		if originHost != requestHost {
			http.Error(w, "Invalid origin", http.StatusForbidden)
			return
		}
	}

	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	label := r.Form.Get("label")
	if label == "" {
		http.Error(w, "Label required", http.StatusBadRequest)
		return
	}

	sessionMu.Lock()
	sess, exists := sessions[sessionCookie.Value]
	if !exists || time.Now().After(sess.expiresAt) {
		if exists {
			sess.clearSession()
			delete(sessions, sessionCookie.Value)
		}
		sessionMu.Unlock()
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}
	sess.expiresAt = time.Now().Add(sessionTimeout)

	// Keep lock while calling getSecret to prevent cleanup race
	secret, err := sess.getSecret(label)
	sessionMu.Unlock()

	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	defer zeroBytes(secret)

	code, err := generateTOTP(secret)
	if err != nil {
		http.Error(w, "TOTP failed", http.StatusInternalServerError)
		return
	}

	remaining := 30 - int(time.Now().Unix()%30)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TOTPCode{Code: code, Remaining: remaining})
}
