package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	minInterval    = 30 * time.Second
	checkTimeout   = 10 * time.Second
	commandTimeout = 30 * time.Second
	// Maximum bytes consumed from the HTTP response body. We only care
	// about the status code; this cap prevents a misbehaving service
	// from making us buffer an arbitrarily large response.
	maxBodyBytes = 4096
)

// Restart-storm protection: exponential backoff capped at maxBackoff.
const (
	baseBackoff = 30 * time.Second
	maxBackoff  = 5 * time.Minute
)

var allowedProtos = map[string]bool{
	"http":  true,
	"https": true,
}

type config struct {
	port     int
	proto    string
	host     string // empty for http; required FQDN for https
	interval time.Duration
	cmd      string
	cmdArgs  []string
}

// argList is a flag.Value that accumulates repeated -arg flags.
type argList []string

func (a *argList) String() string { return strings.Join(*a, " ") }
func (a *argList) Set(v string) error {
	*a = append(*a, v)
	return nil
}

// resetTimer stops t, drains any buffered tick, then resets it to d.
//
// This sequence is safe to call from a single goroutine at any time —
// not only after receiving from t.C. In the current main loop we always
// reset immediately after a receive, so draining is a no-op in practice;
// the helper exists to make the invariant explicit and to guard against
// a future caller that resets the timer before it has fired.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)

	cfg := parseAndValidateFlags()

	// ctx is cancelled on SIGTERM or SIGINT, giving the daemon a clean
	// exit path when systemd stops the unit or the user presses Ctrl-C.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	host := cfg.host
	if host == "" {
		host = "127.0.0.1"
	}
	targetURL := fmt.Sprintf("%s://%s:%d/", cfg.proto, host, cfg.port)

	log.Printf("Starting httpwd")
	log.Printf("  Target   : %s", targetURL)
	log.Printf("  Interval : %s", cfg.interval)
	log.Printf("  Command  : %s %s", cfg.cmd, strings.Join(cfg.cmdArgs, " "))

	client := buildHTTPClient(cfg.proto)

	// A single time.Timer drives all scheduling — both the normal check
	// interval and the failure backoff. This avoids the dual-scheduler
	// problem that arises when time.Ticker runs concurrently with
	// time.Sleep: accumulated ticks pile up inside the ticker channel
	// during a long backoff sleep and fire immediately upon return,
	// even after draining one tick with a select.
	// With a Timer we always set the exact next wake-up ourselves and
	// there is never a stale event in the channel.
	timer := time.NewTimer(0) // fire immediately for the first check
	defer timer.Stop()

	backoff := baseBackoff

	for {
		select {
		case <-ctx.Done():
			log.Printf("Shutting down: %v", ctx.Err())
			return

		case <-timer.C:
			if err := checkService(client, targetURL); err != nil {
				log.Printf("CHECK FAILED : %v", err)
				log.Printf("ACTION       : %s %s", cfg.cmd, strings.Join(cfg.cmdArgs, " "))
				if runErr := runCommand(cfg.cmd, cfg.cmdArgs); runErr != nil {
					log.Printf("COMMAND ERROR: %v", runErr)
				} else {
					log.Printf("COMMAND OK   : completed successfully")
				}
				// Schedule the next check after the backoff interval.
				log.Printf("BACKOFF      : next check in %s", backoff)
				resetTimer(timer, backoff)
				// Advance the backoff for the next consecutive failure.
				if backoff < maxBackoff {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
			} else {
				// Successful check: reset backoff and schedule the
				// normal interval.
				backoff = baseBackoff
				resetTimer(timer, cfg.interval)
			}
		}
	}
}

// parseAndValidateFlags parses CLI flags and enforces all constraints.
func parseAndValidateFlags() config {
	port := flag.Int("port", 0, "TCP port to monitor on localhost (required, 1–65535)")
	proto := flag.String("proto", "http", "Protocol: http or https")
	host := flag.String("host", "", "FQDN resolving to 127.0.0.1 (required with -proto https)")
	interval := flag.Duration("interval", 0, "Check interval (minimum and default 30s)")
	cmd := flag.String("cmd", "", "Absolute path of the executable to run on failure (required)")
	var args argList
	flag.Var(&args, "arg", "Argument passed to -cmd; repeat for multiple arguments:\n"+
		"\t\t-cmd /usr/bin/systemctl -arg restart -arg service")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: httpwd [flags]\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  httpwd -port 8080 -proto http -interval 30s \
         -cmd /usr/bin/systemctl -arg restart -arg service

  httpwd -port 443 -proto https -interval 5m -host foo.tld.fr \
         -cmd /usr/bin/systemctl -arg restart -arg service
`)
	}

	flag.Parse()

	if flag.NFlag() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	if *port < 1 || *port > 65535 {
		fatal("-port must be between 1 and 65535 (got %d)", *port)
	}

	protoLower := strings.ToLower(*proto)
	if !allowedProtos[protoLower] {
		fatal("-proto must be 'http' or 'https' (got %q)", *proto)
	}

	hostVal := strings.TrimSpace(*host)
	if protoLower == "https" && hostVal == "" {
		fatal("-host is required with -proto https")
	}
	if protoLower == "http" && hostVal != "" {
		fatal("-host is only valid with -proto https")
	}

	if *interval == 0 {
		*interval = minInterval
	}
	if *interval < minInterval {
		fatal("-interval must be at least %s (got %s)", minInterval, *interval)
	}

	if strings.TrimSpace(*cmd) == "" {
		fatal("-cmd is required")
	}
	exe, err := resolveExecutable(*cmd)
	if err != nil {
		fatal("-cmd %q: %v", *cmd, err)
	}

	return config{
		port:     *port,
		proto:    protoLower,
		host:     hostVal,
		interval: *interval,
		cmd:      exe,
		cmdArgs:  []string(args),
	}
}

// resolveExecutable validates the executable path.
//
// The path must be absolute. Symlinks are resolved to obtain the
// canonical executable location, after which os.OpenRoot is used to
// verify that the target exists, is a regular file, and has executable
// permission bits set.
// Validation is performed only at startup. The executable is later
// reopened by name when exec.Command runs.
func resolveExecutable(name string) (string, error) {
	if !filepath.IsAbs(name) {
		return "", fmt.Errorf("must be an absolute path (got %q)", name)
	}

	// filepath.Clean collapses ".." and redundant slashes.
	absPath := filepath.Clean(name)

	// Resolve the executable path to its canonical target before
	// validation. This accommodates common layouts such as
	// /bin -> /usr/bin and executable symlinks managed by alternatives
	// systems.. Without this, systems where /bin -> /usr/bin cause
	// os.Root.Stat to fail with "path escapes from parent" because the
	// kernel sees the symlink mid-path during the openat(2) traversal.
	absPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", fmt.Errorf("cannot resolve symlinks in %q: %w", name, err)
	}

	dir := filepath.Dir(absPath)
	base := filepath.Base(absPath)

	// Open the parent directory as an os.Root. All subsequent
	// operations through this Root are relative to the directory file
	// descriptor and cannot escape it via symlinks or path components.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", fmt.Errorf("cannot open directory %q: %w", dir, err)
	}
	defer root.Close()

	// Stat the executable through the directory fd — equivalent to
	// fstatat(2).
	info, err := root.Stat(base)
	if err != nil {
		return "", fmt.Errorf("cannot stat %q: %w", absPath, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%q is not a regular file", absPath)
	}
	if info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("%q has no executable bits set", absPath)
	}

	return absPath, nil
}

// Security properties:
//   - DialContext resolves the target hostname and refuses to connect
//     if any returned address is not 127.0.0.1, ensuring the connection
//     stays local regardless of future DNS or /etc/hosts changes.
//   - HTTPS: InsecureSkipVerify is false; the certificate is validated
//     against the FQDN supplied via -host. Minimum TLS version: 1.2.
//   - Keep-alives disabled: each check opens a fresh connection.
//   - Redirects are not followed.
func buildHTTPClient(proto string) *http.Client {
	baseDialer := &net.Dialer{Timeout: checkTimeout}

	restrictedDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}
		// Resolve the hostname (covers both the literal "127.0.0.1"
		// used for HTTP and the FQDN used for HTTPS). Every resolved
		// address must be loopback. If the hostname resolves to any
		// non-loopback address, the connection is refused.
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve %q: %w", host, err)
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("host %q resolved to no addresses", host)
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("host %q resolves to %q, which is not a loopback address", host, a)
			}
		}
		return baseDialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}

	transport := &http.Transport{
		DialContext:           restrictedDial,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   checkTimeout,
		ResponseHeaderTimeout: checkTimeout,
	}

	if proto == "https" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   checkTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// checkService performs an HTTP(S) GET and returns an error when the
// service is considered down: connection failure, TLS error, or
// HTTP 5xx response. 1xx–4xx are treated as "service is alive" (it
// responded meaningfully).
func checkService(client *http.Client, targetURL string) error {
	resp, err := client.Get(targetURL)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", targetURL, err)
	}
	defer resp.Body.Close()
	// Drain a bounded portion of the body so the server can close
	// cleanly.
	_, _ = io.CopyN(io.Discard, resp.Body, maxBodyBytes)

	if resp.StatusCode >= 500 {
		return fmt.Errorf("service at %s returned HTTP %d", targetURL, resp.StatusCode)
	}
	return nil
}

// A context timeout of commandTimeout kills the child process group if
// the command hangs (e.g. a broken systemd unit that never resolves),
// preventing httpwd from blocking indefinitely.
//
// Why kill the process group, not just the child?
// exec.CommandContext sends SIGKILL to the child PID when the context
// expires, but Setpgid places the child in its own process group. Any
// grandchildren (e.g. a wrapper script that forks systemctl) inherit
// that group and are not killed by the default signal. We therefore
// send SIGKILL to -pgid ourselves after cmd.Run returns with a deadline
// error.
//
// Security properties:
//   - exec.CommandContext is called directly — no shell, no
//     metacharacter expansion.
//   - The child environment contains only HOME and LANG; no PATH, no
//     secrets.
//   - stdin is bound to /dev/null.
//   - stdout/stderr are forwarded to our own file descriptors
//     (journald).
//   - Setpgid places the child in its own process group so it cannot
//     deliver signals to the httpwd parent.
func runCommand(exe string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, args...)

	cmd.Env = []string{
		// HOME is set to /tmp rather than omitted or set to "/" because:
		//   - omitting it breaks programs that call os.UserHomeDir() or
		//     expand "~"
		//   - "/" as a home directory is semantically wrong
		//   - /tmp is a harmless throwaway location for any config or
		//     cache the child might try to write, and when the systemd
		//     unit sets PrivateTmp=yes, /tmp is a private namespace
		//     mount so nothing bleeds into the real filesystem.
		// For system tools like systemctl, HOME is irrelevant; this is
		// purely defensive for future -cmd executables that inspect the
		// environment.
		"HOME=/tmp",
		"LANG=C.UTF-8",
	}

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("cannot open /dev/null: %w", err)
	}
	defer devNull.Close()
	cmd.Stdin = devNull
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			// Kill every process in the child's process group. The pgid
			// equals the child PID when Setpgid is true; a negative
			// signal target addresses the group. This catches
			// grandchildren that survived the per-PID SIGKILL sent by
			// exec.CommandContext.
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			return fmt.Errorf("command timed out after %s (process group killed): %w", commandTimeout, err)
		}
		return err
	}
	return nil
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "httpwd: "+format+"\n", a...)
	os.Exit(2)
}
