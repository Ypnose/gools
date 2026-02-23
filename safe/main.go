package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	devMode         bool
	loginSemaphore  = make(chan struct{}, 3)
	sessions        = make(map[string]*Session)
	sessionMu       sync.Mutex
	limiter         = &rateLimiter{attempts: make(map[string][]time.Time), max: 5, window: time.Hour}
	retrieveLimiter = &rateLimiter{attempts: make(map[string][]time.Time), max: 10, window: time.Minute}
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
	max      int
	window   time.Duration
}

const sessionTimeout = 2 * time.Minute

type PasswordEntry struct {
	Label string `json:"label"`
}

var pageTemplate *template.Template

func isEncrypted(data []byte) bool {
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
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		next(w, r)
	}
}

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 4, 64*1024, 2, 32)
}

func deriveSessionKey(masterKey []byte, info string) []byte {
	hkdfReader := hkdf.New(sha256.New, masterKey, nil, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		panic(err)
	}
	return key
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func encrypt(data []byte, key []byte, aad []byte) ([]byte, error) {
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

	ciphertext := gcm.Seal(nil, nonce, data, aad)
	return append(nonce, ciphertext...), nil
}

func decrypt(data []byte, key []byte, aad []byte) ([]byte, error) {
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
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func decryptWithPassword(data []byte, password string) ([]byte, []byte, error) {
	if len(data) < 66 {
		return nil, nil, fmt.Errorf("invalid data")
	}

	if string(data[:6]) != "VAULT1" {
		return nil, nil, fmt.Errorf("invalid safe format")
	}

	salt := make([]byte, 32)
	copy(salt, data[6:38])
	encryptedData := data[38:]

	aad := make([]byte, 38)
	copy(aad, data[:38])

	key := deriveKey(password, salt)
	defer zeroBytes(key)

	decrypted, err := decrypt(encryptedData, key, aad)
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

	header := make([]byte, 0, 6+32)
	header = append(header, []byte("VAULT1")...)
	header = append(header, salt...)

	encrypted, err := encrypt(plaintext, key, header)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	result := make([]byte, 0, len(header)+len(encrypted))
	result = append(result, header...)
	result = append(result, encrypted...)

	if err := os.WriteFile(inputFile, result, 0400); err != nil {
		return fmt.Errorf("writing encrypted file: %w", err)
	}

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

	defer zeroBytes(encryptedCopy)
	decrypted, err := decrypt(encryptedCopy, keyCopy, nil)
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

		if len(line) == 0 || line[0] == '#' {
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

		secret := make([]byte, len(rest))
		copy(secret, rest)
		return secret
	}

	return nil
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
	cutoff := now.Add(-rl.window)

	attempts := rl.attempts[ip]
	validAttempts := make([]time.Time, 0, len(attempts))
	for _, t := range attempts {
		if t.After(cutoff) {
			validAttempts = append(validAttempts, t)
		}
	}

	if len(validAttempts) >= rl.max {
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
		cutoff := now.Add(-rl.window)

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
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}
	reqHost, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		reqHost = r.Host
	}
	return originURL.Hostname() == reqHost
}

func parseEntriesBytes(content []byte) []PasswordEntry {
	var entries []PasswordEntry
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		start := bytes.IndexByte(line, '[')
		end := bytes.IndexByte(line, ']')
		if start == -1 || end == -1 || end <= start+1 {
			continue
		}

		label := string(bytes.TrimSpace(line[start+1 : end]))
		entries = append(entries, PasswordEntry{Label: label})
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Warning: scanner error while parsing entries: %v", err)
		return entries
	}

	return entries
}

func initTemplate() error {
	tmpl := `<!DOCTYPE html>
<html>
<head>
	<title>Safe</title>
	<meta name="viewport" content="width=device-width, initial-scale=1, interactive-widget=resizes-content">
	<style nonce="{{.Nonce}}">
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
		#safe-container {
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
		.copy-btn, .show-pw-btn {
			padding:0.4rem 1rem;
			font-size:0.875rem;
			white-space:nowrap;
		}
		.pw-display {
			display:none;
			width:100%;
		}
		.pw-value {
			font-family:ui-monospace, SFMono-Regular, monospace;
			font-size:0.85rem;
			font-weight:600;
			background:var(--code-bg);
			color:var(--code-text);
			padding:0.2rem 0.8rem;
			border-radius:6px;
			letter-spacing:0.05em;
			word-break:break-all;
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
		<input type="password" id="password" placeholder="Password">
		<button id="unlock-btn">Unlock</button>
	</div>
	<div id="safe-container">
		<div id="entries"></div>
	</div>
	<script nonce="{{.Nonce}}">
		const prefix = {{.Prefix}};
		let entries = [], autoHideTimers = {}, clipboardTimers = {}, inactivityTimer;
		const INACTIVITY_TIMEOUT = 120000;
		function resetInactivity() { clearTimeout(inactivityTimer); inactivityTimer = setTimeout(() => { entries.forEach((_, i) => { hidePassword(i); if (clipboardTimers[i]) { clearTimeout(clipboardTimers[i]); delete clipboardTimers[i]; } }); navigator.clipboard.writeText('').catch(() => {}); document.cookie = 'session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=' + (prefix ? prefix + '/' : '/') + ';'; alert('Session expired'); location.reload(); }, INACTIVITY_TIMEOUT); }
		async function login() { const p = document.getElementById('password'), pw = p.value; p.value = ''; const r = await fetch(prefix + '/decrypt/', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'password=' + encodeURIComponent(pw) }); if (r.ok) { entries = await r.json(); document.getElementById('login-container').style.display = 'none'; document.getElementById('safe-container').style.display = 'flex'; renderEntries(); resetInactivity(); ['mousemove','keypress','click'].forEach(e => document.addEventListener(e, resetInactivity)); } else { alert('Invalid password'); p.focus(); } }
		function renderEntries() {
			const c = document.getElementById('entries');
			c.innerHTML = '';
			entries.forEach((e, i) => {
				const d = document.createElement('div');
				d.className = 'entry';

				const label = document.createElement('div');
				label.className = 'entry-label';
				label.textContent = e.label;

				const copyBtn = document.createElement('button');
				copyBtn.className = 'copy-btn';
				copyBtn.textContent = 'Copy';
				copyBtn.addEventListener('click', () => copyPassword(i));

				const showBtn = document.createElement('button');
				showBtn.className = 'show-pw-btn';
				showBtn.textContent = 'Show password';
				showBtn.addEventListener('click', () => togglePassword(i));

				const actions = document.createElement('div');
				actions.className = 'entry-actions';
				actions.appendChild(copyBtn);
				actions.appendChild(showBtn);

				const pwDisplay = document.createElement('div');
				pwDisplay.className = 'pw-display';
				pwDisplay.id = 'pw-' + i;
				const pwValue = document.createElement('code');
				pwValue.className = 'pw-value';
				pwValue.id = 'pw-value-' + i;
				pwDisplay.appendChild(pwValue);

				d.appendChild(label);
				d.appendChild(actions);
				d.appendChild(pwDisplay);
				c.appendChild(d);
			});
		}
		async function fetchPassword(i) {
			const r = await fetch(prefix + '/retrieve/', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'label=' + encodeURIComponent(entries[i].label) });
			if (!r.ok) return null;
			const d = await r.json();
			return d.password;
		}
		async function copyPassword(i) {
			const pw = await fetchPassword(i);
			if (pw === null) { alert('Failed to retrieve password'); return; }
			await navigator.clipboard.writeText(pw);
			const b = document.getElementById('entries').children[i].querySelector('.copy-btn');
			b.textContent = 'Copied!';
			if (clipboardTimers[i]) clearTimeout(clipboardTimers[i]);
			clipboardTimers[i] = setTimeout(() => {
				b.textContent = 'Copy';
				navigator.clipboard.writeText('').catch(() => {});
			}, 5000);
		}
		async function togglePassword(i) {
			const display = document.getElementById('pw-' + i);
			if (display.style.display === 'block') {
				hidePassword(i);
			} else {
				const pw = await fetchPassword(i);
				if (pw === null) { alert('Failed to retrieve password'); return; }
				entries.forEach((_, j) => { if (j !== i) hidePassword(j); });
				document.getElementById('pw-value-' + i).textContent = pw;
				display.style.display = 'block';
				if (autoHideTimers[i]) clearTimeout(autoHideTimers[i]);
				autoHideTimers[i] = setTimeout(() => hidePassword(i), 5000);
			}
		}
		function hidePassword(i) {
			const display = document.getElementById('pw-' + i);
			display.style.display = 'none';
			document.getElementById('pw-value-' + i).textContent = '';
			if (autoHideTimers[i]) { clearTimeout(autoHideTimers[i]); delete autoHideTimers[i]; }
		}
		window.onload = () => {
			document.getElementById('password').focus();
			document.getElementById('password').addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
			document.getElementById('unlock-btn').addEventListener('click', login);
		};
	</script>
</body>
</html>`

	var err error
	pageTemplate, err = template.New("page").Parse(tmpl)
	return err
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: safe [-addr string] [-dev] [-encrypt-password string] [-file string] [-port number] [-prefix string]\n")
		flag.PrintDefaults()
	}

	addr := flag.String("addr", "127.0.0.1", "listening address")
	port := flag.Int("port", 3072, "listening port")
	encryptPassword := flag.String("encrypt-password", "", "password to encrypt plaintext file (CLI mode)")
	flag.StringVar(&contentFile, "file", "safe.enc", "encrypted file")
	flag.StringVar(&prefix, "prefix", "", "URL prefix")
	flag.BoolVar(&devMode, "dev", false, "disable secure cookie and use unsafe-inline CSP (HTTP testing only)")
	flag.Parse()

	contentFile = normalizeFilename(contentFile)

	if *encryptPassword != "" {
		fileData, err := os.ReadFile(contentFile)
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}

		if isEncrypted(fileData) {
			log.Fatalf("Error: file is already encrypted")
		}

		if err := encryptFile(contentFile, *encryptPassword); err != nil {
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
			fmt.Fprintf(os.Stderr, "  [Label] password\n")
			fmt.Fprintf(os.Stderr, "Encrypt it with: safe -encrypt-password 'password' -file %s\n", contentFile)
			os.Exit(1)
		}
		log.Fatalf("Error reading file: %v", err)
	}

	if !isEncrypted(fileData) {
		fmt.Fprintf(os.Stderr, "Error: file %s is not encrypted\n", contentFile)
		fmt.Fprintf(os.Stderr, "Encrypt it with: safe -encrypt-password 'password' -file %s\n", contentFile)
		os.Exit(1)
	}

	if len(fileData) < 66 {
		fmt.Fprintf(os.Stderr, "Error: file %s is corrupted or invalid (too small)\n", contentFile)
		os.Exit(1)
	}

	remainingAfterHeader := len(fileData) - 38
	if remainingAfterHeader < 28 {
		fmt.Fprintf(os.Stderr, "Error: file %s is corrupted or invalid\n", contentFile)
		os.Exit(1)
	}

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

	// Disable core dumps so session keys cannot leak to disk
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		log.Printf("Warning: could not disable core dumps: %v", err)
	}

	mux := http.NewServeMux()
	prefix = strings.TrimSuffix(prefix, "/")
	for _, c := range prefix {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' || c == '-' || c == '_') {
			log.Fatalf("Invalid -prefix %q: only alphanumeric, '/', '-', '_' allowed", prefix)
		}
	}
	mux.HandleFunc(prefix+"/", securityHeaders(timeoutMiddleware(handleHome)))
	mux.HandleFunc(prefix+"/decrypt/", securityHeaders(timeoutMiddleware(handleDecrypt)))
	mux.HandleFunc(prefix+"/retrieve/", securityHeaders(timeoutMiddleware(handleRetrieve)))

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", *addr, *port),
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go cleanupSessions()
	go limiter.cleanup()
	go retrieveLimiter.cleanup()

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

	log.Printf("Starting password safe on %s", srv.Addr)
	if devMode {
		log.Printf("WARNING: dev mode enabled — secure cookie and CSP nonce disabled, do not use in production")
	}

	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != prefix+"/" {
		http.Redirect(w, r, prefix+"/", http.StatusFound)
		return
	}

	nonce := ""
	if !devMode {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		nonce = fmt.Sprintf("%x", nonceBytes)
	}

	if devMode {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	} else {
		w.Header().Set("Content-Security-Policy",
			fmt.Sprintf("default-src 'self'; script-src 'nonce-%s'; style-src 'nonce-%s'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", nonce, nonce))
	}

	data := struct {
		Prefix template.JS
		Nonce  string
	}{
		Prefix: template.JS(fmt.Sprintf("%q", prefix)),
		Nonce:  nonce,
	}
	if err := pageTemplate.Execute(w, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !sameOrigin(r) {
		http.Error(w, "Invalid origin", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 3072)
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

	select {
	case loginSemaphore <- struct{}{}:
		defer func() { <-loginSemaphore }()
	default:
		http.Error(w, "Server busy", http.StatusTooManyRequests)
		return
	}

	encrypted, err := os.ReadFile(contentFile)

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
		log.Printf("Failed login attempt from %s (wrong password or corrupted file)", remoteIP)
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	entries := parseEntriesBytes(decrypted)

	masterKey := deriveKey(password, salt)
	sessionKey := deriveSessionKey(masterKey, "password-session-key-v1")
	zeroBytes(masterKey)

	encryptedForSession, err := encrypt(decrypted, sessionKey, nil)
	zeroBytes(decrypted)

	if err != nil {
		zeroBytes(sessionKey)
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	sessionToken, err := createSession(encryptedForSession, sessionKey)
	zeroBytes(sessionKey)

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
		Secure:   !devMode,
		SameSite: http.SameSiteStrictMode,
	})

	log.Printf("Successful login from %s (%d entries)", remoteIP, len(entries))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(entries)
}

func handleRetrieve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !sameOrigin(r) {
		http.Error(w, "Invalid origin", http.StatusForbidden)
		return
	}

	sessionCookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// validate token is exactly 64 lowercase hex chars (32 random bytes as %x)
	token := sessionCookie.Value
	if len(token) != 64 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	remoteIP := getRemoteIP(r)
	if !retrieveLimiter.allow(remoteIP) {
		log.Printf("Rate limit exceeded from %s", remoteIP)
		http.Error(w, "Too many attempts", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 3072)
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
	sess, exists := sessions[token]
	if !exists || time.Now().After(sess.expiresAt) {
		if exists {
			sess.clearSession()
			delete(sessions, token)
		}
		sessionMu.Unlock()
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}
	sess.expiresAt = time.Now().Add(sessionTimeout)

	secret, err := sess.getSecret(label)
	sessionMu.Unlock()

	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	defer zeroBytes(secret)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{"password": string(secret)})
}
