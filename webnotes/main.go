package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
)

var (
	contentFile string
	prefix      string
	mu          sync.Mutex
	sessions    = make(map[string]*Session)
	sessionMu   sync.Mutex
	limiter     = &rateLimiter{attempts: make(map[string][]time.Time)}
)

type Session struct {
	key       []byte
	expiresAt time.Time
}

type rateLimiter struct {
	attempts map[string][]time.Time
	mu       sync.Mutex
}

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Notes</title>
	<meta name="viewport" content="width=device-width, initial-scale=1, interactive-widget=resizes-content">
	<style>
		:root {
			--background:#fff;
			--text:#24292e;
			font-size:16px;
		}
		@media (prefers-color-scheme:dark) {
			:root {
				--background:#21292c;
				--text:#c9d1d9;
			}
			input[type="password"] {
				background-color:#21292c;
				color:#c5d1d3;
			}
		}
		@media (max-width:600px) {
			:root { font-size:0.875rem; }
		}
		body {
			font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
			background:var(--background);
			margin:0;
			padding:0;
			overflow:hidden;
		}
		body,#filename,#editor { color:var(--text); }
		body,#login-container,#editor-container { height:100dvh; }
		#login-container {
			display:flex;
			justify-content:center;
			align-items:center;
			flex-direction:column;
		}
		input[type="password"],button { font-size:1rem; }
		input[type="password"] {
			padding:0.5rem;
			margin:0.625rem;
			border:1px solid #ced4da;
		}
		button { padding:0.35rem 1rem; }
		#editor-container,#filename { display:none; }
		#editor-container,#filename,#editor { box-sizing:border-box; }
		#editor-container { position:relative; }
		#filename,#editor { background-color:var(--background); }
		#filename {
			font-size:0.85rem;
			border-bottom:1px solid rgba(128, 128, 128, 0.2);
			position:fixed;
			top:0;
			left:0;
			right:0;
			padding:0.55rem 1rem;
			z-index:1;
		}
		#editor-container #filename { display:block; }
		#editor {
			font-family:ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace;
			font-size:0.9rem;
			width:100%;
			height:calc(100% - 2.5rem);
			border:none;
			outline:none;
			padding:1rem;
			margin-top:2.5rem;
			resize:none;
			line-height:1.2;
		}
	</style>
	<script>
		const prefix = "{{.Prefix}}";
		let timeout;
		let inactivityTimer;
		const INACTIVITY_TIMEOUT = 10 * 60 * 1000; // 10 minutes

		function resetInactivity() {
			clearTimeout(inactivityTimer);
			inactivityTimer = setTimeout(() => {
				const cookiePath = prefix ? prefix + '/' : '/';
				document.cookie = 'session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=' + cookiePath + ';';
				alert('Session expired due to inactivity');
				location.reload();
			}, INACTIVITY_TIMEOUT);
		}

		async function login() {
			const password = document.getElementById('password').value;
			const passwordField = document.getElementById('password');

			const response = await fetch(prefix + '/decrypt/', {
				method: 'POST',
				headers: {'Content-Type': 'application/x-www-form-urlencoded'},
				body: 'password=' + encodeURIComponent(password)
			});

			passwordField.value = '';

			if (response.ok) {
				document.querySelector('#login-container').style.display = 'none';
				document.querySelector('#editor-container').style.display = 'block';
				const text = await response.text();
				document.getElementById('editor').value = text;

				resetInactivity();
				document.addEventListener('mousemove', resetInactivity);
				document.addEventListener('keypress', resetInactivity);
			} else {
				alert('Invalid password');
				passwordField.focus();
			}
		}

		function saveContent() {
			clearTimeout(timeout);
			timeout = setTimeout(() => {
				fetch(prefix + '/save/', {
					method: 'POST',
					headers: {'Content-Type': 'application/x-www-form-urlencoded'},
					body: 'content=' + encodeURIComponent(document.getElementById('editor').value)
				});
			}, 500);
		}

		window.onload = function() {
			const editor = document.getElementById('editor');
			editor.addEventListener('input', saveContent);
			document.getElementById('password').focus();
		};
	</script>
</head>
<body>
	<div id="login-container">
		<input type="password" id="password" placeholder="Password" onkeydown="if(event.key==='Enter')login()">
		<button onclick="login()">Unlock</button>
	</div>
	<div id="editor-container">
		<div id="filename">{{.Filename}}</div>
		<textarea id="editor" spellcheck="false"></textarea>
	</div>
</body>
</html>
`

var pageTemplate *template.Template

func normalizeFilename(filename string) string {
	// Note: This only normalizes path, does NOT prevent directory traversal
	// Safe here because filename comes from flag.StringVar, not user input
	return filepath.Clean(strings.TrimSpace(filename))
}

func validateContent(content string) bool {
	return len(content) <= 1024*1024
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
		next(w, r)
	}
}

func deriveKey(password string, salt []byte) []byte {
	// Argon2id parameters:
	// - 4 passes over memory
	// - 64MB memory usage
	// - 2 threads of parallelism
	// - 32-byte output key for AES-256
	return argon2.IDKey([]byte(password), salt, 4, 64*1024, 2, 32)
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

	// GCM.Seal appends auth tag automatically - provides integrity
	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return encryptedData, nil
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

	// GCM.Open verifies integrity - fails if tampered
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("integrity check failed")
	}

	return decrypted, nil
}

func decryptWithPassword(data []byte, password string) ([]byte, []byte, error) {
	if len(data) < 32 {
		return nil, nil, fmt.Errorf("invalid data")
	}

	salt := data[:32]
	encryptedData := data[32:]

	key := deriveKey(password, salt)

	decrypted, err := decrypt(encryptedData, key)
	if err != nil {
		zeroBytes(key)
		return nil, nil, err
	}

	return decrypted, key, nil
}

func createSession(key []byte) (string, error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	// Prevent unbounded session growth
	if len(sessions) >= 100 {
		return "", fmt.Errorf("too many sessions")
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	token := fmt.Sprintf("%x", tokenBytes)

	sessions[token] = &Session{
		key:       key,
		expiresAt: time.Now().Add(10 * time.Minute),
	}

	return token, nil
}

func validateSession(token string) ([]byte, bool) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	session, exists := sessions[token]
	if !exists || time.Now().After(session.expiresAt) {
		if exists {
			zeroBytes(session.key)
			delete(sessions, token)
		}
		return nil, false
	}

	// Return a copy of the key to prevent use-after-zero
	keyCopy := make([]byte, len(session.key))
	copy(keyCopy, session.key)
	return keyCopy, true
}

func extendSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if session, exists := sessions[token]; exists {
		session.expiresAt = time.Now().Add(10 * time.Minute)
	}
}

func cleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		sessionMu.Lock()
		now := time.Now()
		for token, session := range sessions {
			if now.After(session.expiresAt) {
				zeroBytes(session.key)
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
	cutoff := now.Add(-5 * time.Minute)

	// Clean old attempts for this IP
	var recent []time.Time
	for _, t := range rl.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= 5 {
		return false
	}

	// Record this attempt
	rl.attempts[ip] = append(recent, now)
	return true
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		cutoff := now.Add(-5 * time.Minute)

		for ip, attempts := range rl.attempts {
			var recent []time.Time
			for _, t := range attempts {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}

			if len(recent) == 0 {
				delete(rl.attempts, ip)
			} else {
				rl.attempts[ip] = recent
			}
		}
		rl.mu.Unlock()
	}
}

func getRemoteIP(r *http.Request) string {
	// Only trust X-Forwarded-For if request comes from localhost
	remoteAddr := strings.Split(r.RemoteAddr, ":")[0]
	if remoteAddr == "127.0.0.1" || remoteAddr == "::1" {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			return strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
	}
	return remoteAddr
}

func main() {
	flag.Usage = func() {
		progName := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage: %s [-addr string] [-file string] [-port number] [-prefix string]\n", progName)
		flag.PrintDefaults()
	}

	addr := flag.String("addr", "127.0.0.1", "listening address")
	port := flag.Int("port", 2048, "listening port")
	flag.StringVar(&contentFile, "file", "notes.enc", "encrypted file to store notes")
	flag.StringVar(&prefix, "prefix", "", "URL prefix")
	flag.Parse()

	contentFile = normalizeFilename(contentFile)

	var err error
	pageTemplate, err = template.New("page").Parse(htmlTemplate)
	if err != nil {
		log.Fatal(err)
	}

	// Create directory for content file if needed
	if dir := filepath.Dir(contentFile); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatal(err)
		}
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", *addr, *port),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	prefix = strings.TrimSuffix(prefix, "/")
	http.HandleFunc(prefix+"/", securityHeaders(timeoutMiddleware(handleHome)))
	http.HandleFunc(prefix+"/save/", securityHeaders(timeoutMiddleware(handleSave)))
	http.HandleFunc(prefix+"/decrypt/", securityHeaders(timeoutMiddleware(handleDecrypt)))

	go cleanupSessions()
	go limiter.cleanup()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("HTTP server Shutdown: %v", err)
		}
	}()

	log.Printf("Starting server on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != prefix+"/" {
		http.Redirect(w, r, prefix+"/", http.StatusFound)
		return
	}

	data := struct {
		Filename string
		Prefix   string
	}{
		Filename: strings.TrimSuffix(filepath.Base(contentFile), ".enc"),
		Prefix:   prefix,
	}

	pageTemplate.Execute(w, data)
}

func handleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate Origin header for CSRF protection
	if origin := r.Header.Get("Origin"); origin != "" {
		// Parse origin to compare hostnames (handles port differences)
		originHost := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
		originHost = strings.Split(originHost, ":")[0] // Remove port if present
		requestHost := strings.Split(r.Host, ":")[0]   // Remove port if present

		if originHost != requestHost {
			http.Error(w, "Invalid origin", http.StatusForbidden)
			return
		}
	}

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	key, valid := validateSession(cookie.Value)
	if !valid {
		http.Error(w, "Session expired", http.StatusUnauthorized)
		return
	}
	defer zeroBytes(key) // Zero key copy when done

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	content := r.Form.Get("content")

	if !validateContent(content) {
		http.Error(w, "Content too large", http.StatusBadRequest)
		return
	}

	encrypted, err := encrypt([]byte(content), key)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	// Read existing file to get salt
	mu.Lock()
	existing, err := os.ReadFile(contentFile)
	mu.Unlock()

	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	if len(existing) < 32 {
		http.Error(w, "Invalid file format", http.StatusInternalServerError)
		return
	}

	// Preserve salt, replace encrypted data
	salt := existing[:32]
	result := make([]byte, 0, 32+len(encrypted))
	result = append(result, salt...)
	result = append(result, encrypted...)

	// Atomic write: write to temp file, then rename
	tmpFile := contentFile + ".tmp"
	mu.Lock()
	err = os.WriteFile(tmpFile, result, 0600)
	if err == nil {
		err = os.Rename(tmpFile, contentFile)
	}
	if err != nil {
		os.Remove(tmpFile) // Clean up on failure
	}
	mu.Unlock()

	if err != nil {
		http.Error(w, "Failed to save content", http.StatusInternalServerError)
		return
	}

	// Extend session only after successful save
	extendSession(cookie.Value)
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate Origin header for CSRF protection
	if origin := r.Header.Get("Origin"); origin != "" {
		// Parse origin to compare hostnames (handles port differences)
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

	// Check rate limit
	if !limiter.allow(remoteIP) {
		log.Printf("Rate limit exceeded from %s", remoteIP)
		http.Error(w, "Too many attempts. Please try again later.", http.StatusTooManyRequests)
		return
	}

	mu.Lock()
	encrypted, err := os.ReadFile(contentFile)
	mu.Unlock()

	if err != nil && !os.IsNotExist(err) {
		log.Printf("Failed read attempt from %s: %v", remoteIP, err)
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	cookiePath := "/"
	if prefix != "" {
		cookiePath = prefix + "/"
	}

	if len(encrypted) > 0 {
		decrypted, key, err := decryptWithPassword(encrypted, password)
		if err != nil {
			if strings.Contains(err.Error(), "integrity check failed") {
				log.Printf("Integrity check failed from %s - possible file tampering", remoteIP)
			} else {
				log.Printf("Failed login attempt from %s", remoteIP)
			}
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}

		// Create session with derived key
		sessionToken, err := createSession(key)
		if err != nil {
			zeroBytes(key)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    sessionToken,
			Path:     cookiePath,
			MaxAge:   600, // 10 minutes
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		log.Printf("Successful login from %s", remoteIP)
		fmt.Fprint(w, string(decrypted))
	} else {
		// New file - derive key from password
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			http.Error(w, "Failed to generate salt", http.StatusInternalServerError)
			return
		}

		key := deriveKey(password, salt)

		encrypted, err := encrypt([]byte(""), key)
		if err != nil {
			zeroBytes(key)
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		// Prepend salt
		result := make([]byte, 0, 32+len(encrypted))
		result = append(result, salt...)
		result = append(result, encrypted...)

		mu.Lock()
		err = os.WriteFile(contentFile, result, 0600)
		mu.Unlock()

		if err != nil {
			zeroBytes(key)
			http.Error(w, "Failed to create file", http.StatusInternalServerError)
			return
		}

		// Create session with derived key
		sessionToken, err := createSession(key)
		if err != nil {
			zeroBytes(key)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    sessionToken,
			Path:     cookiePath,
			MaxAge:   600, // 10 minutes
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		log.Printf("New file created from %s", remoteIP)
		fmt.Fprint(w, "")
	}
}
