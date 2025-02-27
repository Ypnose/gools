package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
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
)

var (
	content     string
	contentFile string
	prefix      string
	mu          sync.Mutex
)

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
			--link-color:#0366d6;
			font-size:16px;
		}
		@media (prefers-color-scheme:dark) {
			:root {
				--background:#18212c;
				--text:#c9d1d9;
				--link-color:#58a6ff;
			}
		}
		@media (max-width:600px) {
			:root {
				font-size:0.875rem;
			}
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
		const prefix = {{.Prefix}};
		let timeout;
		let currentPassword;

		async function login() {
			currentPassword = document.getElementById('password').value;
			const response = await fetch(prefix + '/decrypt/', {
				method: 'POST',
				headers: {'Content-Type': 'application/x-www-form-urlencoded'},
				body: 'password=' + encodeURIComponent(currentPassword)
			});

			if (response.ok) {
				document.querySelector('#login-container').style.display = 'none';
				document.querySelector('#editor-container').style.display = 'block';
				const text = await response.text();
				document.getElementById('editor').value = text;
			} else {
				alert('Invalid password');
				document.getElementById('password').value = '';
				document.getElementById('password').focus();
			}
		}

		function saveContent() {
			clearTimeout(timeout);
			timeout = setTimeout(() => {
				fetch(prefix + '/save/', {
					method: 'POST',
					headers: {'Content-Type': 'application/x-www-form-urlencoded'},
					body: 'content=' + encodeURIComponent(document.getElementById('editor').value) +
						  '&password=' + encodeURIComponent(currentPassword)
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
		<input type="password" id="password" placeholder="Enter password" onkeydown="if(event.key==='Enter')login()">
		<button onclick="login()">Unlock</button>
	</div>
	<div id="editor-container">
		<div id="filename">{{.Filename}}</div>
		<textarea id="editor" spellcheck="false"></textarea>
	</div>
</body>
</html>
`

func init() {
	if err := os.MkdirAll(filepath.Dir(contentFile), 0700); err != nil {
		log.Fatal(err)
	}
}

func sanitizeFilename(filename string) string {
	return filepath.Clean(strings.TrimSpace(filename))
}

func validateContent(content string) bool {
	return len(content) <= 1024*1024 // 1MB limit
}

func timeoutMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		next(w, r.WithContext(ctx))
	}
}

func deriveKey(password string, salt []byte) []byte {
	// Multiple iterations of SHA-512 for key stretching
	key := sha512.Sum512(append([]byte(password), salt...))
	for i := 0; i < 250000; i++ {
		key = sha512.Sum512(append(key[:], salt...))
	}
	return key[:32] // First 32 bytes for AES-256
}

func encrypt(data []byte, password string) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := deriveKey(password, salt)
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

	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return append(salt, encryptedData...), nil
}

func decrypt(data []byte, password string) ([]byte, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	salt := data[:32]
	data = data[32:]

	key := deriveKey(password, salt)
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
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func getRemoteIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	return strings.Split(r.RemoteAddr, ":")[0]
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

	contentFile = sanitizeFilename(contentFile)

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", *addr, *port),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	prefix = strings.TrimSuffix(prefix, "/")
	http.HandleFunc(prefix+"/", timeoutMiddleware(handleHome))
	http.HandleFunc(prefix+"/save/", timeoutMiddleware(handleSave))
	http.HandleFunc(prefix+"/decrypt/", timeoutMiddleware(handleDecrypt))

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

	tmpl := template.Must(template.New("page").Parse(htmlTemplate))
	tmpl.Execute(w, data)
}

func handleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	content := r.Form.Get("content")
	password := r.Form.Get("password")

	if !validateContent(content) {
		http.Error(w, "Content too large", http.StatusBadRequest)
		return
	}

	encrypted, err := encrypt([]byte(content), password)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	mu.Lock()
	err = os.WriteFile(contentFile, encrypted, 0600)
	mu.Unlock()

	if err != nil {
		http.Error(w, "Failed to save content", http.StatusInternalServerError)
		return
	}
}

func handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	password := r.Form.Get("password")
	if password == "" {
		http.Error(w, "Password required", http.StatusBadRequest)
		return
	}
	remoteIP := getRemoteIP(r)

	mu.Lock()
	encrypted, err := os.ReadFile(contentFile)
	mu.Unlock()

	if err != nil && !os.IsNotExist(err) {
		log.Printf("Failed read attempt from %s: %v", remoteIP, err)
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	if len(encrypted) > 0 {
		decrypted, err := decrypt(encrypted, password)
		if err != nil {
			log.Printf("Failed login attempt from %s", remoteIP)
			http.Error(w, "Invalid password", http.StatusUnauthorized)
			return
		}
		log.Printf("Successful login from %s", remoteIP)
		fmt.Fprint(w, string(decrypted))
	} else {
		encrypted, err := encrypt([]byte(""), password)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		mu.Lock()
		err = os.WriteFile(contentFile, encrypted, 0600)
		mu.Unlock()

		if err != nil {
			http.Error(w, "Failed to create file", http.StatusInternalServerError)
			return
		}

		log.Printf("New file created from %s", remoteIP)
		fmt.Fprint(w, "")
	}
}
