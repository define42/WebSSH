package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// --- Types ---

type sshConnInfo struct {
	IP       string `json:"ip"`
	Username string `json:"username"`
	Password string `json:"password"`
	Port     string `json:"port"`
	Expire   int64  `json:"expire"` // UNIX timestamp (seconds)
}

var (
	encryptionKey []byte
	log           = logrus.New()
	logFilePath   string
	fileWriter    io.Writer
	mu            sync.Mutex
)

// --- Log setup with dynamic file creation ---

func setupLogging() {

	// create folder /log if not exists
	if err := os.MkdirAll("/log/", 0755); err != nil {
		logrus.Fatalf("Failed to create log directory: %v", err)
	}

	// Timestamped filename
	ts := time.Now().Format("2006-01-02_15-04-05")
	logFilePath = filepath.Join("/log/", "webssh-"+ts+".log")

	createLogFile := func() io.Writer {
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			logrus.Fatalf("Failed to open log file: %v", err)
		}
		return file
	}

	fileWriter = createLogFile()

	// Hook that checks file existence on every log write
	log.AddHook(&fileCheckHook{createFile: createLogFile})

	mw := io.MultiWriter(os.Stdout, fileWriter)

	log.SetOutput(mw)
	log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
	log.SetLevel(logrus.InfoLevel)

	log.Infof("Logging to console and %s", logFilePath)
}

// Custom hook to recreate file if deleted
type fileCheckHook struct {
	createFile func() io.Writer
}

func (h *fileCheckHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *fileCheckHook) Fire(entry *logrus.Entry) error {
	mu.Lock()
	defer mu.Unlock()

	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		newFile := h.createFile()
		fileWriter = newFile
		log.SetOutput(io.MultiWriter(os.Stdout, fileWriter))
		log.Infof("Log file was missing — recreated: %s", logFilePath)
	}
	return nil
}

// --- Encryption helpers ---

func init() {
	setupLogging()

	encryptionKey = make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, encryptionKey); err != nil {
		log.Fatalf("Failed to generate encryption key: %v", err)
	}
	log.Info("Generated random encryption key for this session.")
}

func encrypt(data interface{}) (string, error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decrypt(token string, out interface{}) error {
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return io.ErrUnexpectedEOF
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, out)
}

// --- WebSocket + SSH setup ---

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type resizeMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// --- Handlers ---

func connectHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var info sshConnInfo
	if err := json.Unmarshal(body, &info); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		log.Warnf("Invalid JSON input: %v", err)
		return
	}
	if info.IP == "" || info.Username == "" || info.Password == "" || info.Port == "" {
		http.Error(w, "missing SSH parameters", http.StatusBadRequest)
		log.Warn("Missing SSH parameters in request")
		return
	}

	info.Expire = time.Now().Unix() + 5

	token, err := encrypt(info)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		log.Errorf("Encryption failed: %v", err)
		return
	}

	logMessage(r, info, "Generated encrypted SSH token", logrus.InfoLevel, nil)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func logMessage(r *http.Request, info sshConnInfo, message string, level logrus.Level, err error) {

	logfields := logrus.Fields{
		"client_ip": r.RemoteAddr,
		"user":      info.Username,
		"server_ip": info.IP,
		"port":      info.Port,
	}

	if err != nil {
		logfields["error"] = err.Error()
	}

	log.WithFields(logfields).Log(level, message)
}

func terminalHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		log.Warn("Missing token in /terminal request")

		return
	}

	var info sshConnInfo
	if err := decrypt(token, &info); err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		log.Warnf("Invalid token: %v", err)
		logMessage(r, info, "Invalid token", logrus.WarnLevel, err)
		return
	}

	now := time.Now().Unix()
	if info.Expire == 0 || now > info.Expire {
		http.Error(w, "token expired", http.StatusUnauthorized)
		log.Warn("Token expired or invalid")
		logMessage(r, info, "Token expired or invalid", logrus.WarnLevel, nil)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("WebSocket upgrade failed: %v", err)
		logMessage(r, info, "WebSocket upgrade failed", logrus.ErrorLevel, err)
		return
	}
	defer ws.Close()

	sshAddr := net.JoinHostPort(info.IP, info.Port)
	config := &ssh.ClientConfig{
		User:            info.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(info.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	logMessage(r, info, "Attempting SSH connection", logrus.InfoLevel, nil)

	conn, err := ssh.Dial("tcp", sshAddr, config)
	if err != nil {

		ws.WriteMessage(websocket.TextMessage, []byte("SSH connection failed\r\n"))
		ws.WriteMessage(websocket.TextMessage, []byte(err.Error()))
		logMessage(r, info, "SSH dial failed", logrus.ErrorLevel, err)
		return
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to start SSH session\r\n"))
		logMessage(r, info, "Failed to create SSH session", logrus.ErrorLevel, err)
		return
	}
	defer session.Close()

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
		ssh.IUTF8:         1,
	}

	if err := session.RequestPty("xterm-256color", 80, 24, modes); err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to allocate PTY\r\n"))
		logMessage(r, info, "Failed to allocate PTY", logrus.ErrorLevel, err)
		return
	}

	if err := session.Shell(); err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to start remote shell\r\n"))
		logMessage(r, info, "Failed to start remote shell", logrus.ErrorLevel, err)
		return
	}

	logMessage(r, info, "SSH session started successfully", logrus.InfoLevel, nil)

	go func() { io.Copy(wsWriter{ws}, stdout) }()
	go func() { io.Copy(wsWriter{ws}, stderr) }()

	// if session ends, close WebSocket
	go func() {
		session.Wait()
		ws.Close()
		logMessage(r, info, "SSH session ended", logrus.InfoLevel, nil)
	}()

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			logMessage(r, info, "WebSocket connection closed", logrus.InfoLevel, err)

			break
		}
		if len(msg) > 0 && msg[0] == '{' {
			var resize resizeMsg
			if err := json.Unmarshal(msg, &resize); err == nil && resize.Type == "resize" {
				if err := session.WindowChange(resize.Rows, resize.Cols); err != nil {
					logMessage(r, info, "Window resize failed", logrus.WarnLevel, err)
				}
				continue
			}
		}
		if _, err := stdin.Write(msg); err != nil {
			logMessage(r, info, "Failed to write to SSH stdin", logrus.WarnLevel, err)
		}
	}
}

type wsWriter struct{ ws *websocket.Conn }

func (w wsWriter) Write(p []byte) (int, error) {
	return len(p), w.ws.WriteMessage(websocket.TextMessage, p)
}

// --- Main ---

func main() {
	fs := http.FileServer(http.Dir("web"))
	http.Handle("/", fs)
	http.HandleFunc("/connect", connectHandler)
	http.HandleFunc("/terminal", terminalHandler)

	addr := ":8080"
	log.Infof("Serving on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
