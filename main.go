package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// --- Types ---

type sshConnInfo struct {
	IP       string `json:"ip"`
	Username string `json:"username"`
	Password string `json:"password"`
	Port     string `json:"port"`
}

var encryptionKey []byte

func init() {
	encryptionKey = make([]byte, 32) // 32 bytes = AES-256
	if _, err := io.ReadFull(rand.Reader, encryptionKey); err != nil {
		log.Fatalf("failed to generate encryption key: %v", err)
	}
	fmt.Println("[INFO] Generated random encryption key for this session.")
}

// --- Encryption helpers ---

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
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, out)
}

// --- WebSocket + SSH setup ---

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type resizeMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// --- Handlers ---

// POST /connect  →  returns encrypted token
func connectHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var info sshConnInfo
	if err := json.Unmarshal(body, &info); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if info.IP == "" || info.Username == "" || info.Password == "" || info.Port == "" {
		http.Error(w, "missing SSH parameters", http.StatusBadRequest)
		return
	}

	token, err := encrypt(info)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// GET /terminal?token=ENCODED → decrypt + connect SSH
func terminalHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}

	var info sshConnInfo
	if err := decrypt(token, &info); err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer ws.Close()

	sshAddr := net.JoinHostPort(info.IP, info.Port)
	config := &ssh.ClientConfig{
		User:            info.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(info.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", sshAddr, config)
	if err != nil {
		log.Println("ssh dial:", err)
		ws.WriteMessage(websocket.TextMessage, []byte("SSH connection failed\r\n"))
		return
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to start SSH session\r\n"))
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
		return
	}

	if err := session.Shell(); err != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("Failed to start remote shell\r\n"))
		return
	}

	// SSH → WebSocket
	go func() { io.Copy(wsWriter{ws}, stdout) }()
	go func() { io.Copy(wsWriter{ws}, stderr) }()

	// WebSocket → SSH
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}
		if len(msg) > 0 && msg[0] == '{' {
			var resize resizeMsg
			if err := json.Unmarshal(msg, &resize); err == nil && resize.Type == "resize" {
				if err := session.WindowChange(resize.Rows, resize.Cols); err != nil {
					log.Println("window change:", err)
				}
				continue
			}
		}
		if _, err := stdin.Write(msg); err != nil {
			fmt.Println("stdin write:", err)
		}
	}
}

// helper type for io.Copy()
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
	fmt.Println("Serving on", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
