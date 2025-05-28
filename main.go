package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
	_ "github.com/lib/pq"
	"github.com/joho/godotenv"
)

const (
	memory = 64 * 1024
	iterations = 3
	parallelism = 4
	saltLength = 16
	keyLength = 32
)

var (
	questions []Question
	sessions = make(map[string]*Session)
	sessionMux sync.RWMutex
	db *sql.DB
)

type Question struct {
	ID int `json:"id"`
	Image string `json:"image"`
	Answer string `json:"answer"`
}

type Session struct {
	CurrentIndex int
	Username string
	Authenticated bool
}

func initDB() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
}

func compareHash(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) !=6 {
		return false, fmt.Errorf("invalid hash format")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	
	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	newHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)

	if subtle.ConstantTimeCompare(newHash, storedHash) == 1 {
		return true, nil
	}
	return false, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
		case http.MethodGet:
			http.ServeFile(w, r, "templates/login.html")
		case http.MethodPost:
			r.ParseForm()
			username := r.FormValue("user")
			password := r.FormValue("password")

			var storedHash string
			err := db.QueryRow("SELECT password_hash FROM users WHERE username = $1", username,).Scan(&storedHash)

			if err != nil {
				if err == sql.ErrNoRows {
					http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				} else {
					http.Error(w, "Database error", http.StatusInternalServerError)
				}
				return
			}

			match, err := compareHash(password, storedHash)
			if err != nil {
				http.Error(w, "Authentication error", http.StatusInternalServerError)
				return
			}

			if !match {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			session := getSession(w, r)
			session.Authenticated = true
			session.Username = username

			w.Header().Set("HX-Redirect", "/")
			w.WriteHeader(http.StatusOK)
			
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := getSession(w, r)
		if !session.Authenticated {
			if r.Header.Get("HX-Request") != "true" {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func generateSessionID()string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func getSession(w http.ResponseWriter, r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		sessionID := generateSessionID()
		session := &Session{CurrentIndex: 0}
		sessionMux.Lock()
		sessions[sessionID] = session
		sessionMux.Unlock()

		http.SetCookie(w, &http.Cookie {
			Name: "session_id",
			Value: sessionID,
			Path: "/",
			HttpOnly: true,
		})
		return session
	}
	
	sessionMux.RLock()
	session := sessions[cookie.Value]
	sessionMux.RUnlock()

	if session == nil {
		newSessionID := generateSessionID()
		session = &Session{CurrentIndex: 0}
		sessionMux.Lock()
		sessions[newSessionID] = session
		sessionMux.Unlock()

		http.SetCookie(w, &http.Cookie {
			Name: "session_id",
			Value: newSessionID,
			Path: "/",
			HttpOnly: true,
		})
	}
	return session
}

func loadQuestions() error {
	data, err := os.ReadFile("data/questions.json")
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &questions)
}

func main() {
	err := os.MkdirAll("logs", 0755)
	if err != nil {
		log.Fatal(err)
	}

	logFile, err := os.OpenFile("logs/answers.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	initDB()
	defer db.Close()

	if err := loadQuestions(); err != nil {
		panic(err)
	}

	http.HandleFunc("/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/index.html")
	}))

	http.HandleFunc("/login", loginHandler)

	http.HandleFunc("/current-image", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
	
		session := getSession(w, r)
		if session.CurrentIndex >= len(questions) {
			http.Error(w, "No more questions", http.StatusNotFound)
			return
		}
		
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, questions[session.CurrentIndex].Image)
	}))

	http.HandleFunc("/submit-answer", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		session := getSession(w, r)
		if session.CurrentIndex >= len(questions) {
			w.Write([]byte("done"))
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		answer := r.FormValue("answer")
		correctAnswer := questions[session.CurrentIndex].Answer
		normalizedAnswer := strings.ToLower(answer)
		isCorrect := normalizedAnswer == correctAnswer

		log.Printf("User: %s, Answer: %s, Correct: %t\n", session.Username, answer, isCorrect)
		
		if isCorrect {
			session.CurrentIndex++
			w.Write([]byte("correct"))
		} else {
			w.Write([]byte("incorrect"))
		}
	}))

	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
