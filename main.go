package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
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
	AnswerHash string `json:"answerHash"`
}

type Session struct {
	Username string
	Team string
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

func getTeamProgress(team string) (int, error) {
	var currentIndex int
	err := db.QueryRow("SELECT current_index FROM team_progress WHERE team = $1", team).Scan(&currentIndex)
	
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}

	return currentIndex, nil
}

func updateTeamProgress(team string) error {
	_, err := db.Exec("UPDATE team_progress SET current_index = current_index + 1 WHERE team = $1", team)	
	return err
}

func comparePasswordHash(password, encodedHash string) (bool, error) {
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

func hashAnswer(answer string) string {
	normalizedAnswer := strings.ToLower(answer)

	hash := sha256.Sum256([]byte(normalizedAnswer))

	return hex.EncodeToString(hash[:])
}

func compareAnswerHash(userAnswer, storedHash string) bool {
	userHash := hashAnswer(userAnswer)
	return subtle.ConstantTimeCompare([]byte(userHash), []byte(storedHash)) == 1
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
		case http.MethodGet:
			http.ServeFile(w, r, "templates/login.html")
		case http.MethodPost:
			r.ParseForm()
			username := r.FormValue("user")
			password := r.FormValue("password")

			var storedHash, team string
			err := db.QueryRow("SELECT password_hash, team FROM users WHERE username = $1", username).Scan(&storedHash, &team)

			if err != nil {
				if err == sql.ErrNoRows {
					http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				} else {
					http.Error(w, "Database error", http.StatusInternalServerError)
				}
				return
			}

			match, err := comparePasswordHash(password, storedHash)
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
			session.Team = team

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
		newSession := &Session{}
		sessionMux.Lock()
		sessions[sessionID] = newSession
		sessionMux.Unlock()

		http.SetCookie(w, &http.Cookie {
			Name: "session_id",
			Value: sessionID,
			Path: "/",
			HttpOnly: true,
		})
		return newSession
	}
	
	sessionMux.RLock()
	session := sessions[cookie.Value]
	sessionMux.RUnlock()

	if session == nil {
		sessionID := generateSessionID()
		newSession := &Session{}
		sessionMux.Lock()
		sessions[sessionID] = newSession
		sessionMux.Unlock()

		http.SetCookie(w, &http.Cookie {
			Name: "session_id",
			Value: sessionID,
			Path: "/",
			HttpOnly: true,
		})
		return newSession
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

	logFile, err := os.OpenFile("logs/latest.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
		
		currentIndex, err := getTeamProgress(session.Team)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		if currentIndex >= len(questions) {
			http.Error(w, "No more questions", http.StatusNotFound)
			return
		}
		
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, questions[currentIndex].Image)
	}))

	http.HandleFunc("/submit-answer", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		session := getSession(w, r)

		currentIndex, err := getTeamProgress(session.Team)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		if currentIndex >= len(questions) {
			w.Write([]byte("done"))
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		answer := r.FormValue("answer")
		correctAnswerHash := questions[currentIndex].AnswerHash
		isCorrect := compareAnswerHash(answer, correctAnswerHash)
		
		if isCorrect {
			log.Printf("User: %s, Team: %s, Question: %d, Correct: %t\n", session.Username, session.Team, currentIndex+1, isCorrect)

			if err := updateTeamProgress(session.Team); err != nil {
				http.Error(w, "Failed to update progress", http.StatusInternalServerError)
				return
			}

			w.Write([]byte("correct"))
		} else {
			log.Printf("User: %s, Team: %s, Question: %d, Correct: %t, Answer: %s\n", session.Username, session.Team, currentIndex+1, isCorrect, answer)
			w.Write([]byte("incorrect"))
		}
	}))

	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
