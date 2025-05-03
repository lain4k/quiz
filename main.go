package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
)

type Question struct {
	ID int `json:"id"`
	Image string `json:"image"`
	Answer string `json:"answer"`
}

type Session struct {
	CurrentIndex int
}

var (
	questions []Question
	sessions = make(map[string]*Session)
	sessionMux sync.RWMutex
)

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
	if err := loadQuestions(); err != nil {
		panic(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "templates/index.html")
	})

	http.HandleFunc("/current-image", func(w http.ResponseWriter, r *http.Request) {
	
		session := getSession(w, r)
		if session.CurrentIndex >= len(questions) {
			http.Error(w, "No more questions", http.StatusNotFound)
			return
		}
		
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, questions[session.CurrentIndex].Image)
	})

	http.HandleFunc("/submit-answer", func(w http.ResponseWriter, r *http.Request) {
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

		fmt.Println("Received answer:", answer)

		if answer == correctAnswer {
			session.CurrentIndex++
			w.Write([]byte("correct"))
		} else {
			w.Write([]byte("incorrect"))
		}
	})

	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
