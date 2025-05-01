package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type Question struct {
	ID int `json:"id"`
	Image string `json:"image"`
	Answer string `json:"answer"`
}

var questions []Question
var currentQuestionIndex = 0

func loadQuestions() error {
	data, err := os.ReadFile("questions.json")
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
		http.ServeFile(w, r, "index.html")
	})

	http.HandleFunc("/current-image", func(w http.ResponseWriter, r *http.Request) {
		if currentQuestionIndex >= len(questions) {
			http.Error(w, "No more questions", http.StatusNotFound)
			return
		}
		http.ServeFile(w, r, questions[currentQuestionIndex].Image)
	})

	http.HandleFunc("/submit-answer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		answer := r.FormValue("answer")
		fmt.Println("Received answer:", answer)
		fmt.Println("Current question index:", currentQuestionIndex)

		if currentQuestionIndex < len(questions) {
			correctAnswer := questions[currentQuestionIndex].Answer
			if answer == correctAnswer {
				fmt.Println("Correct!")
				currentQuestionIndex++
				
				// Send JSON response with correct answer status
				w.Header().Set("Content-Type", "application/json")
				response := map[string]interface{}{
					"correct": true,
					"completed": currentQuestionIndex >= len(questions),
				}
				json.NewEncoder(w).Encode(response)
			} else {
				fmt.Println("Incorrect! Try again.")
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]bool{"correct": false})
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"completed": true})
		}
	})

	// Add a new endpoint to check current question index
	http.HandleFunc("/current-question-info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		info := map[string]interface{}{
			"currentIndex": currentQuestionIndex,
			"totalQuestions": len(questions),
		}
		json.NewEncoder(w).Encode(info)
	})

	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
