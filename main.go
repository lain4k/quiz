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
		http.ServeFile(w, r, "assets/1.png")
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
	})

	fmt.Println("Server started at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
