package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"

	"golang.org/x/crypto/argon2"
	_ "github.com/lib/pq"
	"github.com/joho/godotenv"
)

const (
	memory = 46 * 1024
	iterations = 1
	parallelism = 1
	saltLength = 16
	keyLength = 32
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodeHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory,
		iterations,
		parallelism,
		b64Salt,
		b64Hash,
	)

	return encodeHash, nil
}

func main() {
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

	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	fmt.Print("How many users do you want to add? ")
	var numUsersStr string
	fmt.Scanln(&numUsersStr)

	numUsers, err := strconv.Atoi(numUsersStr)
	if err != nil || numUsers <= 0 {
		log.Fatal("Please enter a valid positive number")
	}

	for i := 0; i < numUsers; i++ {
		fmt.Print("Enter username: ")
		var username string
		fmt.Scanln(&username)

		fmt.Print("Enter password: ")
		var password string
		fmt.Scanln(&password)

		fmt.Print("Enter team name: ")
		var team string
		fmt.Scanln(&team)

		hash, err := HashPassword(password)
		if err != nil {
			log.Fatal("Error hashing password:", err)
		}

		_, err = db.Exec("INSERT INTO users (username, password_hash, team) VALUES ($1, $2, $3)", username, hash, team)
		if err != nil {
			log.Fatal("Failed to create user:", err)
		}

		fmt.Println("User created successfully!")
	}

	fmt.Printf("Finished creating %d users.\n", numUsers)
}
