package main

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"time"
)

var db *sql.DB

func InitDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./auth.db")
	if err != nil {
		return err
	}

	createUsers := `
	CREATE TABLE IF NOT EXISTS users (
		login TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		rsa_e TEXT NOT NULL,
		rsa_n TEXT NOT NULL,
		rsa_d TEXT NOT NULL
	);`

	createChallenges := `
	CREATE TABLE IF NOT EXISTS challenges (
		challenge_hash TEXT PRIMARY KEY,
		user_login TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		is_active BOOLEAN NOT NULL,
		FOREIGN KEY(user_login) REFERENCES users(login)
	);`

	_, err = db.Exec(createUsers)
	if err != nil {
		return err
	}

	_, err = db.Exec(createChallenges)
	return err
}

func AddUser(login, passwordHash, rsaE, rsaN, rsaD string) error {
	_, err := db.Exec("INSERT INTO users (login, password_hash, rsa_e, rsa_n, rsa_d) VALUES (?, ?, ?, ?, ?)",
		login, passwordHash, rsaE, rsaN, rsaD)
	return err
}

func UserExists(login string) bool {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE login = ?", login).Scan(&count)
	return err == nil && count > 0
}

func GetUser(login string) (string, string, string, string, error) {
	var passwordHash, rsaE, rsaN, rsaD string
	err := db.QueryRow("SELECT password_hash, rsa_e, rsa_n, rsa_d FROM users WHERE login = ?", login).
		Scan(&passwordHash, &rsaE, &rsaN, &rsaD)
	return passwordHash, rsaE, rsaN, rsaD, err
}

func CreateChallenge(challengeHash, userLogin string, expiresAt time.Time) error {
	_, err := db.Exec("UPDATE challenges SET is_active = 0 WHERE user_login = ? ", userLogin)
	if err != nil {
		return err
	}

	_, err = db.Exec("INSERT INTO challenges (challenge_hash, user_login, expires_at, is_active) VALUES (?, ?, ?, 1)",
		challengeHash, userLogin, expiresAt)
	return err
}

func GetActiveChallenge(userLogin string) (string, time.Time, error) {
	var challengeHash string
	var expiresAt time.Time

	err := db.QueryRow("SELECT challenge_hash, expires_at FROM challenges WHERE user_login = ?  AND is_active = 1",
		userLogin).Scan(&challengeHash, &expiresAt)

	return challengeHash, expiresAt, err
}

func DeactivateChallenge(userLogin string) error {
	_, err := db.Exec("UPDATE challenges SET is_active = 0 WHERE user_login = ?", userLogin)
	return err
}
