package main

import (
	"bufio"
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"os"
	"strings"
)

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func openDB() (*sql.DB, error) {
	return sql.Open("sqlite3", "./auth.db")
}

func viewUsers(db *sql.DB) {
	fmt.Println("\n=== ТАБЛИЦА USERS ===")

	rows, err := db.Query("SELECT login, password_hash, rsa_e, rsa_n, rsa_d FROM users")
	if err != nil {
		fmt.Println("Ошибка:", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var login, passwordHash, rsaE, rsaN, rsaD string
		err := rows.Scan(&login, &passwordHash, &rsaE, &rsaN, &rsaD)
		if err != nil {
			fmt.Println("Ошибка чтения:", err)
			continue
		}

		count++
		fmt.Println("\n--- Пользователь", count, "---")
		fmt.Println("Логин:", login)
		fmt.Println("Хэш пароля:", passwordHash)
		fmt.Println("RSA e:", rsaE)
		fmt.Println("RSA n:", truncate(rsaN, 50))
		fmt.Println("RSA d:", truncate(rsaD, 50))
	}

	if count == 0 {
		fmt.Println("Нет пользователей")
	} else {
		fmt.Println("\nВсего пользователей:", count)
	}
}

func viewChallenges(db *sql.DB) {
	fmt.Println("\n=== ТАБЛИЦА CHALLENGES ===")

	rows, err := db.Query("SELECT challenge_hash, user_login, expires_at, is_active FROM challenges ORDER BY expires_at DESC")
	if err != nil {
		fmt.Println("Ошибка:", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var challengeHash, userLogin, expiresAt string
		var isActive bool
		err := rows.Scan(&challengeHash, &userLogin, &expiresAt, &isActive)
		if err != nil {
			fmt.Println("Ошибка чтения:", err)
			continue
		}

		count++
		fmt.Println("\n--- Слово-вызов", count, "---")
		fmt.Println("Хэш слова-вызова:", challengeHash)
		fmt.Println("Для пользователя:", userLogin)
		fmt.Println("Истекает в:", expiresAt)
		if isActive {
			fmt.Println("Статус: АКТИВЕН")
		} else {
			fmt.Println("Статус: ДЕАКТИВИРОВАН")
		}
	}

	if count == 0 {
		fmt.Println("Нет слов-вызовов")
	} else {
		fmt.Println("\nВсего слов-вызовов:", count)
	}
}

func viewActiveChallenges(db *sql.DB) {
	fmt.Println("\n=== АКТИВНЫЕ СЛОВА-ВЫЗОВЫ ===")

	rows, err := db.Query("SELECT challenge_hash, user_login, expires_at FROM challenges WHERE is_active = 1")
	if err != nil {
		fmt.Println("Ошибка:", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var challengeHash, userLogin, expiresAt string
		err := rows.Scan(&challengeHash, &userLogin, &expiresAt)
		if err != nil {
			fmt.Println("Ошибка чтения:", err)
			continue
		}

		count++
		fmt.Println("\n--- Активное слово-вызов", count, "---")
		fmt.Println("Хэш:", challengeHash)
		fmt.Println("Пользователь:", userLogin)
		fmt.Println("Истекает в:", expiresAt)
	}

	if count == 0 {
		fmt.Println("Нет активных слов-вызовов")
	} else {
		fmt.Println("\nВсего активных:", count)
	}
}

func searchUser(db *sql.DB) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nВведите логин для поиска:  ")
	login, _ := reader.ReadString('\n')
	login = strings.TrimSpace(login)

	fmt.Println("\n=== ПОИСК ПОЛЬЗОВАТЕЛЯ:", login, "===")

	var passwordHash, rsaE, rsaN, rsaD string
	err := db.QueryRow("SELECT password_hash, rsa_e, rsa_n, rsa_d FROM users WHERE login = ?", login).
		Scan(&passwordHash, &rsaE, &rsaN, &rsaD)

	if err == sql.ErrNoRows {
		fmt.Println("Пользователь не найден")
		return
	}
	if err != nil {
		fmt.Println("Ошибка:", err)
		return
	}

	fmt.Println("\nЛогин:", login)
	fmt.Println("Хэш пароля:", passwordHash)
	fmt.Println("RSA e:", rsaE)
	fmt.Println("RSA n:", truncate(rsaN, 50))
	fmt.Println("RSA d:", truncate(rsaD, 50))

	var challengeHash, expiresAt string
	err = db.QueryRow("SELECT challenge_hash, expires_at FROM challenges WHERE user_login = ? AND is_active = 1", login).
		Scan(&challengeHash, &expiresAt)

	if err == sql.ErrNoRows {
		fmt.Println("\nАктивных слов-вызовов нет")
	} else if err != nil {
		fmt.Println("\nОшибка при проверке слов-вызовов:", err)
	} else {
		fmt.Println("\n--- Активное слово-вызов ---")
		fmt.Println("Хэш:", challengeHash)
		fmt.Println("Истекает в:", expiresAt)
	}
}

func clearTables(db *sql.DB) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nВы уверены?  Это удалит ВСЕ данные! (yes/no): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)

	if confirm != "yes" {
		fmt.Println("Отменено")
		return
	}

	_, err := db.Exec("DELETE FROM challenges")
	if err != nil {
		fmt.Println("Ошибка при очистке challenges:", err)
		return
	}

	_, err = db.Exec("DELETE FROM users")
	if err != nil {
		fmt.Println("Ошибка при очистке users:", err)
		return
	}

	fmt.Println("Все таблицы очищены")
}

func showStats(db *sql.DB) {
	fmt.Println("\n=== СТАТИСТИКА БД ===")

	var userCount, challengeCount, activeCount int

	db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
	db.QueryRow("SELECT COUNT(*) FROM challenges").Scan(&challengeCount)
	db.QueryRow("SELECT COUNT(*) FROM challenges WHERE is_active = 1").Scan(&activeCount)

	fmt.Println("Пользователей:", userCount)
	fmt.Println("Всего слов-вызовов:", challengeCount)
	fmt.Println("Активных слов-вызовов:", activeCount)
}

func viewUserHistory(db *sql.DB) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nВведите логин:  ")
	login, _ := reader.ReadString('\n')
	login = strings.TrimSpace(login)

	fmt.Println("\n=== ИСТОРИЯ АУТЕНТИФИКАЦИЙ:", login, "===")

	rows, err := db.Query(`
		SELECT challenge_hash, expires_at, is_active 
		FROM challenges 
		WHERE user_login = ? 
		ORDER BY expires_at DESC
	`, login)

	if err != nil {
		fmt.Println("Ошибка:", err)
		return
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var challengeHash, expiresAt string
		var isActive bool
		rows.Scan(&challengeHash, &expiresAt, &isActive)

		count++
		status := "ИСПОЛЬЗОВАН"
		if isActive {
			status = "АКТИВЕН"
		}

		fmt.Printf("\n%d. %s | %s | %s\n", count, expiresAt, status, truncate(challengeHash, 40))
	}

	if count == 0 {
		fmt.Println("Нет истории аутентификаций")
	} else {
		fmt.Println("\nВсего попыток:", count)
	}
}

func deleteUser(db *sql.DB) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nВведите логин для удаления: ")
	login, _ := reader.ReadString('\n')
	login = strings.TrimSpace(login)

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE login = ?)", login).Scan(&exists)
	if err != nil || !exists {
		fmt.Println("Пользователь не найден")
		return
	}

	fmt.Print("Вы уверены? (yes/no): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)

	if confirm != "yes" {
		fmt.Println("Отменено")
		return
	}

	db.Exec("DELETE FROM challenges WHERE user_login = ?", login)

	_, err = db.Exec("DELETE FROM users WHERE login = ?", login)
	if err != nil {
		fmt.Println("Ошибка удаления:", err)
		return
	}

	fmt.Println("Пользователь", login, "удален")
}

func main() {
	db, err := openDB()
	if err != nil {
		fmt.Println("Ошибка открытия БД:", err)
		return
	}
	defer db.Close()

	fmt.Println("=== ПРОСМОТР БАЗЫ ДАННЫХ ===")
	fmt.Println("Файл:  ./auth.db")

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n--- МЕНЮ ---")
		fmt.Println("1. Показать всех пользователей")
		fmt.Println("2. Показать все слова-вызовы")
		fmt.Println("3. Показать только активные слова-вызовы")
		fmt.Println("4. Найти пользователя по логину")
		fmt.Println("5. Статистика")
		fmt.Println("6. История аутентификаций пользователя")
		fmt.Println("7. Удалить пользователя")
		fmt.Println("8. Очистить все таблицы")
		fmt.Println("9. Выход")
		fmt.Print("Выбор: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			viewUsers(db)
		case "2":
			viewChallenges(db)
		case "3":
			viewActiveChallenges(db)
		case "4":
			searchUser(db)
		case "5":
			showStats(db)
		case "6":
			viewUserHistory(db)
		case "7":
			deleteUser(db)
		case "8":
			clearTables(db)
		case "9":
			fmt.Println("Выход")
			return
		default:
			fmt.Println("Неверный выбор")
		}
	}
}
