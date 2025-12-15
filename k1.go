package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

func hashSHA1(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func generateChallenge() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateSimpleRSA() (e, n, d string, err error) {
	p, err := GeneratePrimeMillerRabin(64)
	if err != nil {
		return "", "", "", err
	}

	q, err := GeneratePrimeMillerRabin(64)
	if err != nil {
		return "", "", "", err
	}

	for p.Cmp(q) == 0 {
		q, err = GeneratePrimeMillerRabin(64)
		if err != nil {
			return "", "", "", err
		}
	}

	nBig := new(big.Int).Mul(p, q)

	p1 := new(big.Int).Sub(p, big.NewInt(1))
	q1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(p1, q1)

	eBig := big.NewInt(17)

	gcd := new(big.Int).GCD(nil, nil, eBig, phi)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		eBig = big.NewInt(65537)
	}

	dBig := ModInverse(eBig, phi)

	return eBig.String(), nBig.String(), dBig.String(), nil
}

func handleRegister() {
	fmt.Println("\n=== РЕГИСТРАЦИЯ ===")

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Логин: ")
	login, _ := reader.ReadString('\n')
	login = strings.TrimSpace(login)

	fmt.Print("Пароль:  ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if login == "" || password == "" {
		fmt.Println("Ошибка: заполните все поля")
		return
	}

	if UserExists(login) {
		fmt.Println("Ошибка: пользователь уже существует")
		return
	}

	fmt.Println("--- Хэширование пароля ---")
	fmt.Println("Пароль:", password)
	passwordHash := hashSHA1(password)
	fmt.Println("Хэш пароля:", passwordHash)

	fmt.Println("--- Генерация уникальных RSA параметров ---")
	e, n, d, err := generateSimpleRSA()
	if err != nil {
		fmt.Println("Ошибка генерации RSA:", err)
		return
	}
	fmt.Println("e =", e)
	fmt.Println("n =", n)
	fmt.Println("d =", d)

	fmt.Println("--- Сохранение в БД ---")
	err = AddUser(login, passwordHash, e, n, d)
	if err != nil {
		fmt.Println("Ошибка:", err)
		return
	}

	fmt.Println("Пользователь зарегистрирован:", login)
}

func challengeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("\n========================================")
	fmt.Println("K1: Получен запрос от K2")
	fmt.Println("========================================")

	var req struct {
		Login string `json:"login"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		fmt.Println("Ошибка:", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Логин:", req.Login)

	fmt.Println("--- Проверка пользователя ---")
	if !UserExists(req.Login) {
		fmt.Println("Пользователь не найден")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	fmt.Println("Пользователь найден")

	fmt.Println("--- Генерация слова-вызова ---")
	challenge, err := generateChallenge()
	if err != nil {
		fmt.Println("Ошибка:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("Слово-вызов:", challenge)

	fmt.Println("--- Хэширование слова-вызова ---")
	challengeHash := hashSHA1(challenge)
	fmt.Println("Хэш слова-вызова:", challengeHash)

	fmt.Println("--- Установка срока годности ---")
	expiresAt := time.Now().Add(20 * time.Second)
	fmt.Println("Истекает в:", expiresAt.Format("15:04:05"))

	fmt.Println("--- Сохранение в БД ---")
	err = CreateChallenge(challengeHash, req.Login, expiresAt)
	if err != nil {
		fmt.Println("Ошибка:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("K1:  Отправляем хэш слова-вызова K2")

	response := struct {
		ChallengeHash string `json:"challenge_hash"`
	}{
		ChallengeHash: challengeHash,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HTTP обработчик для верификации
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("\n========================================")
	fmt.Println("K1: Получен супер-хэш от K2")
	fmt.Println("========================================")

	var req struct {
		Login    string `json:"login"`
		SuperKey string `json:"super_key"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		fmt.Println("Ошибка:", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Логин:", req.Login)
	fmt.Println("Супер-хэш S2 от K2:", req.SuperKey)

	fmt.Println("--- Получение слова-вызова из БД ---")
	challengeHash, expiresAt, err := GetActiveChallenge(req.Login)
	if err != nil {
		fmt.Println("Нет активного слова-вызова")
		http.Error(w, "No active challenge", http.StatusNotFound)
		return
	}
	fmt.Println("Хэш слова-вызова:", challengeHash)
	fmt.Println("Истекает в:", expiresAt.Format("15:04:05"))

	fmt.Println("--- Проверка срока годности ---")
	if time.Now().After(expiresAt) {
		fmt.Println("Срок истек!  Генерируем новое слово-вызов")
		DeactivateChallenge(req.Login)

		challenge, _ := generateChallenge()
		challengeHash = hashSHA1(challenge)
		newExpiresAt := time.Now().Add(20 * time.Second)
		CreateChallenge(challengeHash, req.Login, newExpiresAt)

		http.Error(w, "Challenge expired", http.StatusUnauthorized)
		return
	}
	fmt.Println("Срок в порядке")

	fmt.Println("--- Получение хэша пароля из БД ---")
	passwordHash, _, _, _, err := GetUser(req.Login)
	if err != nil {
		fmt.Println("Ошибка:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println("Хэш пароля:", passwordHash)

	fmt.Println("--- Формирование супер-хэша S1 ---")
	fmt.Println("Склеиваем: хэш пароля + хэш слова-вызова")
	concatenated := passwordHash + challengeHash
	s1 := hashSHA1(concatenated)
	fmt.Println("Супер-хэш S1:", s1)

	fmt.Println("--- Сравнение ---")
	fmt.Println("S1 (K1):", s1)
	fmt.Println("S2 (K2):", req.SuperKey)

	response := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: s1 == req.SuperKey,
	}

	if response.Success {
		fmt.Println(">>> СОВПАДАЮТ! Аутентификация успешна")
		response.Message = "Аутентификация успешна"
		DeactivateChallenge(req.Login)
	} else {
		fmt.Println(">>> НЕ СОВПАДАЮТ! Аутентификация провалена")
		response.Message = "Неверный пароль"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func dhInitHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("\n========================================")
	fmt.Println("K1: Запрос на инициализацию Диффи-Хелмана")
	fmt.Println("========================================")

	var req struct {
		Login string `json:"login"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Для пользователя:", req.Login)

	session, err := CreateDHSession(req.Login)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h1 := HashDHParams(session.PublicA, session.G, session.P)
	fmt.Println("--- Вычисление H1 ---")
	fmt.Println("H1 = sha1(A, g, p) =", h1)

	fmt.Println("--- Подпись параметров ---")
	signature := SignDHParams(session.RSAKey, session.PublicA, session.G, session.P)
	fmt.Println("F (подпись) =", signature.String()[:50]+"...")

	fmt.Println("--- Отправка параметров K2 ---")

	response := struct {
		A         string `json:"a"`
		G         string `json:"g"`
		P         string `json:"p"`
		H1        string `json:"h1"`
		Signature string `json:"signature"`
		RSA_N     string `json:"rsa_n"`
		RSA_E     string `json:"rsa_e"`
	}{
		A:         session.PublicA.String(),
		G:         session.G.String(),
		P:         session.P.String(),
		H1:        h1,
		Signature: signature.String(),
		RSA_N:     session.RSAKey.PublicKey.N.String(),
		RSA_E:     session.RSAKey.PublicKey.E.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func dhExchangeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("\n========================================")
	fmt.Println("K1:  Получен открытый ключ B от K2")
	fmt.Println("========================================")

	var req struct {
		Login    string `json:"login"`
		B        string `json:"b"`
		M        string `json:"m"`        // sha1(B)
		U        string `json:"u"`        // подпись от K2
		K2_RSA_N string `json:"k2_rsa_n"` // Открытый ключ K2
		K2_RSA_E string `json:"k2_rsa_e"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Println("Пользователь:", req.Login)

	session := GetDHSession(req.Login)
	if session == nil {
		http.Error(w, "No DH session", http.StatusNotFound)
		return
	}

	fmt.Println("--- Проверка ЭЦП от K2 ---")

	k2RSA_N := new(big.Int)
	k2RSA_N.SetString(req.K2_RSA_N, 10)
	k2RSA_E := new(big.Int)
	k2RSA_E.SetString(req.K2_RSA_E, 10)
	k2PublicKey := &RSAPublicKey{N: k2RSA_N, E: k2RSA_E}

	fmt.Println("K2 RSA N =", k2RSA_N.String()[:50]+"...")
	fmt.Println("K2 RSA E =", k2RSA_E.String())

	uBig := new(big.Int)
	uBig.SetString(req.U, 10)
	recoveredHashInt := RSAVerify(k2PublicKey, uBig)
	fmt.Println("Восстановленный хэш из подписи:", hex.EncodeToString(recoveredHashInt.Bytes()))

	publicB := new(big.Int)
	publicB.SetString(req.B, 10)
	h := sha1.New()
	h.Write(publicB.Bytes())
	expectedHashInt := BytesToBigInt(h.Sum(nil))
	expectedHashHex := hex.EncodeToString(h.Sum(nil))

	fmt.Println("Вычисленный хэш от B:", expectedHashHex)
	fmt.Println("Полученный M:", req.M)

	if recoveredHashInt.Cmp(expectedHashInt) != 0 {
		fmt.Println(">>> ЭЦП НЕ ВЕРНА!  Подпись не соответствует данным!")
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	if expectedHashHex != req.M {
		fmt.Println(">>> ХЭШИ НЕ СОВПАДАЮТ!  Подделка данных!")
		http.Error(w, "Invalid hash", http.StatusUnauthorized)
		return
	}

	fmt.Println(">>> ЭЦП ВЕРНА! ЭЦП установлена")

	fmt.Println("\n--- Вычисление общего ключа ---")

	session.ComputeSharedKeyK1(publicB)
	fmt.Println("Общий ключ K =", session.SharedKey.String()[:50]+"...")

	rc4Key := SharedKeyToRC4Key(session.SharedKey)
	fmt.Println("Ключ RC4 (16 байт) =", hex.EncodeToString(rc4Key))

	response := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: true,
		Message: "ЭЦП установлена, общий ключ вычислен",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func chatReceiveHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login        string `json:"login"`
		EncryptedMsg string `json:"encrypted_msg"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	session := GetDHSession(req.Login)
	if session == nil || !session.Established {
		http.Error(w, "No established session", http.StatusNotFound)
		return
	}

	rc4Key := SharedKeyToRC4Key(session.SharedKey)
	encryptedBytes, _ := hex.DecodeString(req.EncryptedMsg)
	decryptedMsg := RC4Decrypt(rc4Key, encryptedBytes)

	fmt.Println("\n========================================")
	fmt.Println("K1: Получено сообщение от K2")
	fmt.Println("========================================")
	fmt.Println("Зашифрованное:", req.EncryptedMsg)
	fmt.Println("Расшифрованное:", decryptedMsg)

	response := struct {
		Success bool `json:"success"`
	}{
		Success: true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func sendMessageToK2(login, message string) {
	session := GetDHSession(login)
	if session == nil || !session.Established {
		fmt.Println("Ошибка: сессия не установлена")
		return
	}

	rc4Key := SharedKeyToRC4Key(session.SharedKey)
	encryptedBytes := RC4Encrypt(rc4Key, message)
	encryptedHex := hex.EncodeToString(encryptedBytes)

	fmt.Println("\n--- Отправка сообщения K2 ---")
	fmt.Println("Исходное:", message)
	fmt.Println("Зашифрованное:", encryptedHex)

	msgBody, _ := json.Marshal(map[string]string{
		"login":         login,
		"encrypted_msg": encryptedHex,
	})

	resp, err := http.Post("http://localhost:8081/chat/receive", "application/json", bytes.NewBuffer(msgBody))
	if err != nil {
		fmt.Println("Ошибка отправки:", err)
		fmt.Println("Убедитесь что K2 запущен!")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println(">>> Сообщение отправлено!")
	} else {
		fmt.Println(">>> Ошибка отправки сообщения")
	}
}

func main() {
	err := InitDB()
	if err != nil {
		panic(err)
	}

	fmt.Println("=== K1 ===")
	fmt.Println("База данных инициализирована")

	go func() {
		http.HandleFunc("/challenge", challengeHandler)
		http.HandleFunc("/verify", verifyHandler)
		http.HandleFunc("/dh/init", dhInitHandler)
		http.HandleFunc("/dh/exchange", dhExchangeHandler)
		http.HandleFunc("/chat/receive", chatReceiveHandler)
		//fmt.Println("HTTP сервер запущен на порту 8080")
		http.ListenAndServe(":8080", nil)
	}()

	reader := bufio.NewReader(os.Stdin)
	var currentLogin string

	for {
		fmt.Println("\n--- МЕНЮ ---")
		fmt.Println("1. Зарегистрировать пользователя")
		fmt.Println("2. Отправить сообщение K2")
		fmt.Println("3. Выход")
		fmt.Print("Выбор: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			handleRegister()
		case "2":
			if currentLogin == "" {
				fmt.Print("Введите логин пользователя: ")
				currentLogin, _ = reader.ReadString('\n')
				currentLogin = strings.TrimSpace(currentLogin)
			}
			fmt.Print("Сообщение:  ")
			msg, _ := reader.ReadString('\n')
			msg = strings.TrimSpace(msg)
			sendMessageToK2(currentLogin, msg)
		case "3":
			fmt.Println("Выход")
			return
		default:
			fmt.Println("Неверный выбор")
		}
	}
}
