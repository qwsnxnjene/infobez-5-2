package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
)

type K2DHSession struct {
	PublicA *big.Int
	G       *big.Int
	P       *big.Int

	B       *big.Int
	PublicB *big.Int

	RSAKey *RSAPrivateKey

	SharedKey *big.Int

	Established bool
}

var k2Session *K2DHSession

func hashSHA1(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
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

	if k2Session == nil || !k2Session.Established {
		http.Error(w, "No established session", http.StatusNotFound)
		return
	}

	rc4Key := SharedKeyToRC4Key(k2Session.SharedKey)
	encryptedBytes, _ := hex.DecodeString(req.EncryptedMsg)
	decryptedMsg := RC4Decrypt(rc4Key, encryptedBytes)

	fmt.Println("\n========================================")
	fmt.Println("K2: Получено сообщение от K1")
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

func handleAuth() (string, bool) {
	fmt.Println("\n=== АУТЕНТИФИКАЦИЯ ===")

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Логин: ")
	login, _ := reader.ReadString('\n')
	login = strings.TrimSpace(login)

	fmt.Print("Пароль: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if login == "" || password == "" {
		fmt.Println("Ошибка: заполните все поля")
		return "", false
	}

	fmt.Println("--- Хэширование пароля ---")
	passwordHash := hashSHA1(password)
	fmt.Println("Хэш пароля:", passwordHash)

	fmt.Println("--- K2:  Отправка запроса на K1 ---")

	reqBody, _ := json.Marshal(map[string]string{"login": login})
	resp, err := http.Post("http://localhost:8080/challenge", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		fmt.Println("Ошибка подключения к K1:", err)
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Пользователь не найден на сервере")
		return "", false
	}

	var challengeResp struct {
		ChallengeHash string `json:"challenge_hash"`
	}
	json.NewDecoder(resp.Body).Decode(&challengeResp)

	fmt.Println("Получен хэш слова-вызова:", challengeResp.ChallengeHash)

	fmt.Println("--- Формирование супер-хэша S2 ---")
	concatenated := passwordHash + challengeResp.ChallengeHash
	s2 := hashSHA1(concatenated)
	fmt.Println("Супер-хэш S2:", s2)

	fmt.Println("--- K2: Отправка супер-хэша S2 на K1 ---")

	verifyBody, _ := json.Marshal(map[string]string{
		"login":     login,
		"super_key": s2,
	})
	verifyResp, err := http.Post("http://localhost:8080/verify", "application/json", bytes.NewBuffer(verifyBody))
	if err != nil {
		fmt.Println("Ошибка:", err)
		return "", false
	}
	defer verifyResp.Body.Close()

	fmt.Println("--- Результат ---")

	if verifyResp.StatusCode == http.StatusUnauthorized {
		bodyBytes, _ := io.ReadAll(verifyResp.Body)
		fmt.Println(">>> ОШИБКА: Срок годности слова-вызова истек!")
		fmt.Println("Детали:", string(bodyBytes))
		return "", false
	}

	if verifyResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(verifyResp.Body)
		fmt.Println(">>> ОШИБКА:", string(bodyBytes))
		return "", false
	}

	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	json.NewDecoder(verifyResp.Body).Decode(&result)

	if result.Success {
		fmt.Println(">>> УСПЕХ:", result.Message)
		return login, true
	} else {
		fmt.Println(">>> ОШИБКА:", result.Message)
		return "", false
	}
}

func initDiffieHellman(login string) bool {
	fmt.Println("\n========================================")
	fmt.Println("K2: Инициализация Диффи-Хелмана")
	fmt.Println("========================================")

	fmt.Println("--- Запрос параметров DH от K1 ---")
	reqBody, _ := json.Marshal(map[string]string{"login": login})
	resp, err := http.Post("http://localhost:8080/dh/init", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		fmt.Println("Ошибка:", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Ошибка получения параметров DH")
		return false
	}

	var dhResp struct {
		A         string `json:"a"`
		G         string `json:"g"`
		P         string `json:"p"`
		H1        string `json:"h1"`
		Signature string `json:"signature"`
		RSA_N     string `json:"rsa_n"`
		RSA_E     string `json:"rsa_e"`
	}
	json.NewDecoder(resp.Body).Decode(&dhResp)

	fmt.Println("--- Получены параметры ---")
	fmt.Println("A =", dhResp.A[:50]+"...")
	fmt.Println("g =", dhResp.G)
	fmt.Println("p =", dhResp.P[:50]+"...")
	fmt.Println("H1 =", dhResp.H1)
	fmt.Println("F (подпись) =", dhResp.Signature[:50]+"...")
	fmt.Println("RSA N =", dhResp.RSA_N[:50]+"...")
	fmt.Println("RSA E =", dhResp.RSA_E)

	// Преобразуем строки в big.Int
	publicA := new(big.Int)
	publicA.SetString(dhResp.A, 10)

	g := new(big.Int)
	g.SetString(dhResp.G, 10)

	p := new(big.Int)
	p.SetString(dhResp.P, 10)

	signature := new(big.Int)
	signature.SetString(dhResp.Signature, 10)

	rsaN := new(big.Int)
	rsaN.SetString(dhResp.RSA_N, 10)

	rsaE := new(big.Int)
	rsaE.SetString(dhResp.RSA_E, 10)

	fmt.Println("--- Проверка ЭЦП от K1 ---")
	publicKey := &RSAPublicKey{N: rsaN, E: rsaE}

	valid := VerifyDHParams(publicKey, signature, publicA, g, p)

	if !valid {
		fmt.Println(">>> ЭЦП НЕ ВЕРНА!  Возможна подмена данных!")
		return false
	}

	h2 := HashDHParams(publicA, g, p)
	fmt.Println("Полученный H1:", dhResp.H1)
	fmt.Println("Вычисленный H2:", h2)

	if h2 != dhResp.H1 {
		fmt.Println(">>> ХЭШИ НЕ СОВПАДАЮТ! Подмена данных!")
		return false
	}

	fmt.Println(">>> H1 == H2!  Подмены данных нет")
	fmt.Println(">>> ЭЦП ВЕРНА!")

	fmt.Println("\n--- Генерация закрытого ключа b ---")
	b, err := GenerateOddNumber(128)
	if err != nil {
		fmt.Println("Ошибка генерации b:", err)
		return false
	}
	fmt.Println("b =", b.String()[:30]+"...")

	// B = g^b mod p
	fmt.Println("\n--- Вычисление открытого ключа B ---")
	publicB := new(big.Int).Exp(g, b, p)
	fmt.Println("B = g^b mod p =", publicB.String()[:50]+"...")

	// K = A^b mod p
	fmt.Println("\n--- Вычисление общего ключа ---")
	sharedKey := ComputeSharedKeyK2(publicA, b, p)
	fmt.Println("K = A^b mod p =", sharedKey.String()[:50]+"...")

	rc4Key := SharedKeyToRC4Key(sharedKey)
	fmt.Println("Ключ RC4 (16 байт) =", hex.EncodeToString(rc4Key))

	fmt.Println("\n--- Генерация RSA ключей K2 (1024 бит, Миллер-Рабин) ---")
	k2RSAKey, err := GenerateRSAKey(1024)
	if err != nil {
		fmt.Println("Ошибка генерации RSA:", err)
		return false
	}
	fmt.Println("K2 RSA N =", k2RSAKey.PublicKey.N.String()[:50]+"...")
	fmt.Println("K2 RSA E =", k2RSAKey.PublicKey.E.String())
	fmt.Println("K2 RSA D =", k2RSAKey.D.String()[:50]+"...")

	k2Session = &K2DHSession{
		PublicA:     publicA,
		G:           g,
		P:           p,
		B:           b,
		PublicB:     publicB,
		RSAKey:      k2RSAKey,
		SharedKey:   sharedKey,
		Established: false,
	}

	fmt.Println("\n--- Отправка B на K1 ---")

	hM := sha1.New()
	hM.Write(publicB.Bytes())
	m := hex.EncodeToString(hM.Sum(nil))
	fmt.Println("M = sha1(B) =", m)

	// U = RSAd(sha1(B))
	fmt.Println("\n--- Подпись B закрытым ключом K2 ---")
	bHashInt := BytesToBigInt(hM.Sum(nil))
	u := RSASign(k2RSAKey, bHashInt)
	fmt.Println("U = RSAd(sha1(B)) =", u.String()[:50]+"...")

	exchangeBody, _ := json.Marshal(map[string]string{
		"login":    login,
		"b":        publicB.String(),
		"m":        m,
		"u":        u.String(),
		"k2_rsa_n": k2RSAKey.PublicKey.N.String(),
		"k2_rsa_e": k2RSAKey.PublicKey.E.String(),
	})

	exchangeResp, err := http.Post("http://localhost:8080/dh/exchange", "application/json", bytes.NewBuffer(exchangeBody))
	if err != nil {
		fmt.Println("Ошибка отправки B:", err)
		return false
	}
	defer exchangeResp.Body.Close()

	if exchangeResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(exchangeResp.Body)
		fmt.Println("Ошибка обмена ключами:", string(bodyBytes))
		return false
	}

	var exchangeResult struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	json.NewDecoder(exchangeResp.Body).Decode(&exchangeResult)

	if exchangeResult.Success {
		fmt.Println("\n>>> УСПЕХ:", exchangeResult.Message)
		k2Session.Established = true
		return true
	}

	fmt.Println(">>> ОШИБКА:", exchangeResult.Message)
	return false
}

func sendMessageToK1(login, message string) {
	if k2Session == nil || !k2Session.Established {
		fmt.Println("Ошибка: сессия не установлена")
		return
	}

	rc4Key := SharedKeyToRC4Key(k2Session.SharedKey)
	encryptedBytes := RC4Encrypt(rc4Key, message)
	encryptedHex := hex.EncodeToString(encryptedBytes)

	fmt.Println("\n--- Отправка сообщения K1 ---")
	fmt.Println("Исходное:", message)
	fmt.Println("Зашифрованное:", encryptedHex)

	msgBody, _ := json.Marshal(map[string]string{
		"login":         login,
		"encrypted_msg": encryptedHex,
	})

	resp, err := http.Post("http://localhost:8080/chat/receive", "application/json", bytes.NewBuffer(msgBody))
	if err != nil {
		fmt.Println("Ошибка отправки:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println(">>> Сообщение отправлено!")
	} else {
		fmt.Println(">>> Ошибка отправки сообщения")
	}
}

func showSessionInfo() {
	if k2Session == nil {
		fmt.Println("\nСессия не установлена")
		return
	}

	fmt.Println("\n=== ИНФОРМАЦИЯ О СЕССИИ K2 ===")
	fmt.Println("\n--- Параметры DH ---")
	fmt.Println("Закрытый ключ b:", k2Session.B.String()[:30]+"...")
	fmt.Println("Открытый ключ B:", k2Session.PublicB.String()[:50]+"...")
	fmt.Println("Примитивный элемент g:", k2Session.G.String())
	fmt.Println("Простое число p:", k2Session.P.String()[:50]+"...")
	fmt.Println("Открытый ключ A (от K1):", k2Session.PublicA.String()[:50]+"...")

	fmt.Println("\n--- RSA ключи K2 ---")
	fmt.Println("RSA N:", k2Session.RSAKey.PublicKey.N.String()[:50]+"...")
	fmt.Println("RSA E:", k2Session.RSAKey.PublicKey.E.String())
	fmt.Println("RSA D:", k2Session.RSAKey.D.String()[:50]+"...")

	if k2Session.Established {
		fmt.Println("\n--- Общий ключ ---")
		fmt.Println("K =", k2Session.SharedKey.String()[:50]+"...")
		rc4Key := SharedKeyToRC4Key(k2Session.SharedKey)
		fmt.Println("Ключ RC4:", hex.EncodeToString(rc4Key))
		fmt.Println("\nСтатус:  УСТАНОВЛЕНА")
	} else {
		fmt.Println("\nСтатус: В ПРОЦЕССЕ")
	}
}

func main() {
	fmt.Println("=== K2 ===")
	fmt.Println("Подключение к серверу:  http://localhost:8080")

	go func() {
		http.HandleFunc("/chat/receive", chatReceiveHandler)
		//fmt.Println("HTTP сервер K2 запущен на порту 8081")
		http.ListenAndServe(":8081", nil)
	}()

	reader := bufio.NewReader(os.Stdin)
	var currentLogin string
	authenticated := false

	for {
		fmt.Println("\n--- МЕНЮ ---")
		if !authenticated {
			fmt.Println("1. Войти")
		} else {
			fmt.Println("2. Установить защищенное соединение (Диффи-Хелман)")
			fmt.Println("3. Отправить сообщение K1")
			fmt.Println("4. Показать информацию о сессии")
		}
		fmt.Println("5. Выход")
		fmt.Print("Выбор: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			if !authenticated {
				login, success := handleAuth()
				if success {
					currentLogin = login
					authenticated = true
					fmt.Println("Теперь можно установить защищенное соединение!")
				}
			}
		case "2":
			if authenticated {
				success := initDiffieHellman(currentLogin)
				if success {
					fmt.Println("Защищенное соединение установлено! Можно отправлять сообщения.")
				}
			}
		case "3":
			if authenticated && k2Session != nil && k2Session.Established {
				fmt.Print("Сообщение: ")
				msg, _ := reader.ReadString('\n')
				msg = strings.TrimSpace(msg)
				sendMessageToK1(currentLogin, msg)
			} else {
				fmt.Println("Сначала установите защищенное соединение!")
			}
		case "4":
			showSessionInfo()
		case "5":
			fmt.Println("Выход")
			return
		default:
			fmt.Println("Неверный выбор")
		}
	}
}
