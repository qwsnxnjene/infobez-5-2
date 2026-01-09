package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fyne.io/fyne/v2"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

var (
	k2LogWidget  *widget.Entry
	k2ChatWidget *widget.Entry
	k2DHWidget   *widget.Entry
	k2Login      string
)

func k2AddLog(message string) {
	timestamp := time.Now().Format("15:04:05")
	if k2LogWidget == nil {
		fmt.Printf("[%s] %s\n", timestamp, message)
		return
	}
	k2LogWidget.SetText(k2LogWidget.Text + fmt.Sprintf("[%s] %s\n", timestamp, message))
}

func k2AddChat(message string) {
	timestamp := time.Now().Format("15:04:05")
	if k2ChatWidget == nil {
		fmt.Printf("CHAT [%s] %s\n", timestamp, message)
		return
	}
	k2ChatWidget.SetText(k2ChatWidget.Text + fmt.Sprintf("[%s] %s\n", timestamp, message))
}

func k2UpdateDH() {
	if k2DHWidget == nil {
		return
	}

	if k2Session == nil {
		k2DHWidget.SetText("Сессия не установлена")
		return
	}

	info := "=== ПАРАМЕТРЫ ДИФФИ-ХЕЛМАНА ===\n\n"
	if k2Session.B != nil {
		info += fmt.Sprintf("Закрытый ключ b: %s.. .\n", k2Session.B.String()[:min(30, len(k2Session.B.String()))])
	}
	if k2Session.PublicB != nil {
		info += fmt.Sprintf("Открытый ключ B: %s...\n", k2Session.PublicB.String()[:min(50, len(k2Session.PublicB.String()))])
	}
	if k2Session.G != nil {
		info += fmt.Sprintf("Примитивный элемент g: %s\n", k2Session.G.String())
	}
	if k2Session.P != nil {
		info += fmt.Sprintf("Простое число p: %s.. .\n", k2Session.P.String()[:min(50, len(k2Session.P.String()))])
	}
	if k2Session.PublicA != nil {
		info += fmt.Sprintf("Открытый ключ A (от K1): %s...\n", k2Session.PublicA.String()[:min(50, len(k2Session.PublicA.String()))])
	}

	if k2Session.RSAKey != nil {
		info += "\n=== RSA КЛЮЧИ K2 ===\n"
		info += fmt.Sprintf("N: %s.. .\n", k2Session.RSAKey.PublicKey.N.String()[:min(50, len(k2Session.RSAKey.PublicKey.N.String()))])
		info += fmt.Sprintf("E: %s\n", k2Session.RSAKey.PublicKey.E.String())
	}

	if k2Session.Established && k2Session.SharedKey != nil {
		info += "\n=== ОБЩИЙ КЛЮЧ ===\n"
		info += fmt.Sprintf("K: %s...\n", k2Session.SharedKey.String()[:min(50, len(k2Session.SharedKey.String()))])
		rc4Key := SharedKeyToRC4Key(k2Session.SharedKey)
		info += fmt.Sprintf("RC4 ключ: %s\n", hex.EncodeToString(rc4Key))
		info += "\nСтатус: установлена"
	} else {
		info += "\nСтатус: в процессе"
	}

	k2DHWidget.SetText(info)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func k2HandleAuth(loginEntry, passwordEntry *widget.Entry, statusLabel *widget.Label) {
	login := strings.TrimSpace(loginEntry.Text)
	password := strings.TrimSpace(passwordEntry.Text)

	if login == "" || password == "" {
		statusLabel.SetText("Заполните все поля")
		return
	}

	k2AddLog("========================================")
	k2AddLog("Аутентификация")
	k2AddLog(fmt.Sprintf("Логин: %s", login))

	passwordHash := hashSHA1(password)
	k2AddLog(fmt.Sprintf("Хэш пароля: %s", passwordHash[:20]+"..."))

	k2AddLog("Запрос challenge...")
	reqBody, _ := json.Marshal(map[string]string{"login": login})
	resp, err := http.Post("http://localhost:8080/challenge", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		statusLabel.SetText("Ошибка подключения")
		k2AddLog(fmt.Sprintf("Ошибка: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		statusLabel.SetText("Пользователь не найден")
		k2AddLog("Пользователь не найден")
		return
	}

	var challengeResp struct {
		ChallengeHash string `json:"challenge_hash"`
	}
	json.NewDecoder(resp.Body).Decode(&challengeResp)
	k2AddLog(fmt.Sprintf("Хэш слова-вызова: %s", challengeResp.ChallengeHash[:20]+"..."))

	k2AddLog("Формирование супер-хэша...")
	s2 := hashSHA1(passwordHash + challengeResp.ChallengeHash)
	k2AddLog(fmt.Sprintf("S2: %s", s2[:20]+"..."))

	k2AddLog("Отправка супер-хэша...")
	verifyBody, _ := json.Marshal(map[string]string{"login": login, "super_key": s2})
	verifyResp, err := http.Post("http://localhost:8080/verify", "application/json", bytes.NewBuffer(verifyBody))
	if err != nil {
		statusLabel.SetText("Ошибка")
		return
	}
	defer verifyResp.Body.Close()

	if verifyResp.StatusCode == http.StatusUnauthorized {
		statusLabel.SetText("Срок истек")
		k2AddLog("Срок годности истек")
		return
	}

	if verifyResp.StatusCode != http.StatusOK {
		statusLabel.SetText("Ошибка сервера")
		bodyBytes, _ := io.ReadAll(verifyResp.Body)
		k2AddLog(fmt.Sprintf("Ошибка: %s", string(bodyBytes)))
		return
	}

	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	json.NewDecoder(verifyResp.Body).Decode(&result)

	if result.Success {
		statusLabel.SetText("УСПЕХ!")
		k2AddLog("Аутентификация успешна")
		k2Login = login
	} else {
		statusLabel.SetText(result.Message)
		k2AddLog(result.Message)
	}
}

func k2EstablishDH(statusLabel *widget.Label) {
	if k2Login == "" {
		statusLabel.SetText("Сначала аутентифицируйтесь")
		return
	}

	k2AddLog("========================================")
	k2AddLog("Установка Диффи-Хелмана")

	success := initDiffieHellman(k2Login)

	if success {
		statusLabel.SetText("DH установлен!")
		k2AddLog("Защищенное соединение установлено")
	} else {
		statusLabel.SetText("Ошибка DH")
		k2AddLog("Ошибка установки DH")
	}

	k2UpdateDH()
}

func k2SendMessage(messageEntry *widget.Entry, statusLabel *widget.Label) {
	if k2Session == nil || !k2Session.Established {
		statusLabel.SetText("Соединение не установлено")
		return
	}

	message := strings.TrimSpace(messageEntry.Text)
	if message == "" {
		statusLabel.SetText("Введите сообщение")
		return
	}

	rc4Key := SharedKeyToRC4Key(k2Session.SharedKey)
	encryptedBytes := RC4Encrypt(rc4Key, message)
	encryptedHex := hex.EncodeToString(encryptedBytes)

	k2AddChat("K2 -> K1")
	k2AddChat(fmt.Sprintf("Исходное:  %s", message))
	k2AddChat(fmt.Sprintf("Зашифр: %s", encryptedHex[:min(40, len(encryptedHex))]+"..."))

	// Отправка
	msgBody, _ := json.Marshal(map[string]string{
		"login":         k2Login,
		"encrypted_msg": encryptedHex,
	})

	resp, err := http.Post("http://localhost:8080/chat/receive", "application/json", bytes.NewBuffer(msgBody))
	if err != nil {
		statusLabel.SetText("Ошибка отправки")
		k2AddChat(fmt.Sprintf("Ошибка: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		statusLabel.SetText("Отправлено")
		k2AddChat("Сообщение доставлено")
	} else {
		statusLabel.SetText("Ошибка")
	}

	messageEntry.SetText("")
}

func k2MainGUI() {
	myApp := app.New()
	myWindow := myApp.NewWindow("K2 - Клиент")
	myWindow.Resize(fyne.NewSize(850, 700))

	go func() {
		http.HandleFunc("/chat/receive", chatReceiveHandler)
		k2AddLog("HTTP сервер K2 запущен на :8081")
		k2AddLog("Ожидание сообщений от K1...")
		http.ListenAndServe(":8081", nil)
	}()

	loginEntry := widget.NewEntry()
	loginEntry.SetPlaceHolder("Логин")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Пароль")

	authStatus := widget.NewLabel("Готов к аутентификации")

	authBtn := widget.NewButton("Войти", func() {
		k2HandleAuth(loginEntry, passwordEntry, authStatus)
	})

	authTab := container.NewVBox(
		widget.NewLabelWithStyle("Аутентификация", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Логин:"),
		loginEntry,
		widget.NewLabel("Пароль:"),
		passwordEntry,
		authBtn,
		authStatus,
	)

	dhStatus := widget.NewLabel("Сначала аутентифицируйтесь")

	establishBtn := widget.NewButton("Установить защищенное соединение", func() {
		k2EstablishDH(dhStatus)
	})

	k2DHWidget = widget.NewMultiLineEntry()
	k2DHWidget.SetPlaceHolder("Параметры сессии...")
	k2DHWidget.Disable()

	dhScroll := container.NewScroll(k2DHWidget)
	dhScroll.SetMinSize(fyne.NewSize(810, 250))

	dhTab := container.NewVBox(
		widget.NewLabelWithStyle("Диффи-Хелман + ЭЦП", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		establishBtn,
		dhStatus,
		widget.NewSeparator(),
		widget.NewLabel("Параметры сессии:"),
		dhScroll,
	)

	messageEntry := widget.NewEntry()
	messageEntry.SetPlaceHolder("Введите сообщение")

	chatStatus := widget.NewLabel("Установите соединение")

	sendBtn := widget.NewButton("Отправить K1", func() {
		k2SendMessage(messageEntry, chatStatus)
	})

	k2ChatWidget = widget.NewMultiLineEntry()
	k2ChatWidget.SetPlaceHolder("История чата...")
	k2ChatWidget.Disable()

	chatScroll := container.NewScroll(k2ChatWidget)
	chatScroll.SetMinSize(fyne.NewSize(810, 200))

	chatTab := container.NewVBox(
		widget.NewLabelWithStyle("Защищенный чат (RC4)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Сообщение:"),
		messageEntry,
		sendBtn,
		chatStatus,
		widget.NewSeparator(),
		widget.NewLabel("История: "),
		chatScroll,
	)

	k2LogWidget = widget.NewMultiLineEntry()
	k2LogWidget.SetPlaceHolder("Логи клиента...")
	k2LogWidget.Disable()

	logScroll := container.NewScroll(k2LogWidget)
	logScroll.SetMinSize(fyne.NewSize(810, 150))

	k2AddLog("Клиент K2 запущен")
	k2AddLog("Подключение к K1: http://localhost:8080")

	tabs := container.NewAppTabs(
		container.NewTabItem("1. Аутентификация", authTab),
		container.NewTabItem("2. Диффи-Хелман", dhTab),
		container.NewTabItem("3. Чат", chatTab),
	)

	logContainer := container.NewVBox(
		widget.NewLabelWithStyle("Логи", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		logScroll,
	)

	content := container.NewVSplit(tabs, logContainer)
	content.SetOffset(0.7)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}
