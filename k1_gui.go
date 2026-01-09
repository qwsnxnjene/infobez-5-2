package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"fyne.io/fyne/v2"
	"net/http"
	"strings"
	"time"

	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

var (
	k1LogWidget  *widget.Entry
	k1ChatWidget *widget.Entry
	k1UserLabel  *widget.Label
)

func k1AddLog(message string) {
	timestamp := time.Now().Format("15:04:05")
	k1LogWidget.SetText(k1LogWidget.Text + fmt.Sprintf("[%s] %s\n", timestamp, message))
}

func k1AddChat(message string) {
	timestamp := time.Now().Format("15:04:05")
	k1ChatWidget.SetText(k1ChatWidget.Text + fmt.Sprintf("[%s] %s\n", timestamp, message))
}

func k1HandleRegisterGUI(loginEntry, passwordEntry *widget.Entry, statusLabel *widget.Label) {
	login := strings.TrimSpace(loginEntry.Text)
	password := strings.TrimSpace(passwordEntry.Text)

	if login == "" || password == "" {
		statusLabel.SetText("Заполните все поля")
		k1AddLog("Ошибка: пустые поля")
		return
	}

	if UserExists(login) {
		statusLabel.SetText("Пользователь уже существует")
		k1AddLog(fmt.Sprintf("Ошибка: %s уже существует", login))
		return
	}

	k1AddLog("========================================")
	k1AddLog(fmt.Sprintf("Регистрация: %s", login))

	passwordHash := hashSHA1(password)
	k1AddLog(fmt.Sprintf("Хэш пароля: %s", passwordHash[:20]+"..."))

	e, n, d, err := generateSimpleRSA()
	if err != nil {
		statusLabel.SetText("Ошибка RSA")
		k1AddLog(fmt.Sprintf("Ошибка:  %v", err))
		return
	}

	k1AddLog(fmt.Sprintf("RSA:  e=%s", e))

	err = AddUser(login, passwordHash, e, n, d)
	if err != nil {
		statusLabel.SetText("Ошибка БД")
		k1AddLog(fmt.Sprintf("Ошибка: %v", err))
		return
	}

	statusLabel.SetText("Зарегистрирован!")
	k1AddLog(fmt.Sprintf("Успех: %s зарегистрирован", login))

	loginEntry.SetText("")
	passwordEntry.SetText("")
}

func k1SendMessage(messageEntry *widget.Entry, statusLabel *widget.Label, userLabel *widget.Label) {
	currentUser := strings.TrimPrefix(userLabel.Text, "Текущий пользователь: ")

	if currentUser == "не выбран" || currentUser == "" {
		statusLabel.SetText("Выберите пользователя")
		return
	}

	message := strings.TrimSpace(messageEntry.Text)
	if message == "" {
		statusLabel.SetText("Введите сообщение")
		return
	}

	session := GetDHSession(currentUser)
	if session == nil || !session.Established {
		statusLabel.SetText("Сессия не установлена")
		k1AddChat("Ошибка: защищенное соединение не установлено")
		return
	}

	rc4Key := SharedKeyToRC4Key(session.SharedKey)
	encryptedBytes := RC4Encrypt(rc4Key, message)
	encryptedHex := hex.EncodeToString(encryptedBytes)

	k1AddChat("K1 -> K2")
	k1AddChat(fmt.Sprintf("Исходное:  %s", message))
	k1AddChat(fmt.Sprintf("Зашифр: %s", encryptedHex[:min(40, len(encryptedHex))]+"..."))

	statusLabel.SetText("Отправлено")
	messageEntry.SetText("")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func k1MainGUI() {
	err := InitDB()
	if err != nil {
		panic(err)
	}

	myApp := app.New()
	myWindow := myApp.NewWindow("K1 - Сервер")
	myWindow.Resize(fyne.NewSize(850, 650))

	loginEntry := widget.NewEntry()
	loginEntry.SetPlaceHolder("Логин")

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Пароль")

	regStatus := widget.NewLabel("Готов к регистрации")

	registerBtn := widget.NewButton("Зарегистрировать", func() {
		k1HandleRegisterGUI(loginEntry, passwordEntry, regStatus)
	})

	regTab := container.NewVBox(
		widget.NewLabelWithStyle("Регистрация пользователя", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Логин:"),
		loginEntry,
		widget.NewLabel("Пароль:"),
		passwordEntry,
		registerBtn,
		regStatus,
	)

	k1UserLabel = widget.NewLabel("Текущий пользователь: не выбран")

	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("Введите логин пользователя")

	selectUserBtn := widget.NewButton("Выбрать пользователя", func() {
		user := strings.TrimSpace(userEntry.Text)
		if user != "" {
			k1UserLabel.SetText("Текущий пользователь: " + user)
			k1AddChat(fmt.Sprintf("Выбран пользователь: %s", user))
		}
	})

	messageEntry := widget.NewEntry()
	messageEntry.SetPlaceHolder("Введите сообщение для K2")

	chatStatus := widget.NewLabel("Ожидание установки соединения")

	sendBtn := widget.NewButton("Отправить K2", func() {
		k1SendMessage(messageEntry, chatStatus, k1UserLabel)
	})

	k1ChatWidget = widget.NewMultiLineEntry()
	k1ChatWidget.SetPlaceHolder("История чата...")
	k1ChatWidget.Disable()

	chatScroll := container.NewScroll(k1ChatWidget)
	chatScroll.SetMinSize(fyne.NewSize(810, 200))

	chatTab := container.NewVBox(
		widget.NewLabelWithStyle("Защищенный чат (RC4)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		k1UserLabel,
		widget.NewLabel("Выберите пользователя:"),
		userEntry,
		selectUserBtn,
		widget.NewSeparator(),
		widget.NewLabel("Сообщение: "),
		messageEntry,
		sendBtn,
		chatStatus,
		widget.NewSeparator(),
		widget.NewLabel("История: "),
		chatScroll,
	)

	k1LogWidget = widget.NewMultiLineEntry()
	k1LogWidget.SetPlaceHolder("Логи сервера...")
	k1LogWidget.Disable()

	logScroll := container.NewScroll(k1LogWidget)
	logScroll.SetMinSize(fyne.NewSize(810, 200))

	go func() {
		http.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
			k1AddLog("========================================")
			k1AddLog("📥 /challenge от K2")
			challengeHandler(w, r)
		})

		http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
			k1AddLog("========================================")
			k1AddLog("📥 /verify от K2")
			verifyHandler(w, r)
		})

		http.HandleFunc("/dh/init", func(w http.ResponseWriter, r *http.Request) {
			k1AddLog("========================================")
			k1AddLog("📥 /dh/init - Диффи-Хелман")
			dhInitHandler(w, r)
		})

		http.HandleFunc("/dh/exchange", func(w http.ResponseWriter, r *http.Request) {
			k1AddLog("========================================")
			k1AddLog("📥 /dh/exchange - обмен ключами")
			dhExchangeHandler(w, r)
		})

		http.HandleFunc("/chat/receive", func(w http.ResponseWriter, r *http.Request) {
			chatReceiveHandlerGUI(w, r)
		})

		k1AddLog("HTTP сервер запущен на : 8080")
		k1AddLog("Поддержка:")
		k1AddLog("  • Аутентификация (challenge-response)")
		k1AddLog("  • Диффи-Хелман + ЭЦП")
		k1AddLog("  • Защищенный чат (RC4)")
		http.ListenAndServe(":8080", nil)
	}()

	tabs := container.NewAppTabs(
		container.NewTabItem("1. Регистрация", regTab),
		container.NewTabItem("2. Чат", chatTab),
	)

	logContainer := container.NewVBox(
		widget.NewLabelWithStyle("Логи сервера", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		logScroll,
	)

	content := container.NewVSplit(tabs, logContainer)
	content.SetOffset(0.55)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}

func chatReceiveHandlerGUI(w http.ResponseWriter, r *http.Request) {
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

	k1AddChat("========================================")
	k1AddChat("K2 → K1")
	k1AddChat(fmt.Sprintf("Зашифр: %s", req.EncryptedMsg[:min(40, len(req.EncryptedMsg))]+"..."))
	k1AddChat(fmt.Sprintf("Расшифр: %s", decryptedMsg))

	response := struct {
		Success bool `json:"success"`
	}{
		Success: true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
