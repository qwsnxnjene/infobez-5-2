package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
)

type DHSession struct {
	// Параметры DH
	P           *big.Int // простое число
	G           *big.Int // примитивный элемент
	A           *big.Int // закрытый ключ a
	PublicA     *big.Int // открытый ключ A = g^a mod p
	PublicB     *big.Int // открытый ключ B от другой стороны
	SharedKey   *big.Int // общий ключ K
	RSAKey      *RSAPrivateKey
	Established bool
}

var (
	sessions      = make(map[string]*DHSession)
	sessionsMutex sync.Mutex
)

func CreateDHSession(login string) (*DHSession, error) {
	fmt.Println("\n--- Генерация параметров Диффи-Хелмана ---")

	fmt.Println("Генерация простого числа p (512 бит, Соловей-Штрассен)")
	p, err := GeneratePrimeSolovayStrassen(512)
	if err != nil {
		return nil, err
	}
	fmt.Println("p =", p.String()[:50]+"...")

	fmt.Println("Поиск примитивного элемента g")
	g, err := FindPrimitiveRoot(p)
	if err != nil {
		return nil, err
	}
	fmt.Println("g =", g.String())

	fmt.Println("Генерация закрытого ключа a")
	a, err := GenerateOddNumber(128)
	if err != nil {
		return nil, err
	}
	fmt.Println("a =", a.String()[:30]+"...")

	// A = g^a mod p
	fmt.Println("Вычисление открытого ключа A = g^a mod p")
	publicA := new(big.Int).Exp(g, a, p)
	fmt.Println("A =", publicA.String()[:50]+"...")

	fmt.Println("Генерация RSA ключей")
	rsaKey, err := GenerateRSAKey(1024)
	if err != nil {
		return nil, err
	}
	fmt.Println("RSA N =", rsaKey.PublicKey.N.String()[:50]+"...")
	fmt.Println("RSA E =", rsaKey.PublicKey.E.String())
	fmt.Println("RSA D =", rsaKey.D.String()[:50]+"...")

	session := &DHSession{
		P:           p,
		G:           g,
		A:           a,
		PublicA:     publicA,
		RSAKey:      rsaKey,
		Established: false,
	}

	sessionsMutex.Lock()
	sessions[login] = session
	sessionsMutex.Unlock()

	return session, nil
}

func GetDHSession(login string) *DHSession {
	sessionsMutex.Lock()
	defer sessionsMutex.Unlock()
	return sessions[login]
}

func HashDHParams(A, g, p *big.Int) string {
	data := A.String() + g.String() + p.String()
	h := sha1.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func SignDHParams(rsaKey *RSAPrivateKey, A, g, p *big.Int) *big.Int {
	hashStr := HashDHParams(A, g, p)
	hashBytes, _ := hex.DecodeString(hashStr)
	hashInt := BytesToBigInt(hashBytes)

	return RSASign(rsaKey, hashInt)
}

func VerifyDHParams(publicKey *RSAPublicKey, signature *big.Int, A, g, p *big.Int) bool {
	recoveredHashInt := RSAVerify(publicKey, signature)

	expectedHashStr := HashDHParams(A, g, p)
	expectedHashBytes, _ := hex.DecodeString(expectedHashStr)
	expectedHashInt := BytesToBigInt(expectedHashBytes)

	return recoveredHashInt.Cmp(expectedHashInt) == 0
}

func (session *DHSession) ComputeSharedKeyK1(publicB *big.Int) {
	// K = B^a mod p
	session.SharedKey = new(big.Int).Exp(publicB, session.A, session.P)
	session.PublicB = publicB
	session.Established = true
}

func ComputeSharedKeyK2(publicA *big.Int, b *big.Int, p *big.Int) *big.Int {
	// K = A^b mod p
	return new(big.Int).Exp(publicA, b, p)
}

func SharedKeyToRC4Key(sharedKey *big.Int) []byte {
	h := sha1.New()
	h.Write(sharedKey.Bytes())
	return h.Sum(nil)[:16]
}
