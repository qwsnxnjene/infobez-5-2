package main

import (
	"crypto/rand"
	"math/big"
)

type RSAPublicKey struct {
	N *big.Int
	E *big.Int
}

type RSAPrivateKey struct {
	PublicKey RSAPublicKey
	D         *big.Int
	P         *big.Int // простое p
	Q         *big.Int // простое q
}

func GenerateRSAKey(bits int) (*RSAPrivateKey, error) {
	p, err := GeneratePrimeMillerRabin(bits / 2)
	if err != nil {
		return nil, err
	}

	q, err := GeneratePrimeMillerRabin(bits / 2)
	if err != nil {
		return nil, err
	}

	// n = p * q
	n := new(big.Int).Mul(p, q)

	// phi(n) = (p-1)(q-1)
	p1 := new(big.Int).Sub(p, big.NewInt(1))
	q1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(p1, q1)

	e := big.NewInt(65537)

	// d = e^(-1) mod phi(n)
	d := ModInverse(e, phi)
	if d == nil {
		e = big.NewInt(3)
		d = ModInverse(e, phi)
	}

	return &RSAPrivateKey{
		PublicKey: RSAPublicKey{N: n, E: e},
		D:         d,
		P:         p,
		Q:         q,
	}, nil
}

func RSAEncrypt(publicKey *RSAPublicKey, message *big.Int) *big.Int {
	// c = m^e mod n
	return new(big.Int).Exp(message, publicKey.E, publicKey.N)
}

func RSADecrypt(privateKey *RSAPrivateKey, ciphertext *big.Int) *big.Int {
	// m = c^d mod n
	return new(big.Int).Exp(ciphertext, privateKey.D, privateKey.PublicKey.N)
}

func RSASign(privateKey *RSAPrivateKey, message *big.Int) *big.Int {
	// s = m^d mod n
	return new(big.Int).Exp(message, privateKey.D, privateKey.PublicKey.N)
}

func RSAVerify(publicKey *RSAPublicKey, signature *big.Int) *big.Int {
	// m = s^e mod n
	return new(big.Int).Exp(signature, publicKey.E, publicKey.N)
}

func BytesToBigInt(data []byte) *big.Int {
	return new(big.Int).SetBytes(data)
}

func BigIntToBytes(n *big.Int) []byte {
	return n.Bytes()
}

func SplitIntoBlocks(data []byte, blockSize int) [][]byte {
	var blocks [][]byte
	for i := 0; i < len(data); i += blockSize {
		end := i + blockSize
		if end > len(data) {
			end = len(data)
		}
		blocks = append(blocks, data[i:end])
	}
	return blocks
}

func GenerateRandomBigInt(bits int) (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	return rand.Int(rand.Reader, max)
}
