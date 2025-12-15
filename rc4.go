package main

type RC4 struct {
	s []int
	i int
	j int
}

func NewRC4(key []byte) *RC4 {
	rc4 := &RC4{
		s: make([]int, 256),
		i: 0,
		j: 0,
	}

	for i := 0; i < 256; i++ {
		rc4.s[i] = i
	}

	j := 0
	keyLen := len(key)
	for i := 0; i < 256; i++ {
		j = (j + rc4.s[i] + int(key[i%keyLen])) % 256
		rc4.s[i], rc4.s[j] = rc4.s[j], rc4.s[i]
	}

	return rc4
}

func (rc4 *RC4) Crypt(data []byte) []byte {
	result := make([]byte, len(data))

	for idx, b := range data {
		rc4.i = (rc4.i + 1) % 256
		rc4.j = (rc4.j + rc4.s[rc4.i]) % 256
		rc4.s[rc4.i], rc4.s[rc4.j] = rc4.s[rc4.j], rc4.s[rc4.i]

		k := rc4.s[(rc4.s[rc4.i]+rc4.s[rc4.j])%256]
		result[idx] = b ^ byte(k)
	}

	return result
}

func RC4Encrypt(key []byte, plaintext string) []byte {
	rc4 := NewRC4(key)
	return rc4.Crypt([]byte(plaintext))
}

func RC4Decrypt(key []byte, ciphertext []byte) string {
	rc4 := NewRC4(key)
	return string(rc4.Crypt(ciphertext))
}
