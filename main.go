package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"

	"github.com/shirou/gopsutil/host"
)

func main() {
	uuid := uuid()

	ab := Encrypter("AES256Key-32Characters1234567890", "dd"+uuid[:8]+uuid[24:]+"dd", []byte("hey"))
	fmt.Println(ab)

	ba := Decrypter("AES256Key-32Characters1234567890", "dd"+uuid[:8]+uuid[24:]+"dd", ab)
	fmt.Println(string(ba[:]))
}

func uuid() string {

	hostStat, err := host.Info()
	if err != nil {
		panic(err.Error())
	}
	return hostStat.HostID
}

func Encrypter(pass string, uuid string, plaintext []byte) []byte {
	// to select AES-128 or AES-256.
	key := []byte(pass)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce, _ := hex.DecodeString(uuid)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return []byte(fmt.Sprintf("%x", ciphertext)[:])
}

func Decrypter(pass string, uuid string, ba []byte) []byte {
	// to select AES-128 or AES-256.
	key := []byte(pass)

	dst := make([]byte, hex.DecodedLen(len(ba)))
	n, _ := hex.Decode(dst, ba)
	ciphertext := dst[:n]
	nonce, _ := hex.DecodeString(uuid)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return plaintext
}
