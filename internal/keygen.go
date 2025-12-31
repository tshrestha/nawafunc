package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

func Encrypt(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 1. Allocate a single buffer for [nonce + ciphertext + tag]
	rawSize := gcm.NonceSize() + len(plaintext) + 16 // 16 is standard GCM tag size
	out := make([]byte, rawSize)

	// 2. Generate Nonce directly into the start of the buffer
	nonce := out[:gcm.NonceSize()]
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 3. Encrypt directly into the remainder of the buffer
	// Seal(dst, nonce, plaintext, data) -> appends to dst
	gcm.Seal(out[:gcm.NonceSize()], nonce, plaintext, nil)

	// 4. Encode to Base64 string
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func Decrypt(cryptoText string, key []byte) ([]byte, error) {
	// 1. Decode Base64 string back to bytes
	data, err := base64.RawURLEncoding.DecodeString(cryptoText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// 2. Decrypt in-place using the decoded buffer to save memory
	return gcm.Open(ciphertext[:0], nonce, ciphertext, nil)
}
