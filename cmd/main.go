package main

import (
	"fmt"
	"nawa-functions/internal"
)

func main() {
	key := []byte("")
	data := []byte("")

	// Encrypt
	encrypted, _ := internal.Encrypt(data, key)
	fmt.Printf("Encrypted: %s\n", encrypted)

	//Decrypt
	decrypted, _ := internal.Decrypt(encrypted, key)

	fmt.Printf("Decrypted: %s\n", string(decrypted))
}
