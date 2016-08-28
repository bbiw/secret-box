package main

import (
	"drurl.us/bbiw/aesgcm"
	"fmt"
	"os"
	"crypto/aes"
	"crypto/rand"
	//"github.com/pkg/errors"
)

func main() {
	plaintext := []byte("This is a secret that I will never reveal.")
	extra := []byte("This is not secret")
	//extra = nil

	key := make([]byte, aes.BlockSize)
	_, err := rand.Reader.Read(key)
	if err != nil {
		fmt.Printf("cannot generate key: %+v", err)
		return
	}

	msg, err := aesgcm.Seal(key, plaintext, extra)
	if err != nil {
    fmt.Printf("cannot generate key: %+v", err)
		return
	}

	os.Stdout.Write(msg)

	os.Stdout.WriteString("\x00\x00\x00\x00")

	uplain, uextra, err := aesgcm.Open(key, msg)
	if err != nil {
    fmt.Printf("cannot generate key: %+v", err)
		return
	}
	os.Stdout.Write(uextra)
	os.Stdout.WriteString("\x00\x00\x00\x00")
	os.Stdout.Write(uplain)
	os.Stdout.WriteString("\x00\x00\x00\x00")

}
