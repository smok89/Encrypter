package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func getInput(prompt string, r *bufio.Reader) (string, error) {
	fmt.Print(prompt)
	input, err := r.ReadString('\n')
	return strings.TrimSpace(input), err
}

func encrypt_cesar(messageToEncrypt string, offset int) string {
	encryptedMessage := ""
	for _, r := range messageToEncrypt {
		if 'a' <= r && r <= 'z' {
			encryptedMessage += string((r-'a'+rune(offset))%26 + 'a')
		} else if 'A' <= r && r <= 'Z' {
			encryptedMessage += string((r-'A'+rune(offset))%26 + 'A')
		} else {
			encryptedMessage += string(r)
		}
	}
	return encryptedMessage
}

func decrypt_cesar(messageToEncrypt string, offset int) string {
	return encrypt_cesar(messageToEncrypt, -offset)
}

func encrypt(messageToEncrypt string, algo string, r *bufio.Reader) string {
	switch algo {
	case "cesar":
		offset_str, _ := getInput("What is the offset to use ? - ", r)
		offset, _ := strconv.Atoi(offset_str)
		encryptedMessage := encrypt_cesar(messageToEncrypt, offset)
		return encryptedMessage

	default:
		return messageToEncrypt
	}
}

func decrypt(messageToDecrypt string, algo string, r *bufio.Reader) string {
	switch algo {
	case "cesar":
		offset_str, _ := getInput("What is the offset used to cipher ? - ", r)
		offset, _ := strconv.Atoi(offset_str)
		decryptedMessage := decrypt_cesar(messageToDecrypt, offset)
		return decryptedMessage
	default:
		return messageToDecrypt
	}
}

func promptOptions() {
	reader := bufio.NewReader(os.Stdin)
	opt, _ := getInput("Choose option (e - encrypt, d - decrypt) - ", reader)
	switch opt {
	case "e":
		message, _ := getInput("What is the message to be encrypted ? - ", reader)
		algo, _ := getInput("Which algorithm do you want to use ? (cesar, b32, b64) - ", reader)
		encryptedMessage := encrypt(message, algo, reader)
		fmt.Printf("The encrypted message is: %v\n", encryptedMessage)

	case "d":
		message, _ := getInput("What is the message to be decrypted ? - ", reader)
		algo, _ := getInput("Which algorithm was used ? (cesar, b32, b64) - ", reader)
		decryptedMessage := decrypt(message, algo, reader)
		fmt.Printf("The decrypted message is: %v\n", decryptedMessage)
	}
}

func main() {
	fmt.Println()
	promptOptions()
}
