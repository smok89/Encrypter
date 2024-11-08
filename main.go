package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func getInput(prompt string, r *bufio.Reader) (string, error) {
	fmt.Print(prompt)
	input, err := r.ReadString('\n')
	return strings.TrimSpace(input), err
}

func promptOptions() {
	reader := bufio.NewReader(os.Stdin)
	opt, _ := getInput("Choose option (e - encrypt, d - decrypt):   ", reader)
	switch opt {
	case "e":
		message, _ := getInput("What is the message to be encrypted ?   ", reader)
		algo, _ := getInput("Which algorithm do you want to use ? \n(cesar, base32, base64, rot13, vigenere):   ", reader)
		encryptedMessage := encrypt(message, algo, reader)
		fmt.Printf("The encrypted message is:   %v\n", encryptedMessage)

	case "d":
		message, _ := getInput("What is the message to be decrypted ?   ", reader)
		algo, _ := getInput("Which algorithm was used ? \n(cesar, base32, base64, rot13, vigenere):   ", reader)
		decryptedMessage := decrypt(message, algo, reader)
		fmt.Printf("The decrypted message is:   %v\n", decryptedMessage)
	default:
		fmt.Printf("%q is not a valid option.\n", opt)
		promptOptions()
	}
}

func main() {
	promptOptions()
}
