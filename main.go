package main

import (
	"bufio"
	"fmt"
	"math"
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

func stringToBits(str string) []int {
	var bits []int
	for _, c := range []byte(str) {
		for i := 7; i >= 0; i-- {
			bit := (c >> i) & 1
			bits = append(bits, int(bit))
		}
	}
	return bits
}

func binaryToDecimal(binary []int) int {
	decimal := 0
	size := len(binary)
	for i, bit := range binary {
		decimal += bit * int(math.Pow(2, float64(size-i-1)))
	}
	return decimal
}

func decimalToBinary(n int, blockSize int) []int {
	bits := make([]int, blockSize)
	for i := 0; i < blockSize; i++ {
		bits[blockSize-1-i] = n & 1
		n = n >> 1
	}
	return bits
}

func encrypt_base32(messageToEncrypt string) string {
	encryptedMessage := ""
	base32Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	bits := stringToBits(messageToEncrypt)
	size := len(bits)
	if size%40 != 0 {
		numberZerosToAdd := 40 - size%40
		bits = append(bits, make([]int, numberZerosToAdd)...)
	}
	numberOf6BitsBlocks := len(bits) / 5
	for i := 0; i < numberOf6BitsBlocks; i++ {
		if i <= size/5 {
			block := bits[i*5 : (i+1)*5]
			valueOfBlock := binaryToDecimal(block)
			encryptedMessage += string(base32Table[valueOfBlock])
		} else {
			encryptedMessage += "="
		}
	}
	return encryptedMessage
}

func decrypt_base32(messageToDecrypt string) string {
	decryptedMessage := ""
	base32Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var bits []int
	for _, s := range messageToDecrypt {
		if s != rune('=') {
			index := strings.Index(base32Table, string(s))
			IndexBits := decimalToBinary(index, 5)
			bits = append(bits, IndexBits...)
		}
	}
	size := len(bits)
	numberOfBytes := size / 8

	for i := 0; i < numberOfBytes; i++ {
		byteBlock := bits[i*8 : (i+1)*8]
		decimalValue := binaryToDecimal(byteBlock)
		decryptedMessage += string(rune(decimalValue))
	}
	return decryptedMessage
}

func encrypt_base64(messageToEncrypt string) string {
	encryptedMessage := ""
	base64Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	bits := stringToBits(messageToEncrypt)
	size := len(bits)
	if size%24 != 0 {
		numberZerosToAdd := 24 - size%24
		bits = append(bits, make([]int, numberZerosToAdd)...)
	}
	numberOf6BitsBlocks := len(bits) / 6
	for i := 0; i < numberOf6BitsBlocks; i++ {
		if i <= size/6 {
			block := bits[i*6 : (i+1)*6]
			valueOfBlock := binaryToDecimal(block)
			encryptedMessage += string(base64Table[valueOfBlock])
		} else {
			encryptedMessage += "="
		}
	}
	return encryptedMessage
}

func decrypt_base64(messageToDecrypt string) string {
	decryptedMessage := ""
	base64Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var bits []int
	for _, s := range messageToDecrypt {
		if s != rune('=') {
			index := strings.Index(base64Table, string(s))
			IndexBits := decimalToBinary(index, 6)
			bits = append(bits, IndexBits...)
		}
	}
	size := len(bits)
	numberOfBytes := size / 8

	for i := 0; i < numberOfBytes; i++ {
		byteBlock := bits[i*8 : (i+1)*8]
		decimalValue := binaryToDecimal(byteBlock)
		decryptedMessage += string(rune(decimalValue))
	}
	return decryptedMessage
}

func encrypt(messageToEncrypt string, algo string, r *bufio.Reader) string {
	switch algo {
	case "cesar":
		offset_str, _ := getInput("What is the offset to use ? - ", r)
		offset, _ := strconv.Atoi(offset_str)
		encryptedMessage := encrypt_cesar(messageToEncrypt, offset)
		return encryptedMessage
	case "base32":
		encryptedMessage := encrypt_base32(messageToEncrypt)
		return encryptedMessage
	case "base64":
		encryptedMessage := encrypt_base64(messageToEncrypt)
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
	case "base32":
		decryptedMessage := decrypt_base32(messageToDecrypt)
		return decryptedMessage
	case "base64":
		decryptedMessage := decrypt_base64(messageToDecrypt)
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
		algo, _ := getInput("Which algorithm do you want to use ? (cesar, base32, base64) - ", reader)
		encryptedMessage := encrypt(message, algo, reader)
		fmt.Printf("The encrypted message is: %v\n", encryptedMessage)

	case "d":
		message, _ := getInput("What is the message to be decrypted ? - ", reader)
		algo, _ := getInput("Which algorithm was used ? (cesar, base32, base64) - ", reader)
		decryptedMessage := decrypt(message, algo, reader)
		fmt.Printf("The decrypted message is: %v\n", decryptedMessage)
	}
}

func main() {
	promptOptions()
}
