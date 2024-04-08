package main

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

func encryptCesar(messageToEncrypt string, offset int) string {
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

func decryptCesar(messageToEncrypt string, offset int) string {
	return encryptCesar(messageToEncrypt, -offset)
}

func encryptBase(messageToEncrypt string, table string, blockSize int, modulo int) string {
	encryptedMessage := ""
	bits := stringToBits(messageToEncrypt)
	size := len(bits)
	if size%modulo != 0 {
		numberZerosToAdd := modulo - size%modulo
		bits = append(bits, make([]int, numberZerosToAdd)...)
	}
	numberOf6BitsBlocks := len(bits) / blockSize
	for i := 0; i < numberOf6BitsBlocks; i++ {
		if i <= size/blockSize {
			block := bits[i*blockSize : (i+1)*blockSize]
			valueOfBlock := binaryToDecimal(block)
			encryptedMessage += string(table[valueOfBlock])
		} else {
			encryptedMessage += "="
		}
	}
	return encryptedMessage
}

func encryptBase32(messageToEncrypt string) string {
	base32Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	blockSize := 5
	modulo := 40
	return encryptBase(messageToEncrypt, base32Table, blockSize, modulo)
}

func encryptBase64(messageToEncrypt string) string {
	base64Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	blockSize := 6
	modulo := 24
	return encryptBase(messageToEncrypt, base64Table, blockSize, modulo)
}

func decryptBase(messageToDecrypt string, table string, blockSize int) string {
	decryptedMessage := ""
	var bits []int
	for _, s := range messageToDecrypt {
		if s != rune('=') {
			index := strings.Index(table, string(s))
			IndexBits := decimalToBinary(index, blockSize)
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

func decryptBase64(messageToDecrypt string) string {
	base64Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	blockSize := 6
	return decryptBase(messageToDecrypt, base64Table, blockSize)
}

func decryptBase32(messageToDecrypt string) string {
	base32Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	blockSize := 5
	return decryptBase(messageToDecrypt, base32Table, blockSize)
}

func cryptRot13(message string) string {
	return encryptCesar(message, 13)
}

func generateVigenereKey(messageSize int, key string) string {
	keySize := len(key)
	var fullKey string
	for i := 0; ; i++ {
		if i == keySize {
			i = 0
		}
		if len(fullKey) == messageSize {
			break
		}
		fullKey += string(key[i])
	}
	return fullKey
}

func encryptVigenere(messageToEncrypt string, key string) string {
	encryptionKey := generateVigenereKey(len(messageToEncrypt), key)
	var encryptedMessage string
	for i, r := range messageToEncrypt {
		if 'A' <= r && r <= 'Z' {
			encryptedMessage += string((r-2*'A'+rune(encryptionKey[i]))%26 + 'A') // substract 2*'A' because here offset = key[i]-'A' and not just key[i]
		} else {
			encryptedMessage += string(r)

		}
	}
	return encryptedMessage
}

func decryptVigenere(messageToEncrypt string, key string) string {
	encryptionKey := generateVigenereKey(len(messageToEncrypt), key)
	var encryptedMessage string
	for i, r := range messageToEncrypt {
		if 'A' <= r && r <= 'Z' {
			encryptedMessage += string((26+r-rune(encryptionKey[i]))%26 + 'A') // the sign of (key[i]-'A') was changed
		} else {
			encryptedMessage += string(r)

		}
	}
	return encryptedMessage
}

func encrypt(messageToEncrypt string, algo string, r *bufio.Reader) string {
	switch algo {
	case "cesar":
		offset_str, _ := getInput("What is the offset to use ?   ", r)
		offset, _ := strconv.Atoi(offset_str)
		encryptedMessage := encryptCesar(messageToEncrypt, offset)
		return encryptedMessage
	case "base32":
		encryptedMessage := encryptBase32(messageToEncrypt)
		return encryptedMessage
	case "base64":
		encryptedMessage := encryptBase64(messageToEncrypt)
		return encryptedMessage
	case "rot13":
		encryptedMessage := cryptRot13(messageToEncrypt)
		return encryptedMessage
	case "vigenere":
		key, _ := getInput("What is the key to use ?   ", r)
		messageUpper := strings.ToUpper(messageToEncrypt)
		cleanMessage := strings.ReplaceAll(messageUpper, " ", "")
		fmt.Println("The message was reformated as:  ", cleanMessage)
		keyUpper := strings.ToUpper(key)
		cleanKey := strings.ReplaceAll(keyUpper, " ", "")
		fmt.Println("The key was reformated as:  ", cleanKey)
		encryptedMessage := encryptVigenere(cleanMessage, cleanKey)
		return encryptedMessage
	default:
		return "The algorithm provided was not recognized..."
	}
}

func decrypt(messageToDecrypt string, algo string, r *bufio.Reader) string {
	switch algo {
	case "cesar":
		offset_str, _ := getInput("What is the offset used to cipher ?   ", r)
		offset, _ := strconv.Atoi(offset_str)
		decryptedMessage := decryptCesar(messageToDecrypt, offset)
		return decryptedMessage
	case "base32":
		decryptedMessage := decryptBase32(messageToDecrypt)
		return decryptedMessage
	case "base64":
		decryptedMessage := decryptBase64(messageToDecrypt)
		return decryptedMessage
	case "rot13":
		decryptedMessage := cryptRot13(messageToDecrypt)
		return decryptedMessage
	case "vigenere":
		key, _ := getInput("What key was used ?   ", r)
		messageUpper := strings.ToUpper(messageToDecrypt)
		cleanMessage := strings.ReplaceAll(messageUpper, " ", "")
		fmt.Println("The message was reformated as:  ", cleanMessage)
		keyUpper := strings.ToUpper(key)
		cleanKey := strings.ReplaceAll(keyUpper, " ", "")
		fmt.Println("The key was reformated as:  ", cleanKey)
		decryptedMessage := decryptVigenere(cleanMessage, cleanKey)
		return decryptedMessage
	default:
		return "The algorithm provided was not recognized..."
	}
}
