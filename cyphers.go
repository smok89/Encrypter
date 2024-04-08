package main

import (
	"bufio"
	"strconv"
	"strings"
)

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

func encrypt_base(messageToEncrypt string, table string, blockSize int, modulo int) string {
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

func encrypt_base32(messageToEncrypt string) string {
	base32Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	blockSize := 5
	modulo := 40
	return encrypt_base(messageToEncrypt, base32Table, blockSize, modulo)
}

func encrypt_base64(messageToEncrypt string) string {
	base64Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	blockSize := 6
	modulo := 24
	return encrypt_base(messageToEncrypt, base64Table, blockSize, modulo)
}

func decrypt_base(messageToDecrypt string, table string, blockSize int) string {
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

func decrypt_base64(messageToDecrypt string) string {
	base64Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	blockSize := 6
	return decrypt_base(messageToDecrypt, base64Table, blockSize)
}

func decrypt_base32(messageToDecrypt string) string {
	base32Table := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	blockSize := 5
	return decrypt_base(messageToDecrypt, base32Table, blockSize)
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
