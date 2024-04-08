package main

import "math"

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
