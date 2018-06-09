package crypt

import (
	"golang.org/x/crypto/sha3"
)

var SHA3 cryptSha3

type cryptSha3 struct{}

// Sum224 returns the SHA3-224 digest of the data.
func (cryptSha3) Sum224(data []byte) []byte {
	var digest [28]byte
	digest = sha3.Sum224(data)
	return digest[:]
}

// Sum256 returns the SHA3-256 digest of the data.
func (cryptSha3) Sum256(data []byte) []byte {
	var digest [32]byte
	digest = sha3.Sum256(data)
	return digest[:]
}

// Sum384 returns the SHA3-384 digest of the data.
func (cryptSha3) Sum384(data []byte) []byte {
	var digest [48]byte
	digest = sha3.Sum384(data)
	return digest[:]
}

// Sum512 returns the SHA3-512 digest of the data.
func (cryptSha3) Sum512(data []byte) []byte {
	var digest [64]byte
	digest = sha3.Sum512(data)
	return digest[:]
}

func (cryptSha3) Shake128(data []byte, size int) (hash []byte) {
	hash = make([]byte, size)
	sha3.ShakeSum128(hash, data)
	return
}

func (cryptSha3) Shake256(data []byte, size int) (hash []byte) {
	hash = make([]byte, size)
	sha3.ShakeSum256(hash, data)
	return
}