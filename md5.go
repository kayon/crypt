package crypt

import (
	"crypto/md5"
	"encoding/hex"
)

var MD5 cryptMD5

type cryptMD5 struct{}

func (cryptMD5) Sum(plaintext []byte) []byte {
	m := md5.Sum(plaintext)
	return m[:]
}

func (cryptMD5) Hex(plaintext []byte) string {
	return hex.EncodeToString(MD5.Sum(plaintext))
}
