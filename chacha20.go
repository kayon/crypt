package crypt

import (
	"fmt"

	"github.com/Yawning/chacha20"
)

const (
	chacha20SaltKeyByteSize   = 32
	chacha20SaltNonceByteSize = 24
)

var ChaCha20 cryptChaCha20

type cryptChaCha20 struct{}

func (cryptChaCha20) Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	c, err := NewChaCha20(key, iv)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(plaintext)
}

func (cryptChaCha20) Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	c, err := NewChaCha20(key, iv)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ciphertext)
}

func chacha20Encrypt(src, key, iv []byte) (ciphertext []byte, err error) {
	var stream *chacha20.Cipher
	var offset int
	if iv == nil {
		var header [16]byte
		header, key, iv = genSaltHeader(key, chacha20SaltNonceByteSize, 0, chacha20SaltKeyByteSize)
		ciphertext = append(header[:], src...)
		offset = 16
	} else {
		ciphertext = append([]byte{}, src...)
	}
	if stream, err = chacha20.NewCipher(key, iv); err != nil {
		return nil, err
	}
	stream.XORKeyStream(ciphertext[offset:], src)
	return
}

func chacha20Decrypt(src, key, iv []byte) (plaintext []byte, err error) {
	var stream *chacha20.Cipher
	var ciphertext []byte
	if salt, ok := getSalt(src); ok {
		key, iv = parseSaltHeader(salt, key, chacha20SaltNonceByteSize, 0, chacha20SaltKeyByteSize)
		ciphertext = append([]byte{}, src[16:]...)
	} else {
		ciphertext = append([]byte{}, src...)
	}

	if !inSliceInt(len(iv), []int{8, 12, 24}) {
		return nil, fmt.Errorf("crypt ChaCha20.Decrypt: invalid nonce size %d", len(iv))
	} else if stream, err = chacha20.NewCipher(key, iv); err != nil {
		return nil, err
	}
	plaintext = make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return
}
