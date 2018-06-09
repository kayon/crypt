package crypt

import (
	"crypto/cipher"
	"fmt"
)

const blowfishBlockSize = 8

var Blowfish cryptBlowfish

type cryptBlowfish struct{}

func (cryptBlowfish) Encrypt(plaintext, key []byte) ([]byte, error) {
	c, err := NewBlowfish(key)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(plaintext)
}

func (cryptBlowfish) Decrypt(ciphertext, key []byte) ([]byte, error) {
	c, err := NewBlowfish(key)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ciphertext)
}

func blowfishEncrypt(src []byte, block cipher.Block) (ciphertext []byte, err error) {
	var plaintext []byte
	var b = make([]byte, blowfishBlockSize)
	var size int
	if len(src) % blowfishBlockSize != 0 {
		if plaintext, err = Padding(PAD_ZEROPADDING, src, blowfishBlockSize); err != nil {
			return nil, err
		}
	} else {
		plaintext = append([]byte{}, src...)
	}
	size = len(plaintext) / blowfishBlockSize
	ciphertext = make([]byte, 0, size * blowfishBlockSize)
	for i := 0; i < size; i++ {
		block.Encrypt(b, plaintext[i*blowfishBlockSize:(i+1)*blowfishBlockSize])
		ciphertext = append(ciphertext, b...)
	}
	return
}

func blowfishDecrypt(src []byte, block cipher.Block) (plaintext []byte, err error) {
	var b = make([]byte, blowfishBlockSize)
	var size int
	if len(src) % blowfishBlockSize != 0 {
		return nil, fmt.Errorf("crypt Blowfish.Decrypt: ciphertext length must equal block size")
	}
	size = len(src) / blowfishBlockSize
	plaintext = make([]byte, 0, size)
	for i := 0; i < size; i++ {
		block.Decrypt(b, src[i*blowfishBlockSize:(i+1)*blowfishBlockSize])
		plaintext = append(plaintext, b...)
	}
	plaintext, err = UnPadding(PAD_ZEROPADDING, plaintext, blowfishBlockSize)
	return
}