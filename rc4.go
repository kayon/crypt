package crypt

import "crypto/rc4"

var RC4 cryptRC4

type cryptRC4 struct{}

func (cryptRC4) Encrypt(plaintext, key []byte) ([]byte, error) {
	c, err := NewRC4(key)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(plaintext)
}

func (cryptRC4) Decrypt(ciphertext, key []byte) ([]byte, error) {
	c, err := NewRC4(key)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ciphertext)
}

func rc4Encrypt(src, key []byte) (ciphertext []byte, err error) {
	var c *rc4.Cipher
	if c, err = rc4.NewCipher(key); err != nil {
		return
	}
	ciphertext = make([]byte, len(src))
	c.XORKeyStream(ciphertext, src)
	return
}

func rc4Decrypt(src, key []byte) (plaintext []byte, err error) {
	var c *rc4.Cipher
	if c, err = rc4.NewCipher(key); err != nil {
		return
	}
	plaintext = make([]byte, len(src))
	c.XORKeyStream(plaintext, src)
	return
}
