package crypt

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"

	ciphers "github.com/kayon/crypt/cipher"
)

const (
	desSaltKeyByteSize = 8
	tripleDesSaltKeyByteSize = 24
)

var DES cryptDES

type cryptDES struct{}

func (cryptDES) Encrypt(plaintext, key, iv []byte, args ...Options) ([]byte, error) {
	c, err := NewDES(key, iv, args...)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(plaintext)
}

func (cryptDES) Decrypt(ciphertext, key, iv []byte, args ...Options) ([]byte, error) {
	c, err := NewDES(key, iv, args...)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ciphertext)
}

var DES3 tripleDES

type tripleDES struct{}

func (tripleDES) Encrypt(plaintext, key, iv []byte, args ...Options) ([]byte, error) {
	c, err := NewDES3(key, iv, args...)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(plaintext)
}

func (tripleDES) Decrypt(ciphertext, key, iv []byte, args ...Options) ([]byte, error) {
	c, err := NewDES3(key, iv, args...)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ciphertext)
}

func desEncrypt(src, key, iv []byte, block cipher.Block, mode BlockMode, scheme PaddingScheme, triple bool) (ciphertext []byte, err error) {
	var header [16]byte
	var plaintext []byte
	var offset int

	if mode.Has(MODE_CBC, MODE_ECB) {
		plaintext, err = Padding(scheme, src, des.BlockSize)
		if err != nil {
			return nil, err
		}
	} else {
		plaintext = append([]byte{}, src...)
	}
	if mode.Not(MODE_ECB) && iv == nil {
		saltKeyByteSize := desSaltKeyByteSize
		if triple {
			saltKeyByteSize = tripleDesSaltKeyByteSize
		}
		header, key, iv = genSaltHeader(key, block.BlockSize(), mode, saltKeyByteSize)
		if triple {
			if block, err = des.NewTripleDESCipher(key); err != nil {
				return nil, err
			}
		} else if block, err = des.NewCipher(key); err != nil {
			return nil, err
		}
		offset = 16
		ciphertext = append(header[:], plaintext...)
	} else {
		ciphertext = append([]byte{}, plaintext...)
	}

	switch mode {
	case MODE_CBC:
		bm := cipher.NewCBCEncrypter(block, iv)
		bm.CryptBlocks(ciphertext[offset:], plaintext)
	case MODE_CFB:
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(ciphertext[offset:], plaintext)
	case MODE_CTR:
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(ciphertext[offset:], plaintext)
	case MODE_OFB:
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(ciphertext[offset:], plaintext)
	case MODE_ECB:
		bm := ciphers.NewECBEncrypter(block)
		bm.CryptBlocks(ciphertext[offset:], plaintext)
	}
	return
}

func desDecrypt(src, key, iv []byte, block cipher.Block, mode BlockMode, scheme PaddingScheme, triple bool) (plaintext []byte, err error) {
	var ciphertext []byte
	if salt, ok := getSalt(src); ok {
		saltKeyByteSize := desSaltKeyByteSize
		if triple {
			saltKeyByteSize = tripleDesSaltKeyByteSize
		}
		key, iv = parseSaltHeader(salt, key, block.BlockSize(), mode, saltKeyByteSize)
		if triple {
			if block, err = des.NewTripleDESCipher(key); err != nil {
				return nil, err
			}
		} else if block, err = des.NewCipher(key); err != nil {
			return nil, err
		}
		ciphertext = append([]byte{}, src[16:]...)
	} else {
		ciphertext = append([]byte{}, src...)
	}
	if mode.Not(MODE_ECB) && len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("crypt DES.Decrypt: IV length must equal block size")
	}
	plaintext = make([]byte, len(ciphertext))

	switch mode {
	case MODE_CBC:
		bm := cipher.NewCBCDecrypter(block, iv)
		bm.CryptBlocks(plaintext, ciphertext)
	case MODE_CFB:
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(plaintext, ciphertext)
	case MODE_CTR:
		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(plaintext, ciphertext)
	case MODE_OFB:
		stream := cipher.NewOFB(block, iv)
		stream.XORKeyStream(plaintext, ciphertext)
	case MODE_ECB:
		bm := ciphers.NewECBDecrypter(block)
		bm.CryptBlocks(plaintext, ciphertext)
	}
	if mode.Has(MODE_CBC, MODE_ECB) {
		plaintext, err = UnPadding(scheme, plaintext, des.BlockSize)
	}
	return
}

