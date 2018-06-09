package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	ciphers "github.com/kayon/crypt/cipher"
)

const aesSaltKeyByteSize = 32

// Shortcuts
var AES cryptAES

type cryptAES struct{}

func (cryptAES) Encrypt(plaintext, key, iv []byte, args ...Options) ([]byte, error) {
	c, err := NewAES(key, iv, args...)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(plaintext)
}

func (cryptAES) Decrypt(ciphertext, key, iv []byte, args ...Options) ([]byte, error) {
	c, err := NewAES(key, iv, args...)
	if err != nil {
		return nil, err
	}
	return c.Decrypt(ciphertext)
}

func aesEncrypt(src, key, iv []byte, block cipher.Block, mode BlockMode, scheme PaddingScheme) (ciphertext []byte, err error) {
	var header [16]byte
	var plaintext []byte
	var offset int
	if mode.Has(MODE_CBC, MODE_ECB) {
		plaintext, err = Padding(scheme, src, aes.BlockSize)
		if err != nil {
			return nil, err
		}
	} else {
		plaintext = append([]byte{}, src...)
	}
	if mode.Not(MODE_ECB) && iv == nil {
		header, key, iv = genSaltHeader(key, block.BlockSize(), mode, aesSaltKeyByteSize)
		if block, err = aes.NewCipher(key); err != nil {
			return nil, err
		}
		offset = 16
		ciphertext = append(header[:], plaintext...)
	} else {
		ciphertext = append(ciphertext, plaintext...)
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
	case MODE_GCM:
		if uint64(len(plaintext)) > ((1<<32)-2)*uint64(block.BlockSize()) {
			return nil, fmt.Errorf("crypt AES.Encrypt: plaintext too large for GCM")
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext[:offset], gcm.Seal(nil, iv, plaintext, nil)...)
	case MODE_ECB:
		bm := ciphers.NewECBEncrypter(block)
		bm.CryptBlocks(ciphertext[offset:], plaintext)
	}
	return
}

func aesDecrypt(src, key, iv []byte, block cipher.Block, mode BlockMode, scheme PaddingScheme) (plaintext []byte, err error) {
	var ciphertext []byte
	if salt, ok := getSalt(src); ok {
		key, iv = parseSaltHeader(salt, key, block.BlockSize(), mode, aesSaltKeyByteSize)
		if block, err = aes.NewCipher(key); err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, src[16:]...)
	} else {
		ciphertext = append(ciphertext, src...)
	}
	if mode.Not(MODE_ECB) {
		if mode.Has(MODE_GCM) && len(iv) != gcmStandardNonceSize {
			return nil, fmt.Errorf("crypt AES.Decrypt: incorrect nonce length given to GCM")
		} else if mode.Not(MODE_GCM) && len(iv) != block.BlockSize() {
			return nil, fmt.Errorf("crypt AES.Decrypt: IV length must equal block size")
		}
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
	case MODE_GCM:
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		plaintext, err = gcm.Open(nil, iv, ciphertext, nil)
		if err != nil {
			err = fmt.Errorf("crypt AES.Decrypt: GCM authentication failed")
		}
	case MODE_ECB:
		bm := ciphers.NewECBDecrypter(block)
		bm.CryptBlocks(plaintext, ciphertext)
	}
	if mode.Has(MODE_CBC, MODE_ECB) {
		plaintext, err = UnPadding(scheme, plaintext, aes.BlockSize)
	}
	return
}
