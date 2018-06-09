package crypt

import (
	"bytes"
	"fmt"
)

type PaddingScheme uint8

const (
	PAD_PKCS7       PaddingScheme = iota
	PAD_ISO97971
	PAD_ANSIX923
	PAD_ISO10126
	PAD_ZEROPADDING
	PAD_NOPADDING
)

func (scheme PaddingScheme) String() string {
	switch scheme {
	case PAD_PKCS7:
		return "PKCS7"
	case PAD_ISO97971:
		return "ISO/IEC 9797-1"
	case PAD_ANSIX923:
		return "ANSI X.923"
	case PAD_ISO10126:
		return "ISO10126"
	case PAD_ZEROPADDING:
		return "ZeroPadding"
	case PAD_NOPADDING:
		return "NoPadding"
	}
	return ""
}

func padSize(dataSize, blockSize int) (padding int) {
	padding = blockSize - dataSize%blockSize
	return
}

// PKCS7
func PKCS7Padding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("crypt.PKCS7Padding blockSize is out of bounds: %d", blockSize)
	}
	padding := padSize(len(plaintext), blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...), nil
}

func PKCS7UnPadding(ciphertext []byte, blockSize int) ([]byte, error) {
	length := len(ciphertext)
	if length%blockSize != 0 {
		return nil, fmt.Errorf("crypt.PKCS7UnPadding ciphertext's length isn't a multiple of blockSize")
	}
	unpadding := int(ciphertext[length-1])
	if unpadding > blockSize || unpadding <= 0 {
		return nil, fmt.Errorf("crypt.PKCS7UnPadding invalid padding found: %v", unpadding)
	}
	var pad = ciphertext[length-unpadding : length-1]
	for _, v := range pad {
		if int(v) != unpadding {
			return nil, fmt.Errorf("crypt.PKCS7UnPadding invalid padding found")
		}
	}
	return ciphertext[:length-unpadding], nil
}

// Zero padding
func ZeroPadding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("crypt.ZeroPadding blockSize is out of bounds: %d", blockSize)
	}
	padding := padSize(len(plaintext), blockSize)
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(plaintext, padtext...), nil
}

func ZeroUnPadding(ciphertext []byte, _ int) ([]byte, error) {
	return bytes.TrimRightFunc(ciphertext, func(r rune) bool { return r == rune(0) }), nil
}

// ISO/IEC 9797-1 Padding Method 2
func ISO97971Padding(plaintext []byte, blockSize int) ([]byte, error) {
	return ZeroPadding(append(plaintext, 0x80), blockSize)
}

func ISO97971UnPadding(ciphertext []byte, blockSize int) ([]byte, error) {
	data, err := ZeroUnPadding(ciphertext, blockSize)
	if err != nil {
		return nil, err
	}
	return data[:len(data)-1], nil
}

// ANSI X.923 padding
func AnsiX923Padding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, fmt.Errorf("crypt.AnsiX923Padding blockSize is out of bounds: %d", blockSize)
	}
	padding := padSize(len(plaintext), blockSize)
	padtext := append(bytes.Repeat([]byte{byte(0)}, padding-1), byte(padding))
	return append(plaintext, padtext...), nil
}

func AnsiX923UnPadding(ciphertext []byte, blockSize int) ([]byte, error) {
	length := len(ciphertext)
	if length%blockSize != 0 {
		return nil, fmt.Errorf("crypt.AnsiX923UnPadding ciphertext's length isn't a multiple of blockSize")
	}
	unpadding := int(ciphertext[length-1])
	if unpadding > blockSize || unpadding < 1 {
		return nil, fmt.Errorf("crypt.AnsiX923UnPadding invalid padding found: %d", unpadding)
	}
	if length-unpadding < length-2 {
		pad := ciphertext[length-unpadding : length-2]
		for _, v := range pad {
			if int(v) != 0 {
				return nil, fmt.Errorf("crypt.AnsiX923UnPadding invalid padding found")
			}
		}
	}
	return ciphertext[0 : length-unpadding], nil
}

// ISO10126 implements ISO 10126 byte padding. This has been withdrawn in 2007.
func ISO10126Padding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 256 {
		return nil, fmt.Errorf("crypt.ISO10126Padding blockSize is out of bounds: %d", blockSize)
	}
	padding := padSize(len(plaintext), blockSize)
	padtext := append(randBytes(padding-1), byte(padding))
	return append(plaintext, padtext...), nil
}

func ISO10126UnPadding(ciphertext []byte, blockSize int) ([]byte, error) {
	length := len(ciphertext)
	if length%blockSize != 0 {
		return nil, fmt.Errorf("crypt.ISO10126UnPadding ciphertext's length isn't a multiple of blockSize")
	}
	unpadding := int(ciphertext[length-1])
	if unpadding > blockSize || unpadding < 1 {
		return nil, fmt.Errorf("crypt.ISO10126UnPadding invalid padding found: %v", unpadding)
	}
	return ciphertext[:length-unpadding], nil
}

func Padding(scheme PaddingScheme, plaintext []byte, blockSize int) (padded []byte, err error) {
	switch scheme {
	case PAD_PKCS7:
		padded, err = PKCS7Padding(plaintext, blockSize)
	case PAD_ISO97971:
		padded, err = ISO97971Padding(plaintext, blockSize)
	case PAD_ANSIX923:
		padded, err = AnsiX923Padding(plaintext, blockSize)
	case PAD_ISO10126:
		padded, err = ISO10126Padding(plaintext, blockSize)
	case PAD_ZEROPADDING:
		padded, err = ZeroPadding(plaintext, blockSize)
	case PAD_NOPADDING:
		if len(plaintext)%blockSize != 0 {
			return nil, fmt.Errorf("crypt.NoPadding plaintext is not a multiple of the block size")
		}
		return plaintext, nil
	}
	return
}

func UnPadding(scheme PaddingScheme, ciphertext []byte, blockSize int) (data []byte, err error) {
	switch scheme {
	case PAD_PKCS7:
		data, err = PKCS7UnPadding(ciphertext, blockSize)
	case PAD_ISO97971:
		data, err = ISO97971UnPadding(ciphertext, blockSize)
	case PAD_ANSIX923:
		data, err = AnsiX923UnPadding(ciphertext, blockSize)
	case PAD_ISO10126:
		data, err = ISO10126UnPadding(ciphertext, blockSize)
	case PAD_ZEROPADDING:
		data, err = ZeroUnPadding(ciphertext, blockSize)
	case PAD_NOPADDING:
		return ciphertext, nil
	}
	return
}
