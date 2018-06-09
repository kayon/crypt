package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"

	"golang.org/x/crypto/blowfish"
)

const (
	gcmStandardNonceSize = 12
	saltedText           = "salted__"
	saltTextByteSize     = len(saltedText)
)

type CipherMethod uint8

const (
	METHOD_AES        CipherMethod = iota
	METHOD_DES
	METHOD_DES3
	METHOD_CHACHA20
	METHOD_BLOWFISH
	METHOD_RC4
)

func (method CipherMethod) String() string {
	switch method {
	case METHOD_AES:
		return "AES"
	case METHOD_DES:
		return "DES"
	case METHOD_DES3:
		return "DES3"
	case METHOD_CHACHA20:
		return "ChaCha20"
	case METHOD_BLOWFISH:
		return "Blowfish"
	case METHOD_RC4:
		return "RC4"
	}
	return ""
}

type Options struct {
	Mode    BlockMode
	Padding PaddingScheme
}

func NewAES(key, iv []byte, args ...Options) (*Crypt, error) {
	return newCrypt(METHOD_AES, key, iv, args...)
}

func NewDES(key, iv []byte, args ...Options) (*Crypt, error) {
	return newCrypt(METHOD_DES, key, iv, args...)
}

func NewDES3(key, iv []byte, args ...Options) (*Crypt, error) {
	return newCrypt(METHOD_DES3, key, iv, args...)
}

func NewChaCha20(key, iv []byte) (*Crypt, error) {
	return newCrypt(METHOD_CHACHA20, key, iv)
}

func NewBlowfish(key []byte) (*Crypt, error) {
	return newCrypt(METHOD_BLOWFISH, key, nil)
}

func NewRC4(key []byte) (*Crypt, error) {
	return newCrypt(METHOD_RC4, key, nil)
}

func newCrypt(method CipherMethod, key, iv []byte, args ...Options) (*Crypt, error) {
	var opts = Options{0, 0}
	if len(args) > 0 {
		opts = args[0]
	}
	var err error
	if key, err = verifyKey(method, key); err != nil {
		return nil, err
	}
	var block cipher.Block
	switch method {
	case METHOD_AES:
		if block, err = aes.NewCipher(key); err == nil {
			if opts.Mode.Not(MODE_ECB) && iv != nil {
				if opts.Mode.Has(MODE_GCM) && len(iv) != gcmStandardNonceSize {
					err = fmt.Errorf("crypt AES: incorrect nonce length given to GCM")
				} else if opts.Mode.Not(MODE_GCM) && len(iv) != block.BlockSize() {
					err = fmt.Errorf("crypt AES: IV length must equal block size (%d)", block.BlockSize())
				}
			}
		}
	case METHOD_DES:
		if opts.Mode == MODE_GCM {
			err = fmt.Errorf("crypt DES: does not support MODE_GCM")
		} else {
			block, err = des.NewCipher(key)
		}
	case METHOD_DES3:
		if opts.Mode == MODE_GCM {
			err = fmt.Errorf("crypt DES3: does not support MODE_GCM")
		} else {
			block, err = des.NewTripleDESCipher(key)
		}
	case METHOD_CHACHA20:
		if iv != nil {
			switch len(iv) {
			case 8, 12, 24:
			default:
				err = fmt.Errorf("crypt ChaCha20: invalid nonce size %d", len(iv))
			}
		}
	case METHOD_BLOWFISH:
		block, err = blowfish.NewCipher(key)
	case METHOD_RC4:

	default:
		return nil, fmt.Errorf("crypt unknown cipher method %d", method)
	}
	if err != nil {
		return nil, err
	}

	if !opts.Mode.Has(MODE_CBC, MODE_ECB) {
		opts.Padding = PAD_NOPADDING
	}

	return &Crypt{
		method:  method,
		mode:    opts.Mode,
		padding: opts.Padding,
		block:   block,
		key:     key,
		iv:      iv,
	}, nil
}

type Crypt struct {
	method  CipherMethod
	mode    BlockMode
	padding PaddingScheme
	block   cipher.Block
	key     []byte
	iv      []byte
}

func (c Crypt) Encrypt(src []byte) ([]byte, error) {
	switch c.method {
	case METHOD_AES:
		return aesEncrypt(src, c.key, c.iv, c.block, c.mode, c.padding)
	case METHOD_DES, METHOD_DES3:
		return desEncrypt(src, c.key, c.iv, c.block, c.mode, c.padding, c.method == METHOD_DES3)
	case METHOD_CHACHA20:
		return chacha20Encrypt(src, c.key, c.iv)
	case METHOD_BLOWFISH:
		return blowfishEncrypt(src, c.block)
	case METHOD_RC4:
		return rc4Encrypt(src, c.key)
	}
	return nil, fmt.Errorf("crypt.Encrypt unknown cipher method %d", c.method)
}

func (c Crypt) Decrypt(src []byte) ([]byte, error) {
	switch c.method {
	case METHOD_AES:
		return aesDecrypt(src, c.key, c.iv, c.block, c.mode, c.padding)
	case METHOD_DES, METHOD_DES3:
		return desDecrypt(src, c.key, c.iv, c.block, c.mode, c.padding, c.method == METHOD_DES3)
	case METHOD_CHACHA20:
		return chacha20Decrypt(src, c.key, c.iv)
	case METHOD_BLOWFISH:
		return blowfishDecrypt(src, c.block)
	case METHOD_RC4:
		return rc4Decrypt(src, c.key)
	}
	return nil, fmt.Errorf("crypt.Decrypt unknown cipher method %d", c.method)
}

func verifyKey(method CipherMethod, key []byte) ([]byte, error) {
	var limit = map[CipherMethod][]int{
		METHOD_AES:      {32, 24, 16},
		METHOD_DES:      {8},
		METHOD_DES3:     {24},
		METHOD_CHACHA20: {32},
		METHOD_BLOWFISH: {56},
		METHOD_RC4:      {256},
	}
	var length = len(key)
	for _, n := range limit[method] {
		if n == length {
			break
		} else if length > n {
			key = key[:n]
			break
		}
	}
	length = len(key)
	switch method {
	case METHOD_BLOWFISH, METHOD_RC4:
		if length < 1 || length > limit[method][0] {
			return nil, fmt.Errorf("crypt %s: invalid key size %d", method, length)
		}
	default:
		if !inSliceInt(length, limit[method]) {
			return nil, fmt.Errorf("crypt %s: invalid key size %d", method, length)
		}
	}
	return key, nil
}

func genSaltHeader(password []byte, blockSize int, mode BlockMode, keySize int) (header [16]byte, key, iv []byte) {
	var salt = genSalt()
	var size = keySize
	// 8 Bytes: Salted__
	copy(header[:], append([]byte(saltedText), salt[:]...))
	if mode.Has(MODE_GCM) {
		size += gcmStandardNonceSize
	} else if mode.Not(MODE_ECB) {
		size += blockSize
	}
	key, iv = bytesToKey(salt, password, keySize, size)
	return
}

func parseSaltHeader(salt [saltTextByteSize]byte, password []byte, blockSize int, mode BlockMode, keySize int) (key, iv []byte) {
	var size = keySize
	if mode.Has(MODE_GCM) {
		size += gcmStandardNonceSize
	} else if mode.Not(MODE_ECB) {
		size += blockSize
	}
	key, iv = bytesToKey(salt, password, keySize, size)
	return
}

func bytesToKey(salt [saltTextByteSize]byte, password []byte, keySize, minimum int) (key, iv []byte) {
	a := append(password, salt[:]...)
	b := MD5.Sum(a)
	c := append([]byte{}, b...)
	for len(c) < minimum {
		b = MD5.Sum(append(b, a...))
		c = append(c, b...)
	}
	key = c[:keySize]
	iv = c[keySize:minimum]
	return
}

func getSalt(src []byte) (salt [saltTextByteSize]byte, ok bool) {
	if len(src) >= 16 && bytes.Equal([]byte(saltedText), src[:8]) {
		copy(salt[:], src[8:16])
		ok = true
	}
	return
}

func genSalt() (salt [saltTextByteSize]byte) {
	copy(salt[:], randBytes(saltTextByteSize))
	return
}

func inSliceInt(i int, s []int) bool {
	for _, v := range s {
		if v == i {
			return true
		}
	}
	return false
}
