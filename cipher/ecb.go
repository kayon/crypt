package cipher

import (
	"crypto/cipher"
)

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (ecb *ecbEncrypter) BlockSize() int { return ecb.blockSize }

func (ecb *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%ecb.blockSize != 0 {
		panic("crypt/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypt/cipher: output smaller than input")
	}
	for len(src) > 0 {
		ecb.b.Encrypt(dst, src[:ecb.blockSize])
		src = src[ecb.blockSize:]
		dst = dst[ecb.blockSize:]
	}
}

type ecbDecrypter ecb

func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (ecb *ecbDecrypter) BlockSize() int { return ecb.blockSize }

func (ecb *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%ecb.blockSize != 0 {
		panic("crypt/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypt/cipher: output smaller than input")
	}
	for len(src) > 0 {
		ecb.b.Decrypt(dst, src[:ecb.blockSize])
		src = src[ecb.blockSize:]
		dst = dst[ecb.blockSize:]
	}
}
