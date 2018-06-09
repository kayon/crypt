package crypt

import (
	"crypto/rand"
	mrand "math/rand"
	"time"
)

func init() {
	mrand.Seed(time.Now().UnixNano())
}

func randBytes(size int) (r []byte) {
	r = make([]byte, size)
	n, err := rand.Read(r)
	if err != nil || n != size {
		mrand.Read(r)
	}
	return
}
