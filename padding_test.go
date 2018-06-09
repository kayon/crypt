package crypt

import (
	"bytes"
	"testing"
)

func TestPKCS7(t *testing.T) {
	var data = []byte{1, 2, 3, 4, 5}
	var blockSize = 8

	padded, err := PKCS7Padding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded[5:], []byte{3, 3, 3}) {
		t.Fatal("PKCS7: wrong padding")
	}

	data = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	padded, err = PKCS7Padding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded[8:], []byte{8, 8, 8, 8, 8, 8, 8, 8}) {
		t.Fatalf("PKCS7: wrong padding")
	}

	unpad, err := PKCS7UnPadding(padded, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpad, data) {
		t.Fatalf("PKCS7: wrong unpadding")
	}
}

func TestZeroPadding(t *testing.T) {
	var data = []byte{1, 2, 3, 4, 5}
	var blockSize = 8

	padded, err := ZeroPadding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded[5:], []byte{0, 0, 0}) {
		t.Fatal("ZeroPadding: wrong padding")
	}

	data = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	padded, err = ZeroPadding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded[8:], []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("ZeroPadding: wrong padding")
	}

	unpad, err := ZeroUnPadding(padded, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpad, data) {
		t.Fatalf("ZeroPadding: wrong unpadding")
	}
}

func TestISO97971(t *testing.T) {
	var data = []byte{1, 2, 3, 4, 5}
	var blockSize = 8

	padded, err := ISO97971Padding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded[5:], []byte{128, 0, 0}) {
		t.Fatalf("ISO97971: wrong padding")
	}

	data = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	padded, err = ISO97971Padding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded[8:], []byte{128, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("ISO97971: wrong padding")
	}

	unpad, err := ISO97971UnPadding(padded, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpad, data) {
		t.Fatalf("ISO97971: wrong unpadding")
	}
}

func TestAnsiX923(t *testing.T) {
	var data = []byte{1, 2, 3, 4, 5}
	var blockSize = 8

	padded, err := AnsiX923Padding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded[5:], []byte{0, 0, 3}) {
		t.Fatalf("AnsiX923: wrong padding")
	}

	data = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	padded, err = AnsiX923Padding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded[8:], []byte{0, 0, 0, 0, 0, 0, 0, 8}) {
		t.Fatalf("AnsiX923: wrong padding")
	}

	unpad, err := AnsiX923UnPadding(padded, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpad, data) {
		t.Fatalf("AnsiX923: wrong unpadding")
	}
}

func TestISO10126(t *testing.T) {
	var data = []byte{1, 2, 3, 4, 5}
	var blockSize = 8

	padded, err := ISO10126Padding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if padded[7] != 3 {
		t.Fatalf("ISO10126: wrong padding")
	}

	data = []byte{1, 2, 3, 4, 5, 6, 7, 8}
	padded, err = ISO10126Padding(data, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if padded[15] != 8 {
		t.Fatalf("ISO10126: wrong padding")
	}

	unpad, err := ISO10126UnPadding(padded, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unpad, data) {
		t.Fatalf("ISO10126: wrong unpadding")
	}
}
