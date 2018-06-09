package crypt

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestAES(t *testing.T) {
	key := []byte(`15234c27ef5da06b`)
	var c *Crypt
	var err error
	var ciphertext, plaintext []byte
	var text = []byte("hello")

	for mode := MODE_CBC; mode <= MODE_ECB; mode++ {
		for pad := PAD_PKCS7; pad < PAD_NOPADDING; pad ++ {
			p := pad
			if mode.Not(MODE_CBC, MODE_ECB) {
				p = PAD_NOPADDING
			}
			if c, err = newCrypt(METHOD_AES, key, nil, Options{Mode: mode, Padding: pad}); err != nil {
				t.Fatal(err)
			}
			if ciphertext, err = c.Encrypt(text); err != nil {
				t.Fatal(err)
			}
			if plaintext, err = c.Decrypt(ciphertext); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, text) {
				t.Fatalf("AES wrong, mode: %s, padding: %s", mode, p)
			} else {
				t.Logf("AES OK, mode: %s, padding: %s\n", mode, p)
			}
			if mode.Not(MODE_CBC, MODE_ECB) {
				break
			}
		}
	}
}

func TestDES(t *testing.T) {
	key := []byte(`15234c27`)
	var c *Crypt
	var err error
	var ciphertext, plaintext []byte
	var text = []byte("hello")

	for mode := MODE_CBC; mode <= MODE_ECB; mode++ {
		if mode.Has(MODE_GCM) {
			continue
		}
		for pad := PAD_PKCS7; pad < PAD_NOPADDING; pad ++ {
			p := pad
			if mode.Not(MODE_CBC, MODE_ECB) {
				p = PAD_NOPADDING
			}
			if c, err = newCrypt(METHOD_DES, key, nil, Options{Mode: mode, Padding: pad}); err != nil {
				t.Fatal(err)
			}
			if ciphertext, err = c.Encrypt(text); err != nil {
				t.Fatal(err)
			}
			if plaintext, err = c.Decrypt(ciphertext); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, text) {
				t.Fatalf("DES wrong, mode: %s, padding: %s", mode, p)
			} else {
				t.Logf("DES OK, mode: %s, padding: %s\n", mode, p)
			}
			if mode.Not(MODE_CBC, MODE_ECB) {
				break
			}
		}
	}
}

func TestDES3(t *testing.T) {
	key := []byte(`15234c2715234c2715234c27`)
	var c *Crypt
	var err error
	var ciphertext, plaintext []byte
	var text = []byte("hello")

	for mode := MODE_CBC; mode <= MODE_ECB; mode++ {
		if mode.Has(MODE_GCM) {
			continue
		}
		for pad := PAD_PKCS7; pad < PAD_NOPADDING; pad ++ {
			p := pad
			if mode.Not(MODE_CBC, MODE_ECB) {
				p = PAD_NOPADDING
			}
			if c, err = newCrypt(METHOD_DES3, key, nil, Options{Mode: mode, Padding: pad}); err != nil {
				t.Fatal(err)
			}
			if ciphertext, err = c.Encrypt(text); err != nil {
				t.Fatal(err)
			}
			if plaintext, err = c.Decrypt(ciphertext); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, text) {
				t.Fatalf("DES3 wrong, mode: %s, padding: %s", mode, p)
			} else {
				t.Logf("DES3 OK, mode: %s, padding: %s\n", mode, p)
			}
			if mode.Not(MODE_CBC, MODE_ECB) {
				break
			}
		}
	}
}

func TestChaCha20(t *testing.T) {
	key := randBytes(32)
	iv := randBytes(24)
	var c *Crypt
	var err error
	var ciphertext, plaintext []byte
	var text = []byte("hello chacha20")

	if c, err = NewChaCha20(key, iv); err != nil {
		t.Fatal(err)
	}
	if ciphertext, err = c.Encrypt(text); err != nil {
		t.Fatal(err)
	}
	if plaintext, err = c.Decrypt(ciphertext); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, text) {
		t.Fatalf("ChaCha20 wrong")
	} else {
		t.Logf("ChaCha20 OK\n")
	}

	// random nonce
	for i := 0; i < 10; i++ {
		if ciphertext, err = ChaCha20.Encrypt(text, key, nil); err != nil {
			t.Fatal(err)
		}
		if plaintext, err = ChaCha20.Decrypt(ciphertext, key, nil); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plaintext, text) {
			t.Fatalf("ChaCha20 wrong")
		}
		t.Logf("base64 %s = %s\n", base64.StdEncoding.EncodeToString(ciphertext), plaintext)
	}
}

func TestBlowfish(t *testing.T) {
	key := []byte{1, 2, 3}
	var c *Crypt
	var err error
	var ciphertext, plaintext []byte
	var text = []byte("hello blowfish")

	if c, err = NewBlowfish(key); err != nil {
		t.Fatal(err)
	}
	if ciphertext, err = c.Encrypt(text); err != nil {
		t.Fatal(err)
	}
	t.Logf("plain: %d %v\n", len(text), text)
	t.Logf("cipher: %d %v\n", len(ciphertext), ciphertext)
	t.Logf("base64: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
	if plaintext, err = c.Decrypt(ciphertext); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, text) {
		t.Fatalf("Blowfish wrong")
	} else {
		t.Logf("Blowfish OK\n")
	}
}

func TestRC4(t *testing.T) {
	key := []byte("123")
	var err error
	var ciphertext, plaintext []byte
	var text = []byte("hello")

	if ciphertext, err = RC4.Encrypt(text, key); err != nil {
		t.Fatal(err)
	}
	t.Logf("plain: %d %v\n", len(text), text)
	t.Logf("cipher: %d %v\n", len(ciphertext), ciphertext)
	t.Logf("base64: %s\n", base64.StdEncoding.EncodeToString(ciphertext))

	if plaintext, err = RC4.Decrypt(ciphertext, key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, text) {
		t.Fatalf("RC4 wrong")
	} else {
		t.Logf("RC4 OK\n")
	}
}

func TestMD5(t *testing.T) {
	if MD5.Hex([]byte("123")) != "202cb962ac59075b964b07152d234b70" {
		t.Fatalf("MD5 wrong")
	}
}

func TestSha3(t *testing.T) {
	t.Logf("SHA3 Shake128: %v\n", SHA3.Shake128([]byte("123"), 32))
}
