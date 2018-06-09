# crypt
A simple Go library for cryptographic

## Simple example
```
import "github.com/kayon/crypt"

func main() {

    ...

    c, err := crypt.NewAES(key, nil)
    if err != nil {
        ...
    }
    ciphertext, err := c.Encrypt(plaintext)


    // shortcut
    ciphertext, err := crypt.AES.Encrypt(plaintext, key, nil, crypt.Options{Mode: crypt.MODE_CBC, Padding: crypt.PAD_ANSIX923})

}
```

## List of methods

**AES**

```
NewAES(key, iv []byte, args ...Options) (*Crypt, error)
```

**DES**

```
NewDES(key, iv []byte, args ...Options) (*Crypt, error)
```

**Triple DES**

```
NewDES3(key, iv []byte, args ...Options) (*Crypt, error)
```

**ChaCha20**

```
NewChaCha20(key, iv []byte）(*Crypt, error)
```

**Blowfish**

```
NewBlowfish(key[]byte) (*Crypt, error)
```

**RC4**

```
NewRC4(key []byte) (*Crypt, error)
```

#### Crypt

```
(Crypt) Encrypt(plaintext []byte) (ciphertext []byte, err error)

(Crypt) Decrypt(ciphertext []byte) (plaintext []byte, err error)
```

## Shortcut
**AES**

* AES.Encrypt(plaintext, key, iv []byte, args ...Options) ([]byte, error)

* AES.Decrypt(ciphertext, key, iv []byte, args ...Options) ([]byte, error)

**DES**

* DES.Encrypt(plaintext, key, iv []byte, args ...Options) ([]byte, error)

* DES.Decrypt(ciphertext, key, iv []byte, args ...Options) ([]byte, error)

**DES3**

* DES3.Encrypt(plaintext, key, iv []byte, args ...Options) ([]byte, error)

* DES3.Decrypt(ciphertext, key, iv []byte, args ...Options) ([]byte, error)

**ChaCha20**

* ChaCha20.Encrypt(plaintext, key, iv []byte) ([]byte, error)

* ChaCha20.Decrypt(ciphertext, key, iv []byte) ([]byte, error)

**Blowfish**

* Blowfish.Encrypt(plaintext, key []byte) ([]byte, error)

* Blowfish.Decrypt(ciphertext, key []byte) ([]byte, error)

**RC4**

* RC4.Encrypt(plaintext, key []byte) ([]byte, error)

* RC4.Decrypt(ciphertext, key []byte) ([]byte, error)

**MD5**

* MD5.Sum(plaintext []byte) []byte

* MD5.Hex(plaintext []byte) string


**Sha3**

* Sha3.Sum224(data []byte) []byte

* Sha3.Sum256(data []byte) []byte

* Sha3.Sum384(data []byte) []byte

* Sha3.Sum512(data []byte) []byte

* Sha3.Shake128(data []byte, size int) (hash []byte)

* Sha3.Shake256(data []byte, size int) (hash []byte)


## Options.Mode
*block cipher mode*

* **MODE_CBC** *default*

  `CBC` Cipher-block chaining

* **MODE_CFB**

  `CFB` Cipher feedback</font>

* **MODE_CTR**

  `CTR` Counter mode

* **MODE_OFB**

  `OFB` Output feedback

* **MODE_GCM**

  `GCM` Galois/Counter Mod

* **MODE_ECB**

  `ECB` Electronic codebook

## Options.Padding

* **PAD_PKCS7** *default*

  PKCS#7 RFC 5652

* **PAD_ISO97971**

  ISO/IEC 9797-1 Padding Method 2

* **PAD_ANSIX923**

  ANSI X.923

* **PAD_ISO10126**

  ISO 10126

* **PAD_ZEROPADDING**

  Zero padding

* **PAD_NOPADDING**


