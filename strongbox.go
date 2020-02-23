package strongbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
)

// StrongBox is used to encrypt and decrypt
type StrongBox struct {
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey

	Password string

	Base64 bool
}

// New create a StrongBox pointer
// publicKey, privateKey public & private key's files
// Ruby default params
// :base64 => false
// :symmetric => :always
func New(publicKey, privateKey, password string, base64 bool) (*StrongBox, error) {
	pub, err := ioutil.ReadFile(publicKey)
	if err != nil {
		return nil, err
	}

	priv, err := ioutil.ReadFile(privateKey)
	if err != nil {
		return nil, err
	}

	return NewWithData(string(pub), string(priv), password, base64)
}

// NewWithData creates a strongbox with string content keys
func NewWithData(pub, priv, password string, base64 bool) (*StrongBox, error) {
	pubBlock, _ := pem.Decode([]byte(pub))
	if pubBlock == nil {
		return nil, fmt.Errorf("invalid public key: %s", pub)
	}
	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %s, err: %s", pub, err.Error())
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("may be Go has something wrong")
	}

	privBlock, _ := pem.Decode([]byte(priv))
	if pubBlock == nil {
		return nil, fmt.Errorf("invalid private key: %s", priv)
	}

	if x509.IsEncryptedPEMBlock(privBlock) {
		privBlock.Bytes, err = x509.DecryptPEMBlock(privBlock, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("wrong password[%s] for private key[%s], err: %s", password, priv, err.Error())
		}
	}

	privKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %s, err: %s", priv, err.Error())
	}

	return &StrongBox{
		PublicKey:  pubKey,
		PrivateKey: privKey,

		Password: password,

		Base64: base64,
	}, nil
}

// RSAEncrypt encrypts a []byte use RSA
// Ruby strongbox:
// encrypt_with_public_key :symmetric => :never
func (s *StrongBox) RSAEncrypt(data []byte) ([]byte, error) {
	output, err := rsa.EncryptPKCS1v15(rand.Reader, s.PublicKey, data)
	if err != nil {
		return nil, err
	}

	if s.Base64 {
		buf := make([]byte, base64.StdEncoding.EncodedLen(len(output)))
		base64.StdEncoding.Encode(buf, output)
		return buf, nil
	}
	return output, nil
}

// RSADecrypt decrypts a []byte use RSA
func (s *StrongBox) RSADecrypt(data []byte) ([]byte, error) {
	var (
		text []byte
		err  error
	)

	if s.Base64 {
		text = make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(text, data)
		if err != nil {
			return nil, err
		}
		text = text[:n]
	} else {
		text = data
	}

	output, err := rsa.DecryptPKCS1v15(rand.Reader, s.PrivateKey, text)
	if err != nil {
		return nil, err
	}
	return output, nil
}

// CBCEncrypt encrypts a []byte use AES-256-CBC
// Ruby strongbox:
// encrypt_with_public_key :symmetric => :always
// retrun encrypt data, key, iv, error
func (s *StrongBox) CBCEncrypt(data []byte) ([]byte, []byte, []byte, error) {
	key, iv := make([]byte, aes.BlockSize*2), make([]byte, aes.BlockSize)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, nil, nil, err
	}

	padded, err := pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		return nil, nil, nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(padded, padded)

	key, err = s.RSAEncrypt(key)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err = s.RSAEncrypt(iv)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.Base64 {
		buf := make([]byte, base64.StdEncoding.EncodedLen(len(padded)))
		base64.StdEncoding.Encode(buf, padded)
		padded = buf
	}
	return padded, key, iv, nil
}

// CBCDecrypt decrypts a []byte use AES-256-CBC
func (s *StrongBox) CBCDecrypt(data, key, iv []byte) ([]byte, error) {
	var (
		text []byte
		err  error
	)

	if s.Base64 {
		text = make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(text, data)
		if err != nil {
			return nil, err
		}
		text = text[:n]
	} else {
		text = data
	}

	if len(text) == 0 || len(text)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid blocksize(%v), aes.BlockSize = %v", len(text), aes.BlockSize)
	}

	keyDc, err := s.RSADecrypt(key)
	if err != nil {
		return nil, err
	}
	ivDc, err := s.RSADecrypt(iv)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(keyDc)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(c, ivDc)
	cbc.CryptBlocks(text, text)
	if text, err = pkcs7Unpad(text, aes.BlockSize); err != nil {
		return nil, err
	}

	return text, nil
}

// pkcs7Pad appends padding.
func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// pkcs7Unpad returns slice of the original data without padding.
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padlen], nil
}
