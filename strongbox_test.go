package strongbox

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestRSA(t *testing.T) {
	s, err := New(filepath.Join("keys", "public.pem"), filepath.Join("keys", "private.pem"), "boost facile", true)
	if err != nil {
		t.Fatalf("new a strongbox should be successed, but got an error: %s\n", err.Error())
	}

	// data from https://github.com/spikex/strongbox encrypt
	data := []byte(`ntQtR7MWYLfJ00udZITlP5wmnsE9tYzzlwWhXBum22DW3kjCzCHoZH7RKl0+1taKXMfsDSuylOjPSrwR3iapEStPdLnefhYafIUztnsnP43fjXMJsNm4FZitfVq4bTxBnJ8SRZnN3ATtdECfmyGjuTQviHN/kUhFKVVYuXTVaLY=`)
	output, err := s.RSADecrypt(data)
	if err != nil {
		t.Fatalf("rsa decrypt should be successed, but got an error: %s\n", err.Error())
	}

	expected := []byte("Shhhh")
	if !bytes.Equal(output, expected) {
		t.Fatalf("rsa decrypt expected[%s], but got[%s]\n", expected, output)
	}

	encrypt, err := s.RSAEncrypt(expected)
	if err != nil {
		t.Fatalf("rsa encrypt should be successed, but got an error: %s\n", err.Error())
	}

	output, err = s.RSADecrypt(encrypt)
	if err != nil {
		t.Fatalf("rsa decrypt should be successed, but got an error: %s\n", err.Error())
	}

	if !bytes.Equal(output, expected) {
		t.Fatalf("rsa decrypt expected[%s], but got[%s]\n", expected, output)
	}

	s.Base64 = false
	encrypt, err = s.RSAEncrypt(expected)
	if err != nil {
		t.Fatalf("rsa encrypt should be successed, but got an error: %s\n", err.Error())
	}

	output, err = s.RSADecrypt(encrypt)
	if err != nil {
		t.Fatalf("rsa decrypt should be successed, but got an error: %s\n", err.Error())
	}

	if !bytes.Equal(output, expected) {
		t.Fatalf("rsa decrypt expected[%s], but got[%s]\n", expected, output)
	}
}

func TestRSANoPassword(t *testing.T) {
	s, err := New(filepath.Join("keys", "np_public.pem"), filepath.Join("keys", "np_private.pem"), "", true)
	if err != nil {
		t.Fatalf("new a strongbox should be successed, but got an error: %s\n", err.Error())
	}

	data := []byte(`M71jFZPjm1Xtpeii2ZTr683PamO+YOvEKIVLJCsYLodBtww1f8C/rt/TELCFIip46FS5upzE2nhg+Jh5IALi75BenDuHGNnHnmJgieIhn/eKAR3vkqGTxZppTFPYACP9XmW/kMyNZDukaDnhjF+M8jBAkVDBQIf94i1HydVl8A4=`)
	output, err := s.RSADecrypt(data)
	if err != nil {
		t.Fatalf("rsa decrypt should be successed, but got an error: %s\n", err.Error())
	}

	expected := []byte("suchuangji@gmail.com")
	if !bytes.Equal(output, expected) {
		t.Fatalf("rsa decrypt expected[%s], but got[%s]\n", expected, output)
	}

	encrypt, err := s.RSAEncrypt(expected)
	if err != nil {
		t.Fatalf("rsa encrypt should be successed, but got an error: %s\n", err.Error())
	}

	output, err = s.RSADecrypt(encrypt)
	if err != nil {
		t.Fatalf("rsa decrypt should be successed, but got an error: %s\n", err.Error())
	}

	if !bytes.Equal(output, expected) {
		t.Fatalf("rsa decrypt expected[%s], but got[%s]\n", expected, output)
	}

	s.Base64 = false
	encrypt, err = s.RSAEncrypt(expected)
	if err != nil {
		t.Fatalf("rsa encrypt should be successed, but got an error: %s\n", err.Error())
	}

	output, err = s.RSADecrypt(encrypt)
	if err != nil {
		t.Fatalf("rsa decrypt should be successed, but got an error: %s\n", err.Error())
	}

	if !bytes.Equal(output, expected) {
		t.Fatalf("rsa decrypt expected[%s], but got[%s]\n", expected, output)
	}
}

func TestCBC(t *testing.T) {
	s, err := New(filepath.Join("keys", "public.pem"), filepath.Join("keys", "private.pem"), "boost facile", true)
	if err != nil {
		t.Fatalf("new a strongbox should be successed, but got an error: %s\n", err.Error())
	}

	// data from https://github.com/spikex/strongbox encrypt
	data := []byte(`vHhGqwGZQbR2naewHsKvfQ==`)
	key := []byte(`kERVX82TC4SbBrlmpbBQuIvjvwNefLMJUv9ITEUlYGniwna35nvgw+HcAwIpPH3sAVbkrOPDLTSGMOuOTfgVZZxNuEnKBUYot46jz6LNIw1QgIRn2ZHIYwJpFW0awtF9U5INgJ7xPOfTx2Q714IDgkf0IWCegSosZJRGB9JRjjY=`)
	iv := []byte(`X5Eb5dBTmZ0r+ggVGQR9g/jfXuFc87KzvEYmH8UyA0w0DhIc2GEL134oabgvuUyIHZNqOJZzmQZ2hyfd8UIDFW96Z0TCPcCVfZVRUOLsAHYaxHi/JMm7wZTlBSjoc1TEAHYPEQbTj27ozhQ+X4Gk0ignpI7wVWQNfE7gB+ttUR4=`)

	output, err := s.CBCDecrypt(data, key, iv)
	if err != nil {
		t.Fatalf("cbc decrypt should be successed, but got an error: %s\n", err.Error())
	}

	expected := []byte("Shhhh")
	if !bytes.Equal(output, expected) {
		t.Fatalf("cbc decrypt expected[%s], but got[%s]\n", expected, output)
	}

	encrypt, key, iv, err := s.CBCEncrypt(expected)
	if err != nil {
		t.Fatalf("cbc encrypt should be successed, but got an error: %s\n", err.Error())
	}

	output, err = s.CBCDecrypt(encrypt, key, iv)
	if err != nil {
		t.Fatalf("cbc decrypt should be successed, but got an error: %s\n", err.Error())
	}

	s.Base64 = false
	encrypt, key, iv, err = s.CBCEncrypt(expected)
	if err != nil {
		t.Fatalf("cbc encrypt should be successed, but got an error: %s\n", err.Error())
	}

	output, err = s.CBCDecrypt(encrypt, key, iv)
	if err != nil {
		t.Fatalf("cbc decrypt should be successed, but got an error: %s\n", err.Error())
	}
}
