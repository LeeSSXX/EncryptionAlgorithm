package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

type AesFun struct {
	key  string
	iv   string
	text string
}

func (s *AesFun) init(key string, iv string, text string) {
	s.key = key
	s.iv = iv
	s.text = text
}

func (s *AesFun) PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize //需要padding的数目
	//只要少于256就能放到一个byte中，默认的blockSize=16(即采用16*8=128, AES-128长的密钥)
	//最少填充1个byte，如果原文刚好是blocksize的整数倍，则再填充一个blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding) //生成填充的文本
	return append(ciphertext, padtext...)
}

func (s *AesFun) PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func (s *AesFun) ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding) //用0去填充
	return append(ciphertext, padtext...)
}

func (s *AesFun) ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		})
}

func (s *AesFun) NewCBCEncrypter() {

	//秘钥长度需要时AES-128(16bytes)或者AES-256(32bytes)
	key := []byte(s.key)

	//原文必须填充至blocksize的整数倍
	plaintext := []byte(s.text)

	plaintext = s.ZeroPadding(plaintext, aes.BlockSize)

	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := []byte(s.iv)[:aes.BlockSize]

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	fmt.Printf("%x\n", ciphertext)
}
func (s *AesFun) NewCBCDecrypter() {
	key := []byte(s.key)
	ciphertext, _ := hex.DecodeString(s.text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := []byte(s.iv)
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks可以原地更新
	mode.CryptBlocks(ciphertext, ciphertext)

	fmt.Printf("%s\n", ciphertext)
}

func (s *AesFun) NewCFBEncrypter(key string, iv string, str string) ([]byte, error) {
	encrypted := make([]byte, len(str))
	aesBlockEncrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, []byte(iv)[:aes.BlockSize])
	aesEncrypter.XORKeyStream(encrypted, []byte(str))
	return encrypted, nil
}

func (s *AesFun) NewCFBDecrypter(key string, iv string, str string) (out string, err error) {

	waitKey, err := hex.DecodeString(key)
	waitIV, err := hex.DecodeString(iv)
	waitStr, err := hex.DecodeString(str)

	decrypted := make([]byte, len(waitKey))

	var aesBlockDecrypter cipher.Block
	aesBlockDecrypter, err = aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, []byte(waitIV)[:aes.BlockSize])
	aesDecrypter.XORKeyStream(decrypted, []byte(waitStr))
	return string(decrypted), nil
}

func main() {
	var operAES AesFun
	operAES.init("3fffa6b4", "3fffa6c4", "a1b0a2ec5ebbec8e130060894a878a85")
	//operAES.NewCBCEncrypter()
	operAES.NewCBCDecrypter()

}
