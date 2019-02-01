package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

func main() {
	encryptRet, err := Encrypt("aaafffffffffffff", "000000000000000", "test")
	if err != nil {
		fmt.Printf("加密出错:%v\n", err)
	}
	fmt.Printf("%v\n", hex.EncodeToString(encryptRet))

	DecryptRet, err := Decrypt("aaafffffffffffff", "000000000000000", "a0666833")
	if err != nil {
		fmt.Printf("解密出错:%v\n", err)
	}
	fmt.Printf("%v\n", DecryptRet)

}

//加密字符串
func Encrypt(key string, iv string, str string) ([]byte, error) {
	encrypted := make([]byte, len(str))
	aesBlockEncrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, []byte(iv)[:aes.BlockSize])
	aesEncrypter.XORKeyStream(encrypted, []byte(str))
	return encrypted, nil
}

//解密字符串
func Decrypt(key string, iv string, str string) (out string, err error) {

	waitDecryptText, err := hex.DecodeString(str)
	decrypted := make([]byte, len(waitDecryptText))

	var aesBlockDecrypter cipher.Block
	aesBlockDecrypter, err = aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, []byte(iv)[:aes.BlockSize])
	aesDecrypter.XORKeyStream(decrypted, []byte(waitDecryptText))
	return string(decrypted), nil
}
