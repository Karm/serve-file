package main

import (
	"encoding/base64"
	"io/ioutil"
)

func getBase64(path string) string {
	fileBytes, _ := ioutil.ReadFile(path)
	return base64.StdEncoding.EncodeToString(fileBytes)
}
