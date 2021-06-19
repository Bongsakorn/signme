package signme

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSignHEX(t *testing.T) {
	payload := `{"message":"I am an engineer"}`

	createdTime := time.Now()
	timestamp := strconv.FormatInt(createdTime.Unix(), 10)
	nonceUUID, _ := uuid.NewUUID()
	nonce := strings.Replace(nonceUUID.String(), "-", "", -1)
	messageToSign := timestamp + nonce + string(payload)
	signature, errSign := SignMessage(messageToSign, "private_key.pem", "hex")
	if errSign != nil {
		fmt.Println(errSign.Error())
	}

	fmt.Printf("X-Authentication-Nonce: %s\n", nonce)
	fmt.Printf("X-Authentication-Timestamp: %s\n", timestamp)
	fmt.Printf("X-Authentication-Sign: %s\n", signature)

	if ok, errVerify := verify(signature, messageToSign, "public_key.pem", "hex"); !ok {
		if errVerify != nil {
			t.Error(errVerify.Error())
			return
		}
	}

	fmt.Println("Verify OK")
}

func TestSignBase64(t *testing.T) {
	payload := `{"message":"I am an engineer"}`

	createdTime := time.Now()
	timestamp := strconv.FormatInt(createdTime.Unix(), 10)
	messageToSign := timestamp + string(payload)
	signature, errSign := SignMessage(messageToSign, "private_key.pem", "base64")
	if errSign != nil {
		fmt.Println(errSign.Error())
	}

	fmt.Printf("X-Authentication-Timestamp: %s\n", timestamp)
	fmt.Printf("X-Authentication-Sign: %s\n", signature)

	sig := StrToMap(signature)

	if ok, errVerify := verify(sig["data"].(string), messageToSign, "public_key.pem", "base64"); !ok {
		if errVerify != nil {
			t.Error(errVerify.Error())
			return
		}
	}

	fmt.Println("Verify OK")
}

func StrToMap(in string) map[string]interface{} {
	res := make(map[string]interface{})
	array := strings.Split(in, ";")
	temp := make([]string, 2)
	for _, val := range array {
		temp = strings.SplitN(string(val), "=", 2)
		res[strings.Trim(temp[0], " ")] = temp[1]
	}
	return res
}
