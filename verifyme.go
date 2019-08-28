package signme

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

type rsaPublicKey struct {
	*rsa.PublicKey
}

// A Unsigner is can create signatures that verify against a public key.
type Unsigner interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Unsign(data []byte, sig []byte) error
}

// verify signed message, return true if ok
func VerifyMessage(signedMessage, message, pathToPublicKey string) (bool, error) {
	parser, perr := loadPublicKey(pathToPublicKey)
	if perr != nil {
		return false, fmt.Errorf("could not sign request: %v", perr.Error())
	}

	signed, _ := base64.StdEncoding.DecodeString(signedMessage)
	err := parser.Unsign([]byte(message), signed)
	if err != nil {
		return false, fmt.Errorf("could not sign request: %v", err.Error())
	}
	return true, nil
}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPublicKey(path string) (Unsigner, error) {
	var data []byte
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(data)
}

// parsePublicKey parses a PEM encoded private key.
func parsePublicKey(pemBytes []byte) (Unsigner, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "PUBLIC KEY":
		rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}

	return newUnsignerFromKey(rawkey)
}

// Unsign verifies the message using a rsa-sha256 signature
func (r *rsaPublicKey) Unsign(message []byte, sig []byte) error {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, d, sig)
}
