package signme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"golang.org/x/crypto/pkcs12"
)

type rsaPrivateKey struct {
	*rsa.PrivateKey
}

// A Signer is can create signatures that verify against a public key.
type Signer interface {
	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(data []byte) ([]byte, error)
}

// SignMessage TODO
func SignMessage(message, pathToPrivateKey, format string) (string, error) {
	signer, err := loadPrivateKey(pathToPrivateKey)
	if err != nil {
		return "", err
	}
	signedMessage, err := signer.Sign([]byte(message))
	if err != nil {
		return "", err
	}

	switch format {
	case "base64":
		signKey := base64.StdEncoding.EncodeToString(signedMessage)
		return fmt.Sprintf("digest-alg=RSA-SHA;key-id=KEY:RSA:rsf.org;data=%s", signKey), nil
	case "hex":
		signKey := hex.EncodeToString(signedMessage)
		return fmt.Sprintf("%s", string(signKey)), nil
	default:
		signKey := base64.StdEncoding.EncodeToString(signedMessage)
		return fmt.Sprintf("digest-alg=RSA-SHA;key-id=KEY:RSA:rsf.org;data=%s", signKey), nil
	}

}

// loadPrivateKey loads an parses a PEM encoded private key file.
func loadPrivateKey(path string) (Signer, error) {
	var data []byte
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	extension := filepath.Ext(path)
	switch extension[1:] {
	case "pem":
		return parsePrivateKey(data)
	case "p12":
		return parsePkcs12Key(data)
	default:
		return parsePrivateKey(data)
	}
}

// parsePublicKey parses a PEM encoded private key.
func parsePrivateKey(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	var rawkey interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawkey = rsa
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
	return newSignerFromKey(rawkey)
}

func parsePkcs12Key(keyBytes []byte) (Signer, error) {
	password := ""
	privk, _, err := pkcs12.Decode(keyBytes, password)
	if err != nil {
		return nil, errors.New("ssh: no key found")
	}
	pv := privk.(*rsa.PrivateKey)

	return newSignerFromKey(pv)
}

func newSignerFromKey(k interface{}) (Signer, error) {
	var sshKey Signer
	switch t := k.(type) {
	case *rsa.PrivateKey:
		sshKey = &rsaPrivateKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

func newUnsignerFromKey(k interface{}) (Unsigner, error) {
	var sshKey Unsigner
	switch t := k.(type) {
	case *rsa.PublicKey:
		sshKey = &rsaPublicKey{t}
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}
	return sshKey, nil
}

// Sign signs data with rsa-sha256
func (r *rsaPrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, d)
}
