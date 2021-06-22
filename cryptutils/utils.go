package cryptutils

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
)

func KeyID(pub rsa.PublicKey) string {
	der := x509.MarshalPKCS1PublicKey(&pub)
	h := crypto.SHA256.New()
	h.Write(der)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))[:32]
}
