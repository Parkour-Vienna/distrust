package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func genkey() {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	out := x509.MarshalPKCS1PrivateKey(priv)
	log.Fatal(pem.Encode(os.Stdout, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: out,
	}))
}
