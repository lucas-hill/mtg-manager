package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	dir := "keys"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fail("creating key dir", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fail("generating key", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fail("marshaling private key", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fail("marshaling public key", err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	privPath := filepath.Join(dir, "ed25519_private.pem")
	pubPath := filepath.Join(dir, "ed25519_public.pem")

	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		fail("writing private key", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		fail("writing public key", err)
	}

	fmt.Printf("wrote:\n %s (SECRET - never commit)\n %s (safe to share)\n", privPath, pubPath)
}

func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, "genkeys: %s: %v\n", msg, err)
	os.Exit(1)
}
