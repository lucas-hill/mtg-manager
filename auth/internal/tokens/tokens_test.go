package tokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genKeyFiles writes a fresh Ed25519 keypair to temp PEM files.
func genKeyFiles(t *testing.T) (privPath, pubPath string) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	privPath = filepath.Join(dir, "priv.pem")
	pubPath = filepath.Join(dir, "pub.pem")
	os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600)
	os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644)
	return privPath, pubPath
}

func TestSignAndVerify(t *testing.T) {
	priv, pub := genKeyFiles(t)
	m, err := New(priv, pub, "mtg-auth", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := m.Sign("user-123")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("token: %s", tok)

	sub, err := m.Verify(tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if sub != "user-123" {
		t.Fatalf("expected subject user-123, got %q", sub)
	}
}

func TestVerifyRejectsTampered(t *testing.T) {
	priv, pub := genKeyFiles(t)
	m, _ := New(priv, pub, "mtg-auth", 15*time.Minute)
	tok, _ := m.Sign("user-123")
	tampered := tok[:len(tok)-4] + "AAAA" // corrupt the signature
	if _, err := m.Verify(tampered); err == nil {
		t.Fatal("tampered token must NOT verify")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	priv, pub := genKeyFiles(t)
	m, _ := New(priv, pub, "mtg-auth", -1*time.Minute) // already expired
	tok, _ := m.Sign("user-123")
	if _, err := m.Verify(tok); err == nil {
		t.Fatal("expired token must NOT verify")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	priv1, pub1 := genKeyFiles(t)
	_, pub2 := genKeyFiles(t)
	signer, _ := New(priv1, pub1, "mtg-auth", 15*time.Minute)
	tok, _ := signer.Sign("user-123")

	// verifier holds pub2, which does NOT match the key that signed
	verifier, _ := New(priv1, pub2, "mtg-auth", 15*time.Minute)
	if _, err := verifier.Verify(tok); err == nil {
		t.Fatal("token must NOT verify under a different public key")
	}
}
