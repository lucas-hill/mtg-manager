package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	const pw = "correct horse battery staple"

	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	t.Logf("encoded hash: %s", hash)

	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}

	ok, err := VerifyPassword(pw, hash)
	if err != nil || !ok {
		t.Fatalf("correct password should verify: ok=%v err=%v", ok, err)
	}

	ok, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("verify wrong: unexpected err %v", err)
	}
	if ok {
		t.Fatal("wrong password must NOT verify")
	}

	// Two hashes of the same password must differ (random salt each time).
	hash2, _ := HashPassword(pw)
	if hash == hash2 {
		t.Fatal("two hashes of same password were identical (salt not random?)")
	}
}
