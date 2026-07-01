package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

func TestSignupHashesAndDelegates(t *testing.T) {
	fake := &fakeStore{returnedUser: store.User{ID: "u1", Email: "alice@e.com"}}
	svc := NewService(fake)

	user, err := svc.Signup(context.Background(), "alice@e.com", "Alice", "hunter2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != "u1" {
		t.Fatalf("expected user u1, got %+v", user)
	}
	if !fake.called {
		t.Fatal("store was never called")
	}
	if fake.gotHash == "hunter2" {
		t.Fatal("plaintext password reached the store!")
	}
	if !strings.HasPrefix(fake.gotHash, "$argon2id$") {
		t.Fatalf("store did not receive an argon2 hash: %q", fake.gotHash)
	}
	ok, err := VerifyPassword("hunter2", fake.gotHash)
	if err != nil || !ok {
		t.Fatalf("hash handed to store does not verify: ok=%v err=%v", ok, err)
	}
}

func TestSignupPropagatesStoreError(t *testing.T) {
	fake := &fakeStore{returnedErr: store.ErrEmailTaken}
	svc := NewService(fake)

	_, err := svc.Signup(context.Background(), "alice@e.com", "Alice", "hunter2")
	if !errors.Is(err, store.ErrEmailTaken) {
		t.Fatalf("expected ErrEmailTaken to propagate, got %v", err)
	}
}
