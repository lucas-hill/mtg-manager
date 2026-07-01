package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

func TestLoginSuccess(t *testing.T) {
	hash, _ := HashPassword("hunter2")
	fake := &fakeStore{loginUser: store.User{ID: "u1"}, loginHash: hash}
	svc := NewService(fake)

	user, err := svc.Login(context.Background(), "alice@e.com", "hunter2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.ID != "u1" {
		t.Fatalf("expected user u1, got %+v", user)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	hash, _ := HashPassword("hunter2")
	fake := &fakeStore{loginUser: store.User{ID: "u1"}, loginHash: hash}
	svc := NewService(fake)

	_, err := svc.Login(context.Background(), "alice@e.com", "WRONG")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLoginUnknownUserIsIndistinguishable(t *testing.T) {
	fake := &fakeStore{loginErr: store.ErrUserNotFound}
	svc := NewService(fake)

	_, err := svc.Login(context.Background(), "nobody@e.com", "hunter2")
	// Same error as wrong-password: an attacker cannot tell the difference.
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}
