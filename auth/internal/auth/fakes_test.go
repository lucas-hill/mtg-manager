package auth

import (
	"context"

	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

// fakeStore satisfies UserStore without a database, for unit tests.
type fakeStore struct {
	// CreateUserWithPassword behavior
	returnedUser store.User
	returnedErr  error
	gotHash      string
	called       bool
	// GetPasswordIdentityByEmail behavior
	loginUser store.User
	loginHash string
	loginErr  error
}

func (f *fakeStore) CreateUserWithPassword(ctx context.Context, email, name, passwordHash string) (store.User, error) {
	f.called = true
	f.gotHash = passwordHash
	return f.returnedUser, f.returnedErr
}

func (f *fakeStore) GetPasswordIdentityByEmail(ctx context.Context, email string) (store.User, string, error) {
	return f.loginUser, f.loginHash, f.loginErr
}
