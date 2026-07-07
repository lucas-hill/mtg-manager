package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

var ErrInvalidCredentials = errors.New("invalid email or password")

// dummyHash is a prcomputed argon2 hash. When no user is found we verify the supplied password against the dummy hash.
// This makes the timing for returning there is no user an dther is a wrong password check equal so an attacker cannot distinguish the errors
var dummyHash string

func init() {
	h, err := HashPassword("timing-equalization-placeholder")
	if err != nil {
		panic(fmt.Sprintf("auth: precomputing dummy hash failed: %v", err))
	}
	dummyHash = h
}

func (svc *Service) Login(ctx context.Context, email, password string) (AuthResult, error) {
	user, hash, err := svc.store.GetPasswordIdentityByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			// This spends the same time as a real verification then fails
			_, _ = VerifyPassword(password, dummyHash)
			return AuthResult{}, err
		}
		return AuthResult{}, fmt.Errorf("looking up identity: %w", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		return AuthResult{}, fmt.Errorf("verifying password: %w", err)
	}
	if !ok {
		return AuthResult{}, ErrInvalidCredentials
	}

	return svc.issueTokens(ctx, user)
}
