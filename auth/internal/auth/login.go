package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

var ErrInvalidCredentials = errors.New("invalid email or password")

func (svc *Service) Login(ctx context.Context, email, password string) (store.User, error) {
	user, hash, err := svc.store.GetPasswordIdentityByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			return store.User{}, err
		}
		return store.User{}, fmt.Errorf("looking up identity: %w", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		return store.User{}, fmt.Errorf("verifying password: %w", err)
	}
	if !ok {
		return store.User{}, ErrInvalidCredentials
	}

	return user, nil
}
