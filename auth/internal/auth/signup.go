package auth

import (
	"context"
	"fmt"

	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

func (svc *Service) Signup(ctx context.Context, email, name, password string) (store.User, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return store.User{}, fmt.Errorf("hashing password: %w", err)
	}

	user, err := svc.store.CreateUserWithPassword(ctx, email, name, hash)
	if err != nil {
		return store.User{}, err
	}

	return user, nil
}
