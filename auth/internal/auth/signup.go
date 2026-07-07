package auth

import (
	"context"
	"fmt"
)

func (svc *Service) Signup(ctx context.Context, email, name, password string) (AuthResult, error) {
	hash, err := HashPassword(password)
	if err != nil {
		return AuthResult{}, fmt.Errorf("hashing password: %w", err)
	}

	user, err := svc.store.CreateUserWithPassword(ctx, email, name, hash)
	if err != nil {
		return AuthResult{}, err
	}

	return svc.issueTokens(ctx, user)
}
