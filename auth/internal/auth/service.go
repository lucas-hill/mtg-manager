package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/lucas-hill/mtg-manager/auth/internal/store"
	"github.com/lucas-hill/mtg-manager/auth/internal/tokens"
)

type UserStore interface {
	CreateUserWithPassword(ctx context.Context, email, name, passwordHash string) (store.User, error)
	GetPasswordIdentityByEmail(ctx context.Context, email string) (store.User, string, error)
	CreateRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (store.RefreshToken, error)
}

type TokenSigner interface {
	Sign(userID string) (string, error)
}

type AuthResult struct {
	User         store.User
	AccessToken  string
	RefreshToken string
}

type Service struct {
	store      UserStore
	signer     TokenSigner
	refreshTTL time.Duration
}

func NewService(s UserStore, signer TokenSigner, refreshTTL time.Duration) *Service {
	return &Service{store: s, signer: signer, refreshTTL: refreshTTL}
}

func (svc *Service) issueTokens(ctx context.Context, user store.User) (AuthResult, error) {
	access, err := svc.signer.Sign(user.ID)
	if err != nil {
		return AuthResult{}, fmt.Errorf("signing the token: %w", err)
	}

	refreshPlain, refreshHash, err := tokens.GenerateRefreshToken()
	if err != nil {
		return AuthResult{}, fmt.Errorf("generating refresh token: %w", err)
	}

	expiresAt := time.Now().Add(svc.refreshTTL)
	if _, err := svc.store.CreateRefreshToken(ctx, user.ID, refreshHash, expiresAt); err != nil {
		return AuthResult{}, fmt.Errorf("storing refresh token: %w", err)
	}

	return AuthResult{User: user, AccessToken: access, RefreshToken: refreshPlain}, nil
}
