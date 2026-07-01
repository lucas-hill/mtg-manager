package auth

import (
	"context"

	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

type UserStore interface {
	CreateUserWithPassword(ctx context.Context, email, name, passwordHash string) (store.User, error)
	GetPasswordIdentityByEmail(ctx context.Context, email string) (store.User, string, error)
}

type Service struct {
	store UserStore
}

func NewService(s UserStore) *Service {
	return &Service{store: s}
}
