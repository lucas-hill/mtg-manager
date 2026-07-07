package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrRefreshTokenNotFound = errors.New("refresh token not found")

type RefreshToken struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

func (s *Store) CreateRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (RefreshToken, error) {
	const query = `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES($1, $2, $3)
		RETURNING id, user_id, expires_at, revoked_at, created_at
		`

	var rt RefreshToken
	err := s.db.QueryRow(ctx, query, userID, tokenHash, expiresAt).Scan(&rt.ID, &rt.UserID, &rt.ExpiresAt, &rt.RevokedAt, &rt.CreatedAt)
	if err != nil {
		return RefreshToken{}, fmt.Errorf("create refresh token: %w", err)
	}

	return rt, nil
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (RefreshToken, error) {
	const query = `
		SELECT id, user_id, expires_at, revoked_at, expires_at
		FROM refresh_tokens
		WHERE token_hash = $1
		`

	var rt RefreshToken
	err := s.db.QueryRow(ctx, query, tokenHash).Scan(&rt.ID, &rt.UserID, &rt.ExpiresAt, &rt.RevokedAt, &rt.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RefreshToken{}, ErrRefreshTokenNotFound
		}
		return RefreshToken{}, fmt.Errorf("get refresh token")
	}

	return rt, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	const query = `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL
		`

	if _, err := s.db.Exec(ctx, query, tokenHash); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}

	return nil
}

func (s *Store) RevokeAllForUser(context context.Context, userID string) error {
	const query = `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE user_id = $1
		`
	if _, err := s.db.Exec(context, query, userID); err != nil {
		return fmt.Errorf("revoking all user refresh tokens: %w", err)
	}

	return nil
}
