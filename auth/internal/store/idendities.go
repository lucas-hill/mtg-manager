package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgconn"
)

var ErrIdentityExists = errors.New("identity already exists for this provider")

type Identity struct {
	ID           string
	UserID       string
	Provider     string
	ProficerID   *string
	PasswordHash *string
	CreatedAt    time.Time
}

func (s *Store) CreatePasswordIdentity(ctx context.Context, userID, passwordHash string) (Identity, error) {
	const query = `
		INSERT INTO identities (user_id, provider, password_hash)
		VALUES( $1, 'password', $2)
		RETURNING id, user_id, provider, provider_id, password_hash, created_at`

	var idn Identity
	err := s.db.QueryRow(ctx, query, userID, passwordHash).
		Scan(&idn.ID, &idn.UserID, &idn.Provider, &idn.PasswordHash, &idn.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Identity{}, ErrIdentityExists
		}
		return Identity{}, fmt.Errorf("create password identity: %w", err)
	}

	return idn, nil
}
