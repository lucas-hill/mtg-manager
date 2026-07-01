package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrEmailTaken   = errors.New("email already registerd")
)

type User struct {
	ID        string
	Email     string
	Name      string
	CreatedAt time.Time
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	const query = `
		SELECT
			id
			,email
			,name
			,created_at
		FROM users
		WHERE email = $1`

	var u User
	err := s.db.QueryRow(ctx, query, email).Scan(&u.ID, &u.Email, &u.Name, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("get user by email: %w", err)
	}

	return u, nil
}

func (s *Store) CreateUser(ctx context.Context, email, name string) (User, error) {
	const query = `
		INSERT INTO users(email, name)
		VALUES ($1, $2)
		RETURNING id, email, name, created_at
		`

	var u User
	err := s.db.QueryRow(ctx, query, email, name).Scan(&u.ID, &u.Email, &u.Name, &u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError

		// 23505 = unique_violation; here it can only be the email UNIQUE index.
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return User{}, ErrEmailTaken
		}

		return User{}, fmt.Errorf("create user: %w", err)
	}

	return u, nil
}

func (s *Store) CreateUserWithPassword(ctx context.Context, email, name, passwordHash string) (User, error) {
	var user User
	err := s.WithTx(ctx, func(tx *Store) error {
		u, err := tx.CreateUser(ctx, email, name)
		if err != nil {
			return err
		}
		if _, err := tx.CreatePasswordIdentity(ctx, u.ID, passwordHash); err != nil {
			return err
		}
		user = u
		return nil
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) GetPasswordIdentityByEmail(ctx context.Context, email string) (User, string, error) {
	const query = `
		SELECT u.id, u.email, u.name, u.created_at, i.password_hash
		FROM users u
		JOIN identities i ON i.user_id = u.id
		WHERE u.email = $1 AND i.provider = 'password'
		`

	var u User
	var hash string
	err := s.db.QueryRow(ctx, query, email).Scan(&u.ID, &u.Email, &u.Name, &u.CreatedAt, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, "", ErrUserNotFound
		}
		return User{}, "", err
	}
	return u, hash, nil
}
