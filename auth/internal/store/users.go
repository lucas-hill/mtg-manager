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

type CreateUserParams struct {
	Name  string
	Email string
}

func (s *Store) Createuser(ctx context.Context, params CreateUserParams) (User, error) {
	const query = `
		INSERT INTO users(email, name)
		VALUES ($1, $2)
		RETURNING id, email, name, created_at
		`

	var u User
	err := s.db.QueryRow(ctx, query, params.Email, params.Name).Scan(&u.ID, &u.Email, &u.Name, &u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgErr
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return User{}, ErrEmailTaken
		}

		return User{}, fmt.Errorf("create user: %w", err)
	}

	return u, nil
}
