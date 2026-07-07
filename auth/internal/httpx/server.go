package httpx

import (
	"context"
	"net/http"

	"github.com/lucas-hill/mtg-manager/auth/internal/auth"
)

type AuthService interface {
	Signup(ctx context.Context, email, name, password string) (auth.AuthResult, error)
	Login(ctx context.Context, email, password string) (auth.AuthResult, error)
}

type Server struct {
	auth AuthService
}

func NewServer(a AuthService) *Server {
	return &Server{auth: a}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /signup", s.handleSignup)
	mux.HandleFunc("POST /login", s.handleLogin)
	return mux
}
