package httpx

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucas-hill/mtg-manager/auth/internal/auth"
)

type fakeAuth struct {
	result auth.AuthResult
	err    error
}

func (f *fakeAuth) Signup(ctx context.Context, email, name, password string) (auth.AuthResult, error) {
	return f.result, f.err
}

func (f *fakeAuth) Login(ctx context.Context, email, password string) (auth.AuthResult, error) {
	return f.result, f.err
}

func doPost(t *testing.T, srv *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}
