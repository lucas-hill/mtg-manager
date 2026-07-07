package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucas-hill/mtg-manager/auth/internal/auth"
	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

func do(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/signup", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestSignupHandlerSuccess(t *testing.T) {
	svc := &fakeAuth{result: auth.AuthResult{
		User:         store.User{ID: "u1", Email: "a@e.com", Name: "Alice"},
		AccessToken:  "acc.tok",
		RefreshToken: "ref.tok",
	}}
	rec := do(t, NewServer(svc), `{"email":"a@e.com","name":"Alice","password":"hunter2"}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", rec.Code, rec.Body)
	}
	var resp authResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.AccessToken != "acc.tok" || resp.RefreshToken != "ref.tok" || resp.User.ID != "u1" {
		t.Fatalf("unexpected body: %+v", resp)
	}
}

func TestSignupHandlerDuplicateEmail(t *testing.T) {
	svc := &fakeAuth{err: store.ErrEmailTaken}
	rec := do(t, NewServer(svc), `{"email":"a@e.com","name":"Alice","password":"hunter2"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rec.Code)
	}
}

func TestSignupHandlerBadJSON(t *testing.T) {
	rec := do(t, NewServer(&fakeAuth{}), `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestSignupHandlerMissingPassword(t *testing.T) {
	rec := do(t, NewServer(&fakeAuth{}), `{"email":"a@e.com","name":"Alice"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
