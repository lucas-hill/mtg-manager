package httpx

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lucas-hill/mtg-manager/auth/internal/auth"
	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

func TestLoginHandlerSuccess(t *testing.T) {
	svc := &fakeAuth{result: auth.AuthResult{
		User:         store.User{ID: "u1", Email: "a@e.com", Name: "Alice"},
		AccessToken:  "acc.tok",
		RefreshToken: "ref.tok",
	}}
	rec := doPost(t, NewServer(svc), "/login", `{"email":"a@e.com","password":"hunter2"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body)
	}
	var resp authResponse
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.AccessToken != "acc.tok" || resp.RefreshToken != "ref.tok" {
		t.Fatalf("unexpected body: %+v", resp)
	}
}

func TestLoginHandlerInvalidCredentials(t *testing.T) {
	rec := doPost(t, NewServer(&fakeAuth{err: auth.ErrInvalidCredentials}), "/login", `{"email":"a@e.com","password":"wrong"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestLoginHandlerMissingPassword(t *testing.T) {
	rec := doPost(t, NewServer(&fakeAuth{}), "/login", `{"email":"a@e.com"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
