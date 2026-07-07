package httpx

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/lucas-hill/mtg-manager/auth/internal/auth"
	"github.com/lucas-hill/mtg-manager/auth/internal/store"
)

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeAuthError maps domain errors to HTTP statuses. Unknown errors become 500
// with a generic message so internal details never leak to clients.
func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrEmailTaken):
		writeError(w, http.StatusConflict, "email already registered")
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, "invalid email or password")
	default:
		log.Printf("unhandled auth error: %+v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}
