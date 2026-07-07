package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const refreshTokenBytes = 32

func GenerateRefreshToken() (plaintext, hash string, err error) {
	b := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generating refresh token: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(b)
	return plaintext, HashRefreshToken(plaintext), nil
}

func HashRefreshToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
