package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	DatabaseURL       string
	Port              string
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
}

func Load() (*Config, error) {
	databaseURL := os.Getenv("DATABSE_URL")
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	privPath := os.Getenv("JWT_PRIVATE_KEY_PATH")
	if privPath == "" {
		privPath = "keys/ed25519_private.pem"
	}

	pubPath := os.Getenv("JWT_PUBLIC_KEY_PATH")
	if pubPath == "" {
		pubPath = "keys/ed25519_public.pem"
	}

	accessTTL, err := durationFromEnv("ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return nil, err
	}

	refreshTTL, err := durationFromEnv("REFRESH_TOKEN_TTL", 30*24*time.Hour)
	if err != nil {
		return nil, err
	}

	return &Config{
		DatabaseURL:       databaseURL,
		Port:              port,
		JWTPrivateKeyPath: privPath,
		JWTPublicKeyPath:  pubPath,
		AccessTokenTTL:    accessTTL,
		RefreshTokenTTL:   refreshTTL,
	}, nil
}

func durationFromEnv(key string, def time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return def, nil
	}

	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", key, err)
	}

	return d, nil
}
