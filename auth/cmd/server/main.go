package main

import (
	"context"
	"log"
	"net/http"

	"github.com/lucas-hill/mtg-manager/auth/internal/auth"
	"github.com/lucas-hill/mtg-manager/auth/internal/config"
	"github.com/lucas-hill/mtg-manager/auth/internal/httpx"
	"github.com/lucas-hill/mtg-manager/auth/internal/store"
	"github.com/lucas-hill/mtg-manager/auth/internal/tokens"
)

const issuer = "mtg-auth"

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	tm, err := tokens.New(cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath, issuer, cfg.AccessTokenTTL)
	if err != nil {
		log.Fatalf("tokens: %v", err)
	}

	svc := auth.NewService(st, tm, cfg.RefreshTokenTTL)
	srv := httpx.NewServer(svc)

	addr := ":" + cfg.Port
	log.Printf("auth service listening on %s", addr)
	if err := http.ListenAndServe(addr, srv.Routes()); err != nil {
		log.Fatalf("server: %v", err)
	}
}
