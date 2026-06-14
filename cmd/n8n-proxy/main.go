package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yangs1202/n8n-gw/internal/config"
	"github.com/yangs1202/n8n-gw/internal/httpserver"
	"github.com/yangs1202/n8n-gw/internal/logging"
	"github.com/yangs1202/n8n-gw/internal/n8n"
	oidcclient "github.com/yangs1202/n8n-gw/internal/oidc"
	"github.com/yangs1202/n8n-gw/internal/session"
	"github.com/yangs1202/n8n-gw/internal/vault"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("load config failed", "error", err)
		os.Exit(1)
	}

	logger := logging.New(cfg.LogLevel)
	slog.SetDefault(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sessionStore := session.NewRedisStore(cfg.RedisURL, cfg.SessionTTL, cfg.OIDCStateTTL)
	vaultStore, err := vault.NewStore(ctx, cfg.VaultAddr, vault.AuthConfig{
		Token:    cfg.VaultToken,
		RoleID:   cfg.VaultRoleID,
		SecretID: cfg.VaultSecretID,
	}, cfg.VaultKVMount, cfg.VaultKVPrefix)
	if err != nil {
		logger.Error("create vault store failed", "error", err)
		os.Exit(1)
	}

	oidcProvider, err := oidcclient.New(ctx, oidcclient.Config{
		IssuerURL:    cfg.OIDCIssuerURL,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		Scopes:       cfg.OIDCScopes,
		RedirectURL:  cfg.PublicBaseURL.JoinPath("/auth/callback").String(),
	})
	if err != nil {
		logger.Error("create oidc client failed", "error", err)
		os.Exit(1)
	}

	n8nClient := n8n.NewClient(cfg.N8NUpstreamURL, cfg.ConsoleProxyTimeout)

	app := httpserver.New(httpserver.Dependencies{
		Config:       cfg,
		Logger:       logger,
		Sessions:     sessionStore,
		Credentials:  vaultStore,
		OIDC:         oidcProvider,
		N8N:          n8nClient,
		PublicProxy:  nil,
		ConsoleProxy: nil,
	})

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting n8n proxy", "addr", cfg.ListenAddr, "public_base_url", cfg.PublicBaseURL.String(), "upstream", cfg.N8NUpstreamURL.String())
		errCh <- server.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("http server failed", "error", err)
			os.Exit(1)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown failed", "error", err)
		os.Exit(1)
	}
}
