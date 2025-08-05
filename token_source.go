package serveforme

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sethvargo/go-githubactions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

// TokenSource is an interface that defines a method to get an ID token.
type TokenSource interface {
	// Get retrieves the ID token for the given context.
	Get(ctx context.Context) (string, error)
}

// WithIDToken is a client option that sets the ID token for the client.
func WithIDToken(token string) ClientOption {
	return func(o *clientOptions) {
		o.tokenSource = staticTokenSource(token)
	}
}

// WithGitHubActions is a client option that configures the client to use GitHub Actions for authentication.
func WithGitHubActions() ClientOption {
	return func(o *clientOptions) {
		o.tokenSource = GitHubActions{}
	}
}

// WithGoogleIDToken is a client option that configures the client to use Google ID tokens for authentication.
func WithGoogleIDToken() ClientOption {
	return func(o *clientOptions) {
		o.tokenSource = GoogleIDToken{}
	}
}

type staticTokenSource string

func (s staticTokenSource) Get(ctx context.Context) (string, error) {
	return string(s), nil
}

// GitHubActions is a TokenSource that retrieves ID tokens from GitHub Actions.
type GitHubActions struct{}

// Get implements TokenSource.
func (GitHubActions) Get(ctx context.Context) (string, error) {
	return githubactions.GetIDToken(ctx, ClientID)
}

// GoogleIDToken is a TokenSource that retrieves Google ID tokens.
type GoogleIDToken struct{}

// Get implements TokenSource.
func (GoogleIDToken) Get(ctx context.Context) (string, error) {
	creds, err := google.FindDefaultCredentials(ctx, "openid")
	if err != nil {
		return "", fmt.Errorf("failed to find default credentials: %w", err)
	}

	// Try human user ID token.
	var conf struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(creds.JSON, &conf); err == nil && conf.Type == "authorized_user" {
		token, err := exchangeGoogleRefreshForIDToken(ctx, creds)
		if err != nil {
			return "", fmt.Errorf("failed to get google user ID token: %w", err)
		}
		return token, nil
	}

	// Try machine user ID token (GCP Service Account).
	ts, err := idtoken.NewTokenSource(ctx, ClientID)
	if err != nil {
		return "", fmt.Errorf("failed to create GCP service account token source: %w", err)
	}
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get token for GCP service account: %w", err)
	}
	return tok.AccessToken, nil
}

func exchangeGoogleRefreshForIDToken(ctx context.Context, creds *google.Credentials) (string, error) {
	var u struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
		Type         string `json:"type"`
	}
	if err := json.Unmarshal(creds.JSON, &u); err != nil {
		return "", fmt.Errorf("failed to unmarshal user google credentials: %w", err)
	}
	cfg := &oauth2.Config{
		ClientID:     u.ClientID,
		ClientSecret: u.ClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{"openid"},
	}
	src := cfg.TokenSource(ctx, &oauth2.Token{
		RefreshToken: u.RefreshToken,
	})
	tok, err := src.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get google user ID token: %w", err)
	}
	return tok.Extra("id_token").(string), nil
}
