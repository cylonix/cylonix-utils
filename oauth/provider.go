// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package oauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
)

type Config struct {
	Provider          string   `json:"provider"` // e.g. "google", "apple", "wechat".
	ConfigURL         string   `json:"config_url"`
	RedirectURI       string   `json:"redirect_uri"`
	LogoutURI         string   `json:"logout_uri"`
	LogoutRedirectURI string   `json:"logout_redirect_uri"`
	Scopes            []string `json:"scopes,omitempty"` // Scopes to request, e.g. "openid", "profile", "email".
	ClientID          string   `json:"client_id"`
	ClientSecret      string   `json:"client_secret"`
	TeamID            string   `json:"team_id,omitempty"` // For Apple Sign In.
	KeyID             string   `json:"key_id,omitempty"`  // For Apple Sign In.
	WebAuthSuccessURI string   `json:"web_auth_success_uri"`
	WebAuthFailURI    string   `json:"web_auth_fail_uri"`
	AppAuthSuccessURI string   `json:"app_auth_success_uri"`
	AppAuthFailURI    string   `json:"app_auth_fail_uri"`
}

type User struct {
	Namespace       string
	Provider        string
	UserID          string
	LoginName       string
	DisplayName     string
	Email           string
	EmailVerified   bool
	IsPrivateEmail  bool // If email is private, e.g. Apple Sign In.
	Phone           string
	PhoneVerified   bool
	ProfilePicURL   string
	IsSysAdmin      bool     // Don't set it other than KeyCloakAdminLogin.
	AdminNamespaces []string // Namespace user has admin permission on.
	Roles           []string
	Attributes      map[string][]string
}

func (u *User) Verified() bool {
	switch u.Provider {
	case KeyCloakAdminLogin:
		return true
	case KeyCloakUserLogin:
		return true
	case SignInWithWeChat:
		return true
	default:
		return u.EmailVerified
	}
}

const (
	KeyCloakAdminLogin  = "keycloak-admin"
	KeyCloakUserLogin   = "keycloak-user"
	SignInWithApple     = "apple"
	SignInWithGithub    = "github"
	SignInWithGoogle    = "google"
	SignInWithMicrosoft = "microsoft"
	SignInWithWeChat    = "wechat"
)

type Session struct {
	Provider   string
	Namespace  string
	Code       string
	Username   string
	Password   string
	RawIDToken string
	Logger     *logrus.Entry
}

type Provider interface {
	Config(namespace string) *Config

	// Get user for the oauth session. If provider specifically indicates that
	// the user is not found or the code is incorrect, return ErrUnauthorized so
	// that caller can tell if it is a glitch or actually user is unauthorized.
	User(*Session) (*User, error)
}

func (c *Config) OidcProvider() (*oidc.Provider, error) {
	ctx := context.Background()
	return oidc.NewProvider(ctx, c.ConfigURL)
}

func (c *Config) oauth2Config(provider *oidc.Provider) (*oauth2.Config, error) {
	if err := updateAppleJWTIfNeeded(c); err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       append(c.Scopes, oidc.ScopeOpenID),
	}, nil
}

func (c *Config) AuthCodeURL(state string) (string, error) {
	// Get oauth2 config.
	op, err := c.OidcProvider()
	if err != nil {
		return "", fmt.Errorf("failed to get oidc provider from %v: %w", c.ConfigURL, err)
	}
	oauth2Config, err := c.oauth2Config(op)
	if err != nil {
		return "", fmt.Errorf("failed to get oauth2 config: %w", err)
	}
	var options []oauth2.AuthCodeOption
	if c.Provider == SignInWithApple {
		options = []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam("response_mode", "form_post"),
		}
	}
	authCodeURL := oauth2Config.AuthCodeURL(state, options...)
	return authCodeURL, nil
}

func (c *Config) claims(code, username, password, rawIDToken string, claims interface{}, logger *logrus.Entry) error {
	// Get oauth2 config.
	log := logger.WithField("username", username)
	log.Debugln("Oauth claims login.")
	op, err := c.OidcProvider()
	if err != nil {
		return fmt.Errorf("failed to get oidc provider from %v: %w", c.ConfigURL, err)
	}
	oauth2Config, err := c.oauth2Config(op)
	if err != nil {
		return fmt.Errorf("failed to get oauth2 config: %w", err)
	}
	ctx := context.Background()

	log.Debugln("Oauth claims login. Exchange token or login with password.")

	// Get raw ID token if necessary.
	ok := false
	if rawIDToken == "" {
		// Exchange code to token or password login.
		var oauth2Token *oauth2.Token
		if code != "" {
			oauth2Token, err = oauth2Config.Exchange(ctx, code)
		} else if password != "" {
			oauth2Token, err = oauth2Config.PasswordCredentialsToken(ctx, username, password)
			log.WithError(err).Debugln("Oauth password login result.")
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUnauthorized, err)
		}
		rawIDToken, ok = oauth2Token.Extra("id_token").(string)
		if !ok {
			return errors.New("failed to extract raw ID token")
		}
	}

	// Verify token.
	oidcVerifierConfig := &oidc.Config{
		ClientID:          c.ClientID,
		SkipClientIDCheck: true, // App use different client IDs.
	}
	verifier := op.Verifier(oidcVerifierConfig)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return err
	}
	// Debug print verified idToken claims
	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		log.WithError(err).Errorln("Failed to extract raw claims")
	} else {
		log.WithField("raw_claims", rawClaims).Debugln("ID token claims")
	}
	if err := idToken.Claims(claims); err != nil {
		return err
	}
	return nil
}
