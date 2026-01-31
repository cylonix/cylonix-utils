// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type OAuth struct {
	config Config
}

var (
	wellKnownOAuthProviders = map[string]string {
		SignInWithGoogle:    "https://accounts.google.com",
		SignInWithApple:     "https://appleid.apple.com",
		SignInWithMicrosoft: "https://login.microsoftonline.com/common/v2.0",
		SignInWithGithub:    "https://token.actions.githubusercontent.com",
		SignInWithWeChat:    "https://open.weixin.qq.com",
	}
)
func IssuerURLToProvider(issuerURL string) string {
	for provider, url := range wellKnownOAuthProviders {
		if issuerURL == url {
			return provider
		}
	}
	return ""
}

func NewOAuth(config Config) (Provider, error) {
	if config.ClientID == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("invalid %v auth config", config.Provider)
	}
	config.RedirectURI = strings.TrimSuffix(config.RedirectURI, "/")
	if config.ConfigURL == "" {
		switch config.Provider {
		case SignInWithApple:
			config.ConfigURL = wellKnownOAuthProviders[SignInWithApple]
		case SignInWithGithub:
			config.ConfigURL = wellKnownOAuthProviders[SignInWithGithub]
		case SignInWithGoogle:
			config.ConfigURL = wellKnownOAuthProviders[SignInWithGoogle]
		case SignInWithMicrosoft:
			config.ConfigURL = wellKnownOAuthProviders[SignInWithMicrosoft]
		case SignInWithWeChat:
			config.ConfigURL = wellKnownOAuthProviders[SignInWithWeChat]
		default:
			return nil, fmt.Errorf("missing config URL for provider %v", config.Provider)
		}
	}
	config.Scopes = []string{"profile", "email"}
	if config.Provider == SignInWithApple {
		if err := setAppleConfig(&config); err != nil {
			return nil, err
		}
	}
	return &OAuth{
		config: config,
	}, nil
}

func (o *OAuth) Config(Namespace string) *Config {
	return &o.config
}

func (o *OAuth) User(s *Session) (*User, error) {
	claims := &Claims{}
	err := o.Config(s.Namespace).claims(s.Code, s.Username, s.Password, s.RawIDToken, claims, s.Logger)
	if err != nil {
		return nil, err
	}
	return claims.User(s.Namespace, s.Provider), nil
}

type Claims struct {
	UserID         string `json:"sub"`
	Name           string `json:"name"`
	Email          string `json:"email"`
	EmailVerified  bool   `json:"email_verified"`
	Picture        string `json:"picture"`
	IsPrivateEmail bool   `json:"is_private_email"` // Private relay email if user chose private email
}

func generatePseudoName(userID string) string {
    // Create SHA-256 hash of the entire userID
    hasher := sha256.New()
    hasher.Write([]byte(userID))
    hash := hex.EncodeToString(hasher.Sum(nil))

    // Take first 12 characters for a good balance of uniqueness and readability
    shortHash := hash[:12]
    return shortHash
}

func (c *Claims) User(namespace, provider string) *User {
	userID := c.UserID
	email := c.Email

	// Apple login with phone number based ID may not have email at all.
	// Let's generate a unique login name based on userID instead.
	loginName := email
	if loginName == "" {
		loginName = generatePseudoName(userID)+"@"+provider
	}

	return &User{
		Namespace:     namespace,
		Provider:      provider,
		UserID:        provider + userID,
		DisplayName:   c.Name,
		LoginName:     loginName,
		Email:         email,
		EmailVerified: c.EmailVerified,
		ProfilePicURL: c.Picture,
		IsPrivateEmail: c.IsPrivateEmail,
	}
}
