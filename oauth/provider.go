// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
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
	ClientSecretFile  string   `json:"client_secret_file,omitempty"`
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

func (c *Config) isGithub() bool {
	return c.ConfigURL == wellKnownOAuthProviders[SignInWithGithub]
}

func (c *Config) oauth2Config(provider *oidc.Provider) (*oauth2.Config, error) {
	if err := updateAppleJWTIfNeeded(c); err != nil {
		return nil, err
	}
	endpoint := provider.Endpoint()
	scopes := append(c.Scopes, oidc.ScopeOpenID)
	// Github uses a non-standard OAuth2 endpoint.
	if c.isGithub() {
		endpoint = github.Endpoint
		scopes = []string{"read:user", "user:email"}
	}
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURI,
		Endpoint:     endpoint,
		Scopes:       scopes,
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

func (c *Config) exchangeForToken(
	ctx context.Context, oauth2Config *oauth2.Config,
	code, username, password string,
	log *logrus.Entry,
) (string, *oauth2.Token, error) { // __CYLONIX_MOD__ also return the oauth2 token for the userinfo fetch
	// Exchange code to token or password login.
	var oauth2Token *oauth2.Token
	var err error
	if code != "" {
		oauth2Token, err = oauth2Config.Exchange(ctx, code)
	} else if password != "" {
		oauth2Token, err = oauth2Config.PasswordCredentialsToken(ctx, username, password)
		log.WithError(err).Debugln("Oauth password login result.")
	}
	if err != nil {
		return "", nil, fmt.Errorf("%w: failed to get token: %v", ErrUnauthorized, err)
	}

	// For github, we need to use the access token to get the id information.
	if c.isGithub() {
		v, err := fetchGithubUserInfo(ctx, oauth2Config, oauth2Token, log)
		if err != nil {
			return "", nil, err
		}
		return string(v), oauth2Token, nil
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", nil, errors.New("failed to extract raw ID token")
	}
	return rawIDToken, oauth2Token, nil
}

// enrichClaimsFromUserInfo backfills claims that the ID token did not carry
// from the provider's userinfo endpoint. Spec-compliant IdPs (e.g. the
// Nextcloud "OIDC Identity Provider" app since 2.x) only assert profile and
// email claims via userinfo unless the client explicitly requests them in the
// ID token; without this fetch such logins arrive with an empty email, which
// breaks email-keyed identity matching and custom-provider admin-email
// verification.
//
// A missing or failing userinfo endpoint is non-fatal (the ID token remains
// the source of truth); a userinfo "sub" that does not match the verified ID
// token's "sub" is an error per OIDC Core 5.3.2 — the response must not be
// used, as it could splice another account's attributes into this identity.
func (c *Config) enrichClaimsFromUserInfo(
	ctx context.Context, op *oidc.Provider, oauth2Token *oauth2.Token,
	idTokenSubject string, cl *Claims, log *logrus.Entry,
) error {
	userInfo, err := op.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		// Not all providers expose a userinfo endpoint; keep ID token claims.
		log.WithError(err).Debugln("Userinfo fetch failed; using ID token claims only.")
		return nil
	}
	if userInfo.Subject != idTokenSubject {
		return fmt.Errorf("userinfo subject %q does not match ID token subject %q",
			userInfo.Subject, idTokenSubject)
	}
	extra := &Claims{}
	if err := userInfo.Claims(extra); err != nil {
		log.WithError(err).Debugln("Failed to parse userinfo claims; using ID token claims only.")
		return nil
	}
	if cl.Email == "" && userInfo.Email != "" {
		cl.Email = userInfo.Email
		cl.EmailVerified = userInfo.EmailVerified
	}
	if cl.Name == "" {
		cl.Name = extra.Name
	}
	if cl.Picture == "" {
		cl.Picture = extra.Picture
	}
	log.WithField("email", cl.Email).Debugln("Enriched claims from userinfo endpoint.")
	return nil
}

func (c *Config) claims(
	code, username, password, rawIDToken string, claims interface{},
	logger *logrus.Entry,
) error {
	// Get oauth2 config.
	log := logger.WithField("username", username).WithField("handler", "oauth_claims")
	log.Debugln("Starting oauth claims process.")
	op, err := c.OidcProvider()
	if err != nil {
		return fmt.Errorf("failed to get oidc provider from %v: %w", c.ConfigURL, err)
	}
	oauth2Config, err := c.oauth2Config(op)
	if err != nil {
		return fmt.Errorf("failed to get oauth2 config: %w", err)
	}
	ctx := context.Background()

	log.Debugln("Exchange token or login with password.")

	// Get raw ID token if necessary.
	// __CYLONIX_MOD__ keep the oauth2 token: it authenticates the userinfo
	// fetch below. When the caller supplies a raw ID token directly (e.g.
	// mobile-app flows) there is no access token and no userinfo fetch.
	var oauth2Token *oauth2.Token
	if rawIDToken == "" {
		rawIDToken, oauth2Token, err = c.exchangeForToken(ctx, oauth2Config, code, username, password, log)
		if err != nil {
			return err
		}
	}

	// For github, just unmarshal the claims directly.
	if c.isGithub() {
		err := json.Unmarshal([]byte(rawIDToken), claims)
		if err != nil {
			return fmt.Errorf("failed to unmarshal github claims: %v", err)
		}
		return nil
	}

	// Verify token.
	oidcVerifierConfig := &oidc.Config{
		ClientID:          c.ClientID,
		SkipClientIDCheck: true, // App use different client IDs.
	}
	verifier := op.Verifier(oidcVerifierConfig)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return fmt.Errorf("failed to verify ID token: %v. token: %s", err, rawIDToken)
	}
	// Debug print verified idToken claims
	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		log.WithError(err).Errorln("Failed to extract raw claims")
	} else {
		log.WithField("raw_claims", rawClaims).Debugln("ID token claims")
	}
	if err := idToken.Claims(claims); err != nil {
		return fmt.Errorf("failed to extract claims: %v", err)
	}
	// __BEGIN_CYLONIX_ADD__
	// Backfill missing claims (notably email) from the userinfo endpoint.
	// Scoped to the generic *Claims shape so provider-specific claim types
	// (e.g. keycloak) are unaffected.
	if cl, ok := claims.(*Claims); ok && cl.Email == "" && oauth2Token != nil {
		if err := c.enrichClaimsFromUserInfo(ctx, op, oauth2Token, idToken.Subject, cl, log); err != nil {
			return err
		}
	}
	// __END_CYLONIX_ADD__
	return nil
}
