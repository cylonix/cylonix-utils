// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package oauth

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	kc "github.com/cylonix/utils/keycloak"
	"github.com/sirupsen/logrus"
)

const (
	adminRolePrefix = kc.AdminRolePrefix
	sysadminRole    = kc.SysadminRole
)

func AdminRole(namespace string) string {
	return adminRolePrefix + namespace
}

var (
	ErrEmptyAdminCfg = errors.New("empty admin config is not allowed")
	ErrEmptyBaseUrl  = errors.New("empty base url is not allowed")
	ErrEmptyUserCfg  = errors.New("empty user config is not allowed")
)

type KeyCloakConfig struct {
	URL               string `json:"url"`
	Realm             string `json:"realm"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	RedirectPathBase  string `json:"redirect_path_base"`
	LogoutRedirectURI string `json:"logout_redirect_uri"`
	AuthSuccessURI    string `json:"auth_success_uri"`
	AuthFailURI       string `json:"auth_fail_uri"`
}

type KeyCloak struct {
	config  KeyCloakConfig
}

func (c *KeyCloakConfig) CheckAdminConfig() error {
	if c.URL == "" ||
		c.Realm == "" ||
		c.ClientID == "" ||
		c.ClientSecret == "" ||
		c.RedirectPathBase == "" {
		return fmt.Errorf(
			"%w url=%v realm=%v clientID=%v secret=%v redirect=%v",
			ErrEmptyAdminCfg,
			c.URL, c.Realm, c.ClientID, c.ClientSecret, c.RedirectPathBase,
		)
	}
	return nil
}

func (c *KeyCloakConfig) CheckUserConfig() error {
	if c.URL == "" || c.RedirectPathBase == "" {
		return ErrEmptyUserCfg
	}
	return nil
}

func NewKeyCloakAuth(config KeyCloakConfig) (Provider, error) {
	if config.URL == "" {
		return nil, ErrEmptyBaseUrl
	}
	if config.AuthFailURI == "" {
		config.AuthFailURI = config.URL + "/401"
	}
	return &KeyCloak{
		config:  config,
	}, nil
}

func (k *KeyCloak) Config(namespace string) *Config {
	base := k.config.URL
	realm := namespace
	cfg := k.config
	if cfg.Realm != "" {
		realm = k.config.Realm
	}
	clientID := kc.RealmClientID(realm)
	if cfg.ClientID != "" {
		clientID = cfg.ClientID
	}
	prefix := base + "/realms/" + realm
	return &Config{
		ConfigURL:         prefix,
		ClientID:          clientID,
		ClientSecret:      cfg.ClientSecret,
		RedirectURI:       base + cfg.RedirectPathBase + realm,
		LogoutURI:         prefix + "/protocol/openid-connect/logout",
		LogoutRedirectURI: cfg.LogoutRedirectURI,
		WebAuthSuccessURI: cfg.AuthSuccessURI,
		WebAuthFailURI:    cfg.AuthFailURI,
		Scopes:            []string{"roles"},
	}
}

func (k *KeyCloak) User(s *Session) (*User, error) {
	claims := &KeyCloakClaims{}
	err := k.Config(s.Namespace).claims(s.Code, s.Username, s.Password, s.RawIDToken, claims, s.Logger)
	if err != nil {
		return nil, err
	}
	return claims.User(s.Namespace, s.Provider, s.Logger)
}

type KeyCloakClaims struct {
	UserID        string   `json:"sub"`
	Username      string   `json:"preferred_username"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	RoleList      []string `json:"client_role_map"`
	Department    []string `json:"department"`
}

// TODO: support admin user to choose from one of the namespaces.
func GetNamespaceFromAdminRoles(roles []string) []string {
	var s []string
	for _, role := range roles {
		if strings.HasPrefix(role, adminRolePrefix) {
			s = append(s, strings.TrimPrefix(role, adminRolePrefix))
		}
	}
	return s
}

func GetKeyCloakAdminRole(namespace string) string {
	return adminRolePrefix + namespace
}

func HasSysAdminRole(roles []string) bool {
	return slices.Contains(roles, sysadminRole)
}

func HasNamespaceAdminRole(namespace string, roles []string) bool {
	return slices.Contains(roles, GetKeyCloakAdminRole(namespace))
}

func HasAdminRole(roles []string) bool {
	for _, r := range roles {
		if strings.HasPrefix(r, adminRolePrefix) {
			return true
		}
	}
	return false
}

func GetKeyCloakClientRoleMapKey() string {
	return "client_role_map" // must be the same as the JSON key of KeyCloakClaims.RoleList
}

func (c *KeyCloakClaims) User(namespace, provider string, logger *logrus.Entry) (*User, error) {
	// Fetch the real namespace from user roles.
	var adminNamespaces []string
	var isSysAdmin = false
	logger.WithField("roles", c.RoleList).WithField("provider", provider).Debugln("Keycloak login roles")
	if provider == KeyCloakAdminLogin {
		isSysAdmin = HasSysAdminRole(c.RoleList)
		logger.WithField("is-sys-admin", isSysAdmin).Debugln("Keycloak admin login")
		if !isSysAdmin {
			adminNamespaces = GetNamespaceFromAdminRoles(c.RoleList)
			if len(adminNamespaces) <= 0 {
				return nil, fmt.Errorf("%w: admin user has no namespace set", ErrUnauthorized)
			}
			if !slices.Contains(adminNamespaces, namespace) {
				return nil, fmt.Errorf("%w: %v is not an admin of %v", ErrUnauthorized, c.Username, namespace)
			}
		}
	}
	return &User{
		Namespace:       namespace,
		UserID:          c.UserID,
		LoginName:       c.Username,
		DisplayName:     c.Username,
		Email:           c.Email,
		EmailVerified:   c.EmailVerified,
		AdminNamespaces: adminNamespaces,
		IsSysAdmin:      isSysAdmin,
		Roles:           c.RoleList,
		Attributes:      map[string][]string{"department": c.Department},
	}, nil
}

func (k *KeyCloak) AddLoginRedirectIdpHint(redirect, domain string) string {
	if domain == "gmail.com" {
		redirect = redirect + "&kc_idp_hint=google"
	}
	return redirect
}
