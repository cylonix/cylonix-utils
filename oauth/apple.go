package oauth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

func generateAppleClientSecret(keyContent string, teamID string, clientID string, keyID string) (string, error) {
	block, _ := pem.Decode([]byte(keyContent))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": teamID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(96 * time.Hour).Unix(), // 96 hour expiration
		"aud": "https://appleid.apple.com",
		"sub": clientID,
	})
	token.Header["kid"] = keyID

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func readApplePrivateKey(path string) (string, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read apple private key: %w", err)
	}
	return string(keyBytes), nil
}

func setAppleConfig(config *Config) error {
	keyContent, err := readApplePrivateKey(config.ClientSecret)
	if err != nil {
		return err
	}

	// Generate client secret JWT
	clientSecret, err := generateAppleClientSecret(
		keyContent,
		config.TeamID,
		config.ClientID,
		config.KeyID,
	)
	if err != nil {
		return fmt.Errorf("failed to generate Apple client secret: %w", err)
	}

	config.ClientSecret = clientSecret
	config.Scopes = []string{"name", "email"}
	return nil
}

func isJWTExpired(tokenString string) bool {
    parser := jwt.Parser{}
    token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
    if err != nil {
        return true
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return true
    }

    exp, ok := claims["exp"].(float64)
    if !ok {
        return true
    }

    // Add 5 minute buffer before expiration
    return time.Now().Add(5 * time.Minute).After(time.Unix(int64(exp), 0))
}

func updateAppleJWTIfNeeded(config *Config) error {
	if config.Provider != SignInWithApple {
		return nil
	}

	if isJWTExpired(config.ClientSecret) {
		newSecret, err := generateAppleClientSecret(
			config.ClientSecret,
			config.TeamID,
			config.ClientID,
			config.KeyID,
		)
		if err != nil {
			return fmt.Errorf("failed to refresh Apple client secret JWT: %w", err)
		}
		config.ClientSecret = newSecret
	}
	return nil
}
