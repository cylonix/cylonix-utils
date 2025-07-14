# Cylonix Utils

Shared Go utilities for Cylonix Manager and Cylonix Supervisor services. This package provides common functionality used across Cylonix's platform components.

## Features

### Token Management

- Secure token generation and validation
- Support for multiple token types:
  - System Admin tokens
  - Admin tokens
  - User tokens
  - OAuth state tokens
  - OAuth code tokens
  - OTP tokens
  - QR code tokens
- Token caching with PostgreSQL persistence
- Configurable expiration times

### OAuth Utilities

- OAuth 2.0 and OpenID Connect support
- Multiple identity provider integrations:
  - Apple Sign In
  - Google
  - Microsoft
  - GitHub
  - WeChat
- JWT token handling
- State management for OAuth flows

### Security Features

- Cryptographically secure random number generation
- Password generation and validation
- Base32 encoding for tokens
- UUID-based identifiers
- Name hashing utilities

## Installation

```bash
go get github.com/cylonix/utils
```

## Usage Examples

### Token Generation

```go
// Create a new user token
userToken := NewUserToken(namespace)
err := userToken.Create(&UserTokenData{
    UserID: uuid.New(),
    Username: "example",
    // ...other fields
})

// Generate OTP code
otpToken := NewOtpToken()
code, err := otpToken.CanSendCode()
```

### OAuth State Management

```go
// Create OAuth state token
stateToken := NewOauthStateToken(namespace)
err := stateToken.Create(&OauthStateTokenData{
    Provider: "google",
    RedirectURL: "https://example.com/callback",
    // ...other fields
})
```

### Security Utilities

```go
// Generate secure random state token
stateToken := NewStateToken(16)

// Generate secure password
password := NewPassword()
```

## Configuration

### Token Cache Settings

```go
// Default cache durations
SysAdmin: 30 minutes
Admin: 30 minutes
User: 24 hours
OTP: 5 minutes
QR Code: 5 minutes
OAuth State: 5 minutes
OAuth Code: 5 minutes
```

## Testing

Run the test suite:

```bash
go test ./... -v
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[BSD 3-Clause License](./LICENSE)

## Notes

- This package will be published as a Go module in the future
- Currently used internally by Cylonix services
- API may change before first public release
