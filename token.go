// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	cryptorand "crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/cylonix/utils/namehash"
	"github.com/cylonix/utils/postgres"
	"github.com/google/uuid"
	"github.com/lib/pq"
	cache "github.com/patrickmn/go-cache"
	"github.com/sethvargo/go-password/password"
	"gorm.io/gorm"
)

var (
	gSysAdminTokenCache   *TokenCache
	gAdminTokenCache      *TokenCache
	gUserTokenCache       *TokenCache
	gOtpTokenCache        *TokenCache
	gQRCodeTokenCache     *TokenCache
	gOauthStateTokenCache *TokenCache
	gOauthCodeTokenCache  *TokenCache
	sysAdminTokenPath     = "sysadmin"
	adminTokenPath        = "admin"
	userTokenPath         = "user"
	oauthStateTokenPath   = "oauth-state"
	oauthCodeTokenPath    = "oauth-code"
	otpTokenPath          = "otp"
	qrCodeTokenPath       = "qr-code"
	smsCodeTokenPath      = "sms-code"
)

type Token interface {
	Delete() error
	Get(interface{}) error
	Key() string
	Name() string
	Refresh(interface{}) error
	Create(interface{}) error
	Update(interface{}) error
}

type UserTokenData struct {
	Token         string `gorm:"index" json:"token"`
	TokenTypeName string `json:"token_name"` // Token type.

	Namespace    string    `json:"namespace"`
	UserID       uuid.UUID `json:"user_id"`
	Username     string    `json:"username"`
	IsAdminUser  bool      `json:"is_admin_user"`
	IsSysAdmin   bool      `json:"is_sys_admin"`
	LoginType    string    `json:"login_type"`
	Value        string    `json:"value"`          // TODO: REMOVE
	WgServerName string    `json:"wg_server_name"` // TODO: REMOVE
	VpnApiKey    string    `json:"vpn_api_key"`
	Network      string    `json:"network"`

	// One admin may be permitted to manage multiple namespaces.
	// Namespace filed above is one in the list below.
	AdminNamespaces pq.StringArray `gorm:"type:text[]" json:"admin_namespaces"`

	// For added authentication, check if the auth is from an approved device.
	// This can be achieved by login with a token and a message signed by the
	// approved device's machine key.
	FromApprovedDevice       bool `json:"from_approved_device"`
	MultiFactorAuthenticated bool `json:"multi_factor_authenticated"`
}

type QRCodeAuthTokenData struct {
	TokenType          string `json:"token_type"`
	GranterID          string `json:"requester_granter_id"`
	GranterHostname    string `json:"granter_hostname"`
	GranterUserAgent   string `json:"granter_user_agent"`
	GranterUserToken   string `json:"user_token"`
	RequesterID        string `json:"requester_id"`
	RequesterHostname  string `json:"requester_hostname"`
	RequesterUserAgent string `json:"requester_user_agent"`
	WantVpnAuthKey     bool   `json:"want_vpn_auth_key"`
	State              string `json:"state"`
	CreatedAt          int64  `json:"created_at"`
}

const (
	QRCodeTokenTypeAuthRequest = "auth_request"
	QRCodeTokenTypeAuthGrant   = "auth_grant"
)

func IsQrCodeTokenTypeRequest(qrTokenType string) bool {
	return qrTokenType == QRCodeTokenTypeAuthRequest
}

type SmsTokenData struct {
	Code string `json:"code"`
}

type OauthStateTokenData struct {
	Token            string `gorm:"index" json:"token"`
	UserToken        *string
	Namespace        string
	Provider         string
	UserType         string
	RedirectURL      string
	AppListeningPort int
	NodeKey          string
	MachineKey       string
	Hostname         string
	OS               string
	OSVersion        string
	DeviceModel      string
	NetworkDomain    string
	InviteCode       string
	CreatedAt        time.Time
}

type OauthCodeTokenData struct {
	Namespace string
	UserID    uuid.UUID
}

func init() {
	gSysAdminTokenCache = NewTokenCache(sysAdminTokenPath, time.Minute*30, 5*time.Minute)
	gAdminTokenCache = NewTokenCache(adminTokenPath, time.Minute*30, 10*time.Minute)
	gUserTokenCache = NewTokenCache(userTokenPath, time.Hour*24, 2*time.Hour)
	gOtpTokenCache = NewTokenCache(smsCodeTokenPath, 5*time.Minute, 10*time.Minute)
	gQRCodeTokenCache = NewTokenCache(qrCodeTokenPath, 5*time.Minute, 10*time.Minute)
	gOauthStateTokenCache = NewTokenCache(oauthCodeTokenPath, 5*time.Minute, 10*time.Minute)
	gOauthStateTokenCache = NewTokenCache(oauthStateTokenPath, 5*time.Minute, 10*time.Minute)
}

func getToken(token, tokenPath string) Token {
	switch tokenPath {
	case sysAdminTokenPath:
		return &SysAdminToken{Token: token}
	case adminTokenPath:
		return &AdminToken{Token: token}
	case userTokenPath:
		return &UserToken{Token: token}
	}
	return nil
}

func newNamespaceHash(namespace string) string {
	return namehash.New(namespace)
}

func newTokenWithNamespaceHash(namespace, prefix string) string {
	n := newNamespaceHash(namespace)
	return prefix + "-" + n[:5] + "-" + uuid.New().String()
}

// Oauth state token operations.
type OauthStateToken struct {
	Token string
}

func NewOauthStateToken(namespace string) *OauthStateToken {
	token := NewStateToken(8) // No prefix to keep it short.
	return &OauthStateToken{
		Token: token,
	}
}

func GetOauthStateTokenData(token string) (*OauthStateTokenData, error) {
	v := &OauthStateToken{Token: token}
	return v.Get()
}

type OauthStateTokenForNodeInput struct {
	Namespace     string
	MachineKey    string
	NodeKey       string
	Hostname      string
	OS            string
	OSVersion     string
	DeviceModel   string
	NetworkDomain string
}

func newOauthStateToken(node OauthStateTokenForNodeInput) (*OauthStateToken, error) {
	v := NewOauthStateToken(node.Namespace)
			token := v.Token
			if err := v.Create(&OauthStateTokenData{
				Token:         token,
				NodeKey:       node.NodeKey,
				Namespace:     node.Namespace,
				MachineKey:    node.MachineKey,
				Hostname:      node.Hostname,
				OS:            node.OS,
				OSVersion:     node.OSVersion,
				DeviceModel:   node.DeviceModel,
				NetworkDomain: node.NetworkDomain,
			}, time.Duration(time.Hour * time.Duration(2))); err != nil {
				log.Printf("OauthStateTokenData create: %v failed %v", token, err)
				return nil, err
			}
			return v, nil
}

func GetOauthStateTokenForNode(node OauthStateTokenForNodeInput) (*OauthStateToken, error) {
	v := &OauthStateTokenData{}
	if err := postgres.SelectFirst(v, "node_key = ?", node.NodeKey); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return newOauthStateToken(node)
		}
		return nil, err
	}
	// If token has been used. Time to delete it to prevent reuse.
	if v.UserToken != nil && *v.UserToken != "" {
		log.Printf("OauthStateTokenData get: %v already used by user %v, deleting it", v.Token, *v.UserToken)
		t := &OauthStateToken{
			Token: v.Token,
		}
		if err := t.Delete(); err != nil {
			log.Printf("OauthStateTokenData delete: %v failed %v", v.Token, err)
			return nil, err
		}
		return newOauthStateToken(node)
	}

	// Token exists. Set it in cache and restart the expiration clock.
	if err := gOauthStateTokenCache.Set(v.Token, v, time.Duration(time.Hour * time.Duration(2)), false); err != nil {
		log.Printf("OauthStateTokenData set: %v failed %v", v.Token, err)
		return nil, err
	}
	return &OauthStateToken{
		Token: v.Token,
	}, nil
}
func (t *OauthStateToken) Create(data *OauthStateTokenData, duration time.Duration) error {
	if err := gOauthStateTokenCache.Set(t.Token, data, duration, false); err != nil {
		return err
	}
	if err := postgres.Create(data); err != nil {
		gOauthStateTokenCache.Delete(t.Token)
		return err
	}
	return nil
}
func (t *OauthStateToken) Update(data *OauthStateTokenData, duration time.Duration) error {
	log.Printf("OauthStateTokenData updated: %v: %#v", t.Token, *data)
	if err := postgres.Updates(&OauthStateTokenData{}, data, &OauthStateTokenData{Token: t.Token}); err != nil {
		return err
	}
	return gOauthStateTokenCache.Set(t.Token, data, duration, true)
}
func (t *OauthStateToken) Delete() error {
	if err := postgres.Delete(&OauthStateTokenData{}, &OauthStateTokenData{Token: t.Token}); err != nil {
		return err
	}
	return gOauthStateTokenCache.Delete(t.Token)
}

func (t *OauthStateToken) Get() (*OauthStateTokenData, error) {
	data := &OauthStateTokenData{}
	if err := gOauthStateTokenCache.Get(t.Token, data); err != nil {
		// TEMPORARY TO RECOVER FROM CACHE MISS
		// REMOVE THIS CODE AFTER A WHILE
		if errors.Is(err, ErrTokenNotExists) || errors.Is(err, ErrTokenExpired) {
			postgresErr := postgres.SelectFirst(data, "token = ?", t.Token)
			if postgresErr == nil {
				postgresErr = gOauthStateTokenCache.Set(t.Token, data, time.Duration(time.Hour*2), false)
			}
			if postgresErr == nil {
				//log.Printf("OauthStateTokenData get: %v found in postgres", t.Token)
				return data, nil
			}
			if errors.Is(postgresErr, gorm.ErrRecordNotFound) {
				//log.Printf("OauthStateTokenData get: %v not found in postgres", t.Token)
				return nil, ErrTokenNotExists
			}
		}
		log.Printf("OauthStateTokenData get: %v failed %v", t.Token, err)
		return nil, err
	}
	//log.Printf("OauthStateTokenData get: %v: %#v", t.Token, *data)
	return data, nil
}

// Oauth code token operations.
// Oauth code token is to act as an oauth provider to the client request.
// Oauth code exchange for data will delete the token i.e. one time user only.
type OauthCodeToken struct {
	Token string
}

func NewOauthCodeToken(namespace string) *OauthCodeToken {
	token := newTokenWithNamespaceHash(namespace, oauthCodeTokenPath)
	return &OauthCodeToken{
		Token: token,
	}
}
func (t *OauthCodeToken) Create(data *OauthCodeTokenData) error {
	return gOauthCodeTokenCache.Set(t.Token, data, cache.DefaultExpiration, false)
}
func (t *OauthCodeToken) Update(data *OauthCodeTokenData) error {
	return gOauthCodeTokenCache.Set(t.Token, data, cache.DefaultExpiration, true)
}
func (t *OauthCodeToken) Delete() error {
	return gOauthCodeTokenCache.Delete(t.Token)
}
func (t *OauthCodeToken) Get() (*OauthCodeTokenData, error) {
	data := &OauthCodeTokenData{}
	if err := gOauthCodeTokenCache.Get(t.Token, data); err != nil {
		return nil, err
	}
	t.Delete()
	return data, nil
}

// QR code token operations.
type QRCodeToken struct {
	Token string
}

func NewQRCodeToken() *QRCodeToken {
	return &QRCodeToken{
		Token: newTokenWithNamespaceHash("qr-code", qrCodeTokenPath),
	}
}
func (t *QRCodeToken) Create(data interface{}) error {
	return gQRCodeTokenCache.Set(t.Token, data, cache.DefaultExpiration, false)
}
func (t *QRCodeToken) Update(data interface{}) error {
	return gQRCodeTokenCache.Set(t.Token, data, cache.DefaultExpiration, true)
}
func (t *QRCodeToken) Get(data interface{}) error {
	return gQRCodeTokenCache.Get(t.Token, data)
}
func (t *QRCodeToken) Delete() error {
	return gQRCodeTokenCache.Delete(t.Token)
}

// Token operation for sysadmins.
// Don't save it in PG. Access is time sensitive and restricted.
type SysAdminToken struct {
	Token string
}

func NewSysAdminToken() *SysAdminToken {
	return &SysAdminToken{
		Token: newTokenWithNamespaceHash("sys-admin", sysAdminTokenPath),
	}
}
func (t *SysAdminToken) Name() string {
	return sysAdminTokenPath
}
func (t *SysAdminToken) Key() string {
	return t.Token
}
func (t *SysAdminToken) Create(data interface{}) error {
	return gSysAdminTokenCache.Set(t.Token, data, cache.DefaultExpiration, false)
}
func (t *SysAdminToken) Delete() error {
	return gSysAdminTokenCache.Delete(t.Token)
}
func (t *SysAdminToken) Get(data interface{}) error {
	if err := gSysAdminTokenCache.Get(t.Token, data); err != nil {
		return fmt.Errorf("check sys admin token error: %w", err)
	}
	return nil
}
func (t *SysAdminToken) Refresh(data interface{}) error {
	err := gSysAdminTokenCache.Refresh(t.Token, data)
	if err != nil {
		return fmt.Errorf("refresh sys admin token error: %w", err)
	}
	return nil
}
func (t *SysAdminToken) Update(data interface{}) error {
	return gSysAdminTokenCache.Set(t.Token, data, cache.DefaultExpiration, true)
}

// Token operation for admin accounts.
type AdminToken struct {
	Token string
}

func NewAdminToken(namespace string) *AdminToken {
	return &AdminToken{
		Token: newTokenWithNamespaceHash(namespace, adminTokenPath),
	}
}
func (t *AdminToken) Name() string {
	return adminTokenPath
}
func (t *AdminToken) Key() string {
	return t.Token
}
func (t *AdminToken) Create(data interface{}) error {
	if err := gAdminTokenCache.Set(t.Token, data, cache.DefaultExpiration, false); err != nil {
		return err
	}
	return postgres.Create(data)
}
func (t *AdminToken) Delete() error {
	if err := postgres.Delete(&UserTokenData{}, &UserTokenData{Token: t.Token}); err != nil {
		return err
	}
	return gAdminTokenCache.Delete(t.Token)
}
func (t *AdminToken) Get(data interface{}) error {
	var err error
	if err = gAdminTokenCache.Get(t.Token, data); err == nil {
		return nil
	}
	// ETCD should have the key already. We shouldn't need to get it from postgres.
	return fmt.Errorf("check admin token error: %w", err)
}
func (t *AdminToken) Refresh(data interface{}) error {
	err := gAdminTokenCache.Refresh(t.Token, data)
	if err != nil {
		return fmt.Errorf("refresh admin token error: %w", err)
	}
	return nil
}
func (t *AdminToken) Update(data interface{}) error {
	if err := postgres.Updates(&UserTokenData{}, data, &UserTokenData{Token: t.Token}); err != nil {
		return err
	}
	return gAdminTokenCache.Set(t.Token, data, cache.DefaultExpiration, true)
}

// Token operation for user accounts.
type UserToken struct {
	Token string
}

func NewUserToken(namespace string) *UserToken {
	return &UserToken{
		Token: newTokenWithNamespaceHash(namespace, userTokenPath),
	}
}
func (t *UserToken) Name() string {
	return userTokenPath
}
func (t *UserToken) Key() string {
	return t.Token
}
func (t *UserToken) Create(data interface{}) error {
	if err := gUserTokenCache.Set(t.Token, data, cache.DefaultExpiration, false); err != nil {
		return err
	}
	if err := postgres.Create(data); err != nil {
		gUserTokenCache.Delete(t.Token)
		return err
	}
	return nil
}
func (t *UserToken) Get(data interface{}) error {
	if err := gUserTokenCache.Get(t.Token, data); err != nil {
		return err
	}
	return nil
}
func (t *UserToken) Refresh(data interface{}) error {
	if err := gUserTokenCache.Refresh(t.Token, data); err != nil {
		return fmt.Errorf("refresh user token error: %w", err)
	}
	return nil
}
func (t *UserToken) Delete() error {
	if t == nil {
		return nil
	}
	err1 := postgres.Delete(&UserTokenData{}, &UserTokenData{Token: t.Token})
	err2 := gUserTokenCache.Delete(t.Token)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("failed to delete token: %w %w", err1, err2)
	}
	return nil
}
func (t *UserToken) Update(data interface{}) error {
	if err := postgres.Updates(&UserTokenData{}, data, &UserTokenData{Token: t.Token}); err != nil {
		return err
	}
	return gUserTokenCache.Set(t.Token, data, cache.DefaultExpiration, true)
}

func (d *UserTokenData) Clone() (*UserTokenData, error) {
	var token Token
	if d.IsAdminUser {
		token = NewAdminToken(d.Namespace)
	} else {
		token = NewUserToken(d.Namespace)
	}
	newData := *d
	newData.Token = token.Key()
	if err := token.Create(&newData); err != nil {
		return nil, err
	}
	return &newData, nil
}
func (d *UserTokenData) Delete() error {
	if d == nil {
		return nil
	}
	token := getToken(d.Token, d.TokenTypeName)
	if token == nil {
		s := TokenShortString(d.Token)
		return fmt.Errorf("%v unknown token type name: %v", s, d.TokenTypeName)
	}
	return token.Delete()
}
func (d *UserTokenData) Save() error {
	if d == nil {
		return nil
	}
	token := getToken(d.Token, d.TokenTypeName)
	if token == nil {
		s := TokenShortString(d.Token)
		return fmt.Errorf("%v unknown token type name: %v", s, d.TokenTypeName)
	}
	return token.Update(d)
}
func (d *UserTokenData) Refresh() error {
	if d == nil {
		return nil
	}
	token := getToken(d.Token, d.TokenTypeName)
	if token == nil {
		s := TokenShortString(d.Token)
		return fmt.Errorf("%v unknown token type name: %v", s, d.TokenTypeName)
	}
	return token.Refresh(d)
}

func userTokenDataFromToken(token string) (*UserTokenData, error) {
	ret := &UserTokenData{}
	if err := postgres.SelectFirst(ret, "token = ?", token); err != nil {
		return nil, err
	}
	return ret, nil
}

func RefreshToken(token string) error {
	ret, err := userTokenDataFromToken(token)
	if err != nil {
		return err
	}
	return ret.Refresh()
}

func WgServerNameFromToken(token string) (string, error) {
	ret, err := userTokenDataFromToken(token)
	if err != nil {
		return "", err
	}
	return ret.WgServerName, nil
}

func GetUserOrAdminTokenWithKey(key string) (Token, *UserTokenData, error) {
	var token Token
	var err error
	data := &UserTokenData{}
	token = &SysAdminToken{
		Token: key,
	}
	if err = token.Get(data); err == nil {
		return token, data, nil
	}
	if !errors.Is(err, ErrTokenNotExists) {
		return nil, nil, err
	}
	token = &AdminToken{
		Token: key,
	}
	if err = token.Get(data); err == nil {
		return token, data, nil
	}
	if !errors.Is(err, ErrTokenNotExists) {
		return nil, nil, err
	}
	token = &UserToken{
		Token: key,
	}
	if err = token.Get(data); err == nil {
		return token, data, nil
	}
	return nil, nil, err
}

func UserTokenToData(key string) (data *UserTokenData, err error) {
	_, data, err = GetUserOrAdminTokenWithKey(key)
	return
}
func UpdateUserToken(key string, data *UserTokenData) error {
	token, _, err := GetUserOrAdminTokenWithKey(key)
	if err != nil {
		return err
	}
	return token.Update(data)
}
func DeleteUserToken(key string) error {
	token, _, err := GetUserOrAdminTokenWithKey(key)
	if err != nil {
		return err
	}
	return token.Delete()
}
func RefreshUserToken(key string) error {
	token, data, err := GetUserOrAdminTokenWithKey(key)
	if err != nil {
		return err
	}
	return token.Refresh(data)
}

/*
 * Token operation to verify one-time code.
 */
type OtpToken struct {
	Token string
}
type OtpTokenData struct {
	State    string
	Code     string
	LastSent int64
}

func NewOtpToken() *OtpToken {
	return &OtpToken{
		Token: otpTokenPath + "-" + uuid.New().String(),
	}
}
func NewEmailOtpToken(email string) *OtpToken {
	return &OtpToken{
		Token: otpTokenPath + "-email-" + namehash.New(email),
	}
}
func NewSmsToken(phone string) *OtpToken {
	return &OtpToken{
		Token: otpTokenPath + "-phone-" + namehash.New(phone),
	}
}

// CanSendCode returns ErrSendAgainTooSoon if the last sent for this token is
// within a minute or error to access the code token cache. Otherwise, it
// returns a new code if the last one expired or not exists, or returns the last
// code if it is still valid. It saves the new code back to the cache too.
// Caller can save a new token data if needs to set the state of the token.
func (t *OtpToken) CanSendCode() (*string, error) {
	var (
		data     = OtpTokenData{}
		err      = gOtpTokenCache.Get(t.Token, &data)
		code     = NewOtp()
		isUpdate = false
	)
	if err != nil {
		if !errors.Is(err, ErrTokenNotExists) && !errors.Is(err, ErrTokenExpired) {
			return nil, err
		}
		if errors.Is(err, ErrTokenExpired) {
			isUpdate = true
		}
		// No existing code or code expired. Fall through to set a new code.
	} else if time.Now().Unix()-data.LastSent < 60 {
		return nil, ErrSendAgainTooSoon
	}
	data.LastSent = time.Now().Unix()
	data.Code = code
	if err = gOtpTokenCache.Set(t.Token, &data, cache.DefaultExpiration, isUpdate); err != nil {
		return nil, err
	}
	return &code, nil
}
func (t *OtpToken) SetNewCode() (*string, error) {
	code := NewOtp()
	data := OtpTokenData{
		Code: code,
	}
	if err := gOtpTokenCache.Set(t.Token, &data, cache.DefaultExpiration, false); err != nil {
		return nil, err
	}
	return &code, nil
}
func (t *OtpToken) Set(state, code string, isUpdate bool) error {
	data := &OtpTokenData{
		Code:  code,
		State: state,
	}
	return gOtpTokenCache.Set(t.Token, data, cache.DefaultExpiration, isUpdate)
}
func (t *OtpToken) IsValid(code string) (bool, string, error) {
	data := &OtpTokenData{}
	token := t.Token
	err := gOtpTokenCache.Get(token, data)
	if err == nil {
		if data.Code != code {
			if debugTokenCache() {
				log.Printf("code does not match %v != %v", data.Code, code)
			}
			return false, "", nil
		}
		gOtpTokenCache.Delete(token)
		return true, data.State, nil
	}
	if errors.Is(err, ErrTokenExpired) || errors.Is(err, ErrTokenNotExists) {
		if debugTokenCache() {
			log.Printf("code %v expired or not exists: %v", code, err)
		}
		return false, "", nil
	}
	return false, "", fmt.Errorf("check otp error: %w", err)
}
func (t *OtpToken) Delete() error {
	return gOtpTokenCache.Delete(t.Token)
}
func NewOtp() string {
	return New6DigitCode()
}

func New6DigitCode() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	rndCode := fmt.Sprintf("%06v", rnd.Int31n(1000000))
	return rndCode
}

func New11DigitCode() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	rndCode := fmt.Sprintf("%011v", rnd.Int63n(100000000000))
	return rndCode
}

func NewPassword() string {
	p, _ := password.Generate(24, 4, 4, false, false)
	return p
}

func NewStateToken(length int) string {
    // Generate random bytes
    randomBytes := make([]byte, 32)
    _, err := cryptorand.Read(randomBytes)
    if err != nil {
        // Fallback to less secure but functional alternative
        return uuid.New().String()[:length]
    }

    // Encode to base32 (using RFC4648 alphabet) and remove padding
    encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
    encoded := encoding.EncodeToString(randomBytes)

    // Return first n characters
    if len(encoded) > length {
        return encoded[:length]
    }
    return encoded
}
