package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type WeChatConfig struct {
	RequestPath       string `json:"request_path"`
	AppID             string `json:"app_id"`
	Secret            string `json:"secret"`
	RedirectPathBase  string `json:"redirect_path_base"`
	WebAuthSuccessUri string `json:"web_auth_success_uri"`
	WebAuthFailUri    string `json:"web_auth_fail_uri"`
}

type weChatAuthResult struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	Scope        string `json:"scope"`
	SnsApiLogin  string `json:"snsapi_login"`
	UnionID      string `json:"unionid"`
}
type weChatClaims struct {
	OpenID      string `gorm:"index;primarykey" json:"openid"`
	DisplayName string `json:"nickname"`
	Sex         int    `json:"sex"`
	Language    string `json:"language"`
	City        string `json:"city"`
	Province    string `json:"province"`
	Country     string `json:"country"`
	HeadImgUrl  string `json:"headimgurl"`
	UnionID     string `json:"unionid"`
}

func (c *weChatClaims) User(namespace, provider string) *User {
	return &User{
		Namespace:     namespace,
		Provider:      provider,
		UserID:        c.OpenID,
		DisplayName:   c.DisplayName,
		ProfilePicURL: c.HeadImgUrl,
	}
}

type WeChatAuth struct {
	config WeChatConfig
}

func NewWeChatAuth(config WeChatConfig) (Provider, error) {
	if config.AppID == "" || config.Secret == "" {
		return nil, errors.New("wechat login config is invalid")
	}
	config.RequestPath = "https://api.weixin.qq.com/sns"
	return &WeChatAuth{
		config: config,
	}, nil
}

func (w *WeChatAuth) Config(namespace string) *Config {
	return &Config{
		ConfigURL:         w.config.RequestPath,
		ClientID:          w.config.AppID,
		ClientSecret:      w.config.Secret,
		RedirectURI:       strings.TrimSuffix(w.config.RedirectPathBase, "/"),
		WebAuthSuccessURI: w.config.WebAuthSuccessUri,
		WebAuthFailURI:    w.config.WebAuthFailUri,
	}
}

func (w *WeChatAuth) User(s *Session) (*User, error) {
	r, err := w.config.auth(s.Code)
	if err != nil {
		return nil, err
	}
	claims, err := r.claims(w.config.RequestPath)
	if err != nil {
		return nil, err
	}
	return claims.user(s.Namespace, s.Provider), nil
}

func (c *weChatClaims) user(namespace, provider string) *User {
	return &User{
		Provider:      provider,
		Namespace:     namespace,
		UserID:        SignInWithWeChat+c.OpenID,
		DisplayName:   c.DisplayName,
		LoginName:     SignInWithWeChat+c.OpenID,
		ProfilePicURL: c.HeadImgUrl,
	}
}
func httpGet(url string, params map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	query := req.URL.Query()
	for name, value := range params {
		query.Add(name, value)
	}

	req.URL.RawQuery = query.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
func (c *WeChatConfig) auth(code string) (*weChatAuthResult, error) {
	oauthParams := map[string]string{
		"appid":      c.AppID,
		"secret":     c.Secret,
		"code":       code,
		"grant_type": "authorization_code",
	}
	resp, err := httpGet(c.RequestPath+"/oauth2/access_token", oauthParams)
	if err != nil {
		return nil, err
	}
	weChatAuth := weChatAuthResult{}
	err = json.Unmarshal(resp, &weChatAuth)
	if err != nil {
		return nil, err
	}
	if weChatAuth.AccessToken == "" || weChatAuth.OpenID == "" {
		return nil, fmt.Errorf("get wechat auth info failed")
	}
	return &weChatAuth, nil
}
func (r *weChatAuthResult) claims(urlPrefix string) (*weChatClaims, error) {
	userInfoParams := map[string]string{
		"access_token": r.AccessToken,
		"openid":       r.OpenID,
	}
	resp, err := httpGet(urlPrefix+"/userinfo", userInfoParams)
	if err != nil {
		return nil, err
	}
	claims := &weChatClaims{}
	err = json.Unmarshal(resp, claims)
	if err != nil {
		return nil, err
	}
	if claims.OpenID == "" {
		return nil, fmt.Errorf("get wechat user info failed")
	}
	return claims, nil
}
