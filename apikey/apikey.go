package apikey

import (
	"log"
	"net/http"
)
const (
	LoginCookieName  = "CYLONIX_MANAGER_LOGIN_COOKIE"
	ApiKeyCookieName = "CYLONIX_MANAGER_API_KEY"
	SecureLoginCookieName = "__Host-" + LoginCookieName
	SecureApiKeyCookieName = "__Host-" + ApiKeyCookieName
)

func Parse(r *http.Request) string {
	if cookie, err := r.Cookie(SecureApiKeyCookieName); err == nil {
		if cookie.Value != "" {
			return cookie.Value
		}
	}
	if cookie, err := r.Cookie(ApiKeyCookieName); err == nil {
		if cookie.Value != "" {
			log.Printf("Using cookie: '%s'", cookie.Value)
			return cookie.Value
		}
	}
	if token := r.Header.Get("X-API-KEY"); token != "" {
		return token
	}
	if token := r.URL.Query().Get("X-API-KEY"); token != "" {
		return token
	}
	return ""
}
