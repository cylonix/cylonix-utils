// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/postgres"
	"github.com/patrickmn/go-cache"
)

const (
	// The token does not expire.
	NoExpiration time.Duration = -1

	// The token will expire base on the default expiration set for the cache.
	DefaultExpiration time.Duration = 0

	// Token prefix in ETCD.
	// TODO: move cache to redis so that we can scan the keys in large scale.
	tokenNamespaceInEtcd = "token"

	// Min token expiration check interval.
	minTokenCleanupCheckInterval = time.Minute * 5

	// Token short string size
	tokenShortStringSize = 28
)

type TokenCache struct {
	Name              string
	defaultExpiration time.Duration
	cleanupInterval   time.Duration
}

type TokenItem struct {
	Object     interface{}
	UpdatedAt  int64
	Expiration int64
}

func TokenShortString(token string) string {
	return ShortStringN(token, tokenShortStringSize)
}

// Debug token cache will generate a lot of output. Use with caution.
func debugTokenCache() bool {
	return viper.GetBool("DEBUG_TOKEN_CACHE")
}

func NewTokenCache(name string, defaultExpiration, cleanupInterval time.Duration) *TokenCache {

	go cleanupToken(name, cleanupInterval)

	return &TokenCache{
		Name:              name,
		defaultExpiration: defaultExpiration,
		cleanupInterval:   cleanupInterval,
	}
}

func isTokenInPG(name string) bool {
	return name == adminTokenPath || name == userTokenPath || name == oauthStateTokenPath
}

func cleanupToken(name string, cleanupInterval time.Duration) {
	if cleanupInterval < minTokenCleanupCheckInterval {
		cleanupInterval = minTokenCleanupCheckInterval
	}
	ticker := time.NewTicker(cleanupInterval)
	for {
		<-ticker.C

		resp, err := etcd.GetAll(tokenNamespaceInEtcd, name)
		if err != nil {
			continue
		}
		if resp.Kvs == nil {
			continue
		}

		now := time.Now().Unix()
		for _, kv := range resp.Kvs {
			item := TokenItem{}
			if err = json.Unmarshal([]byte(kv.Value), &item); err != nil {
				continue
			}
			if item.Expiration <= 0 {
				continue
			}
			if now > item.Expiration {
				if debugTokenCache() {
					log.Printf("token %v expired: now=%v expire=%v", string(kv.Key), now, item.Expiration)
				}
				if isTokenInPG(name) {
					if tokenData, ok := item.Object.(*UserTokenData); ok {
						if debugTokenCache() {
							log.Printf("delete token %v in pg", string(kv.Key))
						}
						postgres.Delete(&UserTokenData{}, &UserTokenData{
							Token: tokenData.Token,
						})
					}
					if tokenData, ok := item.Object.(*OauthStateTokenData); ok {
						if debugTokenCache() {
							log.Printf("delete oauth state %v in pg", string(kv.Key))
						}
						postgres.Delete(&OauthStateTokenData{}, &OauthStateTokenData{
							Token: tokenData.Token,
						})
					}
				}
				etcd.DeleteWithKey(string(kv.Key))
			}
		}
	}
}

func (c *TokenCache) Set(k string, x interface{}, d time.Duration, isUpdate bool) error {
	var e int64
	if d == DefaultExpiration {
		d = c.defaultExpiration
	}
	if d > 0 {
		e = time.Now().Add(d).Unix()
	}
	data := TokenItem{
		Object:     x,
		Expiration: e,
		UpdatedAt:  time.Now().Unix(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if debugTokenCache() {
		shortKey := TokenShortString(k)
		log.Printf("%v save etcd key %v to value %v", c.Name, shortKey, string(jsonData))
	}
	return etcd.Put(tokenNamespaceInEtcd, c.Name, k, string(jsonData))
}

func (c *TokenCache) Get(k string, data interface{}) error {
	_, err := c.get(k, data)
	return err
}

func (c *TokenCache) get(k string, data interface{}) (*TokenItem, error) {
	shortKey := TokenShortString(k)
	resp, err := etcd.Get(tokenNamespaceInEtcd, c.Name, k)
	if err != nil {
		return nil, fmt.Errorf("key %v: %w: %w", shortKey, ErrInternalErr, err)
	}
	if resp.Kvs == nil {
		if debugTokenCache() {
			resp, err = etcd.GetAll(tokenNamespaceInEtcd, c.Name)
			if err == nil {
				log.Printf("%v keys count=%v", c.Name, len(resp.Kvs))
				for _, kv := range resp.Kvs {
					s := TokenShortString(string(kv.Key))
					log.Printf("%v key %v exists", c.Name, s)
				}
			}
		}
		return nil, fmt.Errorf("%v key %v: %w", c.Name, shortKey, ErrTokenNotExists)
	}
	item := TokenItem{}
	item.Object = data
	v := resp.Kvs[0].Value
	if err = json.Unmarshal(v, &item); err != nil {
		return nil, fmt.Errorf("key %v: %w: %w", shortKey, ErrInternalErr, err)
	}

	if debugTokenCache() {
		log.Printf("%v %v found token in cache: %v", c.Name, shortKey, string(v))
	}
	if item.Expiration > 0 {
		if time.Now().Unix() > item.Expiration {
			return nil, fmt.Errorf(
				"key %v expired(%v) updated(%v): %w",
				shortKey,
				time.Unix(item.Expiration, 0),
				time.Unix(item.UpdatedAt, 0),
				ErrTokenExpired,
			)
		}
	}
	return &item, nil
}

func (c *TokenCache) Delete(k string) error {
	if debugTokenCache() {
		shortKey := TokenShortString(k)
		log.Printf("%v delete etcd key %v", c.Name, shortKey)
	}
	return etcd.Delete(tokenNamespaceInEtcd, c.Name, k)
}

func (c *TokenCache) Refresh(k string, data interface{}) error {
	item, err := c.get(k, data)
	if err != nil {
		return err
	}
	// Skip eager refreshes.
	if time.Now().Add(c.cleanupInterval*2).Unix() < item.Expiration {
		if debugTokenCache() {
			log.Printf("token %v refresh skipped: expiring too far in the future", TokenShortString(k))
		}
		return nil
	}
	if time.Now().Unix() < (int64((c.cleanupInterval.Seconds() / 4)) + item.UpdatedAt) {
		if debugTokenCache() {
			log.Printf("token %v refresh skipped: just updated within 1/4 of cleanup interval", TokenShortString(k))
		}
		return nil
	}
	return c.Set(k, data, cache.DefaultExpiration, true)
}
