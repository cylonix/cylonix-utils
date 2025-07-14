// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"fmt"
	"strings"

	"github.com/cylonix/utils/etcd"
)

// Use to communicate between supervisor and sase-manager/sase-tai/
type ApiKeyCache struct {
	Key string
}

var (
	gApiKeyCache             *ApiKeyCache
	GlobalResourceTypeApiKey = "api-key"
	Global                   = "global"
	KVStoreNameSpace         = "/cylonix"
)

func GetGlobalConfigKey(uuid string, resType string) string {
	return strings.Join([]string{KVStoreNameSpace, Global, uuid, resType}, "/")
}

func init() {
	gApiKeyCache = NewApiKeyCache()
}

func NewApiKeyCache() *ApiKeyCache {
	key := GetGlobalConfigKey("all", GlobalResourceTypeApiKey)

	return &ApiKeyCache{
		Key: key,
	}
}

func (c *ApiKeyCache) Get() (string, error) {
	resp, err := etcd.GetWithKey(c.Key)
	if err != nil {
		return "", fmt.Errorf("key %v: %w: %w", ShortString(c.Key), ErrInternalErr, err)
	}
	if resp.Kvs == nil {
		return "", fmt.Errorf("failed to get the api key in %v", c.Key)
	}

	return string(resp.Kvs[0].Value), nil
}

func CheckApiKey(apiKey string) (interface{}, error) {
	data := &UserTokenData{}
	item, err := gApiKeyCache.Get()
	if err != nil {
		return data, err
	}
	if item != apiKey {
		return data, fmt.Errorf("invalid api key %v", TokenShortString(apiKey))
	} else {
		return data, nil
	}
}

func GetApiKey() (string, error) {
	resp, err := etcd.GetWithKey(gApiKeyCache.Key)
	if err != nil {
		return "", err
	}
	if resp.Kvs == nil {
		return "", fmt.Errorf("failed to get the api key in %v", gApiKeyCache.Key)
	}

	return string(resp.Kvs[0].Value), nil
}
