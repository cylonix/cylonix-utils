// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kv

import (
	"errors"
	"strings"
)

const (
	KVStoreNameSpace = "/cylonix"
	GlobalResource   = "sase-global"
	DerperType       = "derper"
	FwType           = "fw"
	PopType          = "pop"
)

var (
	ErrInvalidDerpRegionUUID = errors.New("invalid derp region uuid")
)

func GetGlobalDerperConfigKey(uuid string) string {
	return strings.Join([]string{KVStoreNameSpace, GlobalResource, DerperType, uuid}, "/")
}

func GetGlobalDerperRegionUUIDFromKey(key string) (string, error) {
	ss := strings.Split(key, "/")
	if len(ss) != 5 {
		return "", ErrInvalidDerpRegionUUID
	}
	if ss[2] != GlobalResource || ss[3] != DerperType {
		return "", ErrInvalidDerpRegionUUID
	}
	return ss[4], nil
}

func GetGlobalDerperConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, GlobalResource, DerperType}, "/")
}

func GetGlobalFwConfigKey(uuid string) string {
	return strings.Join([]string{KVStoreNameSpace, GlobalResource, FwType, uuid}, "/")
}

func GetGlobalFwConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, GlobalResource, FwType}, "/")
}

func GetGlobalPopConfigKey(uuid string) string {
	return strings.Join([]string{KVStoreNameSpace, GlobalResource, PopType, uuid}, "/")
}

func GetGlobalPopConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, GlobalResource, PopType}, "/")
}
