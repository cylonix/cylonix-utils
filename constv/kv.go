// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package constv

import "strings"

const (
	//KVStoreNameSpace The root key sapce
	KVStoreNameSpace = "/cylonix"

	//PopNamespace Pop related config
	PopNamespace = "pop"

	//WgNamespace Pop related config
	WgNamespace = "wg"

	//UserNamespace User related
	UserNamespace = "user"

	//System system level configurations
	System = "system"

	//Global global means the resource is global wide, it will use the uuid as the index
	Global = "global"

	//OriginalConfig The original configuration
	OriginalConfig = "origin"

	//NativeConfig The converted configuration
	NativeConfig = "native"

	//TaiNamespace tai related config
	TaiNamespace = "tai"

	//GlobalResourceTypeNat nat global resource type
	GlobalResourceTypeNat = "Nat"
	//GlobalResourceTypePopInstance pop instance global resource type
	GlobalResourceTypePopInstance = "pop"
	//GlobalResourceTypePopConnection pop connection global resource type
	GlobalResourceTypePopConnection = "pop-connection"
	//GlobalResourceTypePolicy policy global resource type
	GlobalResourceTypePolicy = "policy"
	//GlobalResourceTypeAppId app global resource type
	GlobalResourceTypeAppId = "app"
	//GlobalResourceTypeEndpointID endpoint global resource type
	GlobalResourceTypeEndpointID = "endpoint"
	//GlobalResourceTypeUserPop user config resource type
	GlobalResourceTypeUserPop = "user-pop"
	//GlobalResourceTypeUser user config resource type
	GlobalResourceTypeUser = "user"
	//GlobalResourceTypeWg wg config esource type
	GlobalResourceTypeWg = "wg"
	//GlobalResourceTypeWgNamespace wg config esource type
	GlobalResourceTypeWgNamespace = "wg-namespace"
	//GlobalResourceTypeTaiNamespace tai config esource type
	GlobalResourceTypeTaiNamespace = "tai-namespace"
	//GlobalResourceTypeTai tai config esource type
	GlobalResourceTypeTai = "tai"
	//GlobalResourceTypeApiKey pre-configed api keys
	GlobalResourceTypeApiKey = "api-key"
)

//GetPopInstanceConfigKey return the key of pop instance, the name will placed into the suffix
func GetPopInstanceConfigKey(name string) string {
	return strings.Join([]string{KVStoreNameSpace, PopNamespace, "instance", "conn_config", name}, "/")
}

//GetWgInstanceConfigKey return the key of wg instance, the name will placed into the suffix
func GetWgInstanceConfigKey(name string) string {
	return strings.Join([]string{KVStoreNameSpace, WgNamespace, "instance", "conn_config", name}, "/")
}

//GetWgConnConfigPrefix pop instance config prefix
func GetWgConnConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, WgNamespace, "instance", "conn_config"}, "/")
}

//GetTaiInstanceConfigKey return the key of tai instance, the name will placed into the suffix
func GetTaiInstanceConfigKey(name string) string {
	return strings.Join([]string{KVStoreNameSpace, TaiNamespace, "instance", "conn_config", name}, "/")
}

//GetFwConnConfigPrefix tai instance config prefix
func GetFwConnConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, TaiNamespace, "instance", "conn_config"}, "/")
}

//GetPopInstanceConfigPrefix pop instance config prefix
func GetPopInstanceConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, PopNamespace, "instance", "conn_config"}, "/")
}

// GetUserConfigPrefix return the all the config prefix for specific user
func GetUserConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "config"}, "/")
}

//GetUserPopOriginConfigPrefix return the pop config prefix for specific user
func GetUserPopOriginConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "config", PopNamespace, OriginalConfig}, "/")
}

//GetUserWgOriginConfigPrefix return the pop config prefix for specific user
func GetUserWgOriginConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "config", WgNamespace, OriginalConfig}, "/")
}

//GetUserTaiOriginConfigPrefix return the tai config prefix for specific user
func GetUserTaiOriginConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "config", TaiNamespace, OriginalConfig}, "/")
}

//GetUserNativeConfigPrefix return the pop native config prefix for specific user
func GetUserNativeConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "config", PopNamespace, NativeConfig}, "/")
}

//GetUserNativeConfigKey return the pop native config for specific user
func GetUserNativeConfigKey(user string, instanceID string) string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "config", PopNamespace, NativeConfig, user, instanceID}, "/")
}

//GetUserPopOriginConfigKey Put all the pop instance into one key
func GetUserPopOriginConfigKey(name string, popID string) string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "config", PopNamespace, OriginalConfig, name, popID}, "/")
}

//GetUserWgOriginConfigKey Put all the wg instance into one key
func GetUserWgOriginConfigKey(name string, popID string) string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "config", WgNamespace, OriginalConfig, name, popID}, "/")
}

//GetUserTaiOriginConfigKey Put all the tai instance into one key
func GetUserTaiOriginConfigKey(name string, taiID string) string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "config", TaiNamespace, OriginalConfig, name, taiID}, "/")
}

// GetUserGeneralConfigKey user general info configration
func GetUserGeneralConfigKey(name string) string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "general", name}, "/")
}

// GetUserGeneralPrefix user general info configration prefix, for list keys and watch
func GetUserGeneralPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, UserNamespace, "general"}, "/")
}

// GetSystemOriginConfig system level orginal configration
func GetSystemOriginConfig(ID string) string {
	return strings.Join([]string{KVStoreNameSpace, System, "config", PopNamespace, OriginalConfig, ID}, "/")
}

// GetSystemOriginConfigPrefix system level orginal configration
func GetSystemOriginConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, System, "config", PopNamespace, OriginalConfig}, "/")
}

// GetSystemNativeConfig system level native configuration
func GetSystemNativeConfig(ID string) string {
	return strings.Join([]string{KVStoreNameSpace, System, "config", PopNamespace, NativeConfig, ID}, "/")
}

// GetGlobalConfigKey return the key with global prefix
func GetGlobalConfigKey(uuid string, resType string) string {
	return strings.Join([]string{KVStoreNameSpace, Global, uuid, resType}, "/")
}

// GetGlobalConfigPrefix return the global resource prefix, mainly used for
func GetGlobalConfigPrefix() string {
	return strings.Join([]string{KVStoreNameSpace, Global}, "/")
}

// GetGlobalTypeConfigPrefix return the global resource prefix, mainly used for sepecific type
func GetGlobalTypeConfigPrefix(resType string) string {
	return strings.Join([]string{KVStoreNameSpace, Global, resType}, "/")
}
