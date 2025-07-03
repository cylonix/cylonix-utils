package kv

const (
	// KVStoreNameSpace: the root key space
	// KVStoreNameSpace = "/cylonix"

	// PopNamespace: pop related config
	PopNamespace = "pop"

	// WgNamespace: wg gateway related config
	WgNamespace = "wg"

	// UserNamespace: user/namespace related
	UserNamespace = "user"

	// System: system level configurations
	System = "system"

	// Feature: feature configurations
	Feature = "feature"

	// Global: global resources
	Global = "global"

	// OriginalConfig: original configuration
	OriginalConfig = "origin"

	// RuntimeConfig: active configuration added by application, such as application route, policy route et al.
	RuntimeConfig = "runtime"

	// NativeConfig: the converted configuration
	NativeConfig = "native"

	// TaiNamespace: tai related config
	TaiNamespace = "tai"

	// GlobalResourceTypeNat: nat global resource type
	GlobalResourceTypeNat = "Nat"

	// GlobalResourceTypePopInstance: pop instance global resource type
	GlobalResourceTypePopInstance = "pop"

	// GlobalResourceTypePopConnection: pop connection global resource type
	GlobalResourceTypePopConnection = "pop-connection"

	// GlobalResourceTypePolicy: policy global resource type
	GlobalResourceTypePolicy         = "policy"
	GlobalResourceTypeUnderlayTunnel = "underlay-tunnel"
	GlobalResourceTypeUnderlayPop    = "underlay-pop"

	// GlobalResourceTypeAppId: app global resource type
	GlobalResourceTypeAppId = "app"

	// GlobalResourceTypeEndpointID: endpoint global resource type
	GlobalResourceTypeEndpointID = "endpoint"

	// GlobalResourceTypeUserPop: user config resource type
	GlobalResourceTypeUserPop = "user-pop"

	// GlobalResourceTypeUser: user config resource type
	GlobalResourceTypeUser = "user"

	// GlobalResourceTypeWg: wg config resource type
	GlobalResourceTypeWg = "wg"

	// GlobalResourceTypeWgNamespace: wg config resource type
	GlobalResourceTypeWgNamespace = "wg-namespace"

	// GlobalResourceTypeTaiNamespace: tai config resource type
	GlobalResourceTypeTaiNamespace = "tai-namespace"

	// GlobalResourceTypeTai: tai config resource type
	GlobalResourceTypeTai = "tai"

	// GlobalResourceTypeApiKey: pre-configured api keys
	GlobalResourceTypeApiKey = "api-key"

	// GlobalResourceTypeLink: link global resource type
	GlobalResourceTypeLink = "link"
)
