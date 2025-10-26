// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package fabric

// Specific resource
const (
	KvStore = "kvstore"
)

type ActionType string

// Resource tye
const (
	// Global Resource
	StoreType = "kvstore"

	// In system, there is only one instance
	OnlyOneService = "only-one-service"

	DatabaseEtcdType      = "database-etcd"
	DatabasePostgressType = "database-postgres"
	DatabaseRedisType     = "database-redis"

	// Sase-manager resource
	EtcdResourceType      = "etcd-resource"
	SupervisorServiceType = "supervisor-service"
	WgServiceType         = "wg-service"
	PopServiceType        = "pop-service"
	TaiServiceType        = "fw-service"

	// Sase-supervisor Resource
	PopInstanceType        = "Pop"
	PopInstanceDownType    = "Pop-Down"
	PopInstanceVppUpType   = "VPP-Up"
	PopInstanceVppDownType = "VPP-Down"
	WgConnType             = "wg"
	FwConnType            = "fw"
	UserType               = "user"
	UserPopConfigType      = "UserPopConfig"
	UserWgConfigType       = "UserWgConfig"
	UserWgStatusType       = "UserWgStatus"
	UserFwConfigType      = "UserFwConfig"
	SystemConfigType       = "SystemConfig"
	SystemConfigRemoveType = "SystemConfigRemove"

	// Resource Action
	ActionCreate  = "create"
	ActionDelete  = "delete"
	ActionOnline  = "go-online"
	ActionOffline = "go-offline"
	ActionChange  = "change"
)
