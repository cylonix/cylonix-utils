// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import "time"

const (
	DefaultNamespace  = "default"
	SysAdminNamespace = "sysadmin"

	DefaultUserTier               = "default"
	DefaultUserTierDescription    = "default user tier"
	DefaultUserTierMaxUserCount   = 20
	DefaultUserTierMaxDeviceCount = 200

	// ElasticSearch
	MaxElasticSearchOffset        = 10000
	MaxElasticSearchCloudDstIPTop = 10000
	MaxElasticSearchAggrTop       = 10
	ElasticSearchShardRatio       = 2
	ElasticSearchIndexPrefix      = "sase-flow-"

	// Schedule Timer
	DefaultAppSumInterval = time.Minute * 5

	// Path selection modes
	PathSelectionModeGlobalLabel = "everyone"
	PathSelectionModeKeyName     = "path-selection-mode"
	PathSelectionModeGlobal      = "global"
	PathSelectionModeSingle      = "single"
	PathSelectionModeDefault     = PathSelectionModeGlobal

	// fw
	FwEndpointKey   = "sase-instance"
	FwEndpointValue = "wg-endpoint"
)

func GetEsNamespaceIndex(namespace string) string {
	return ElasticSearchIndexPrefix + namespace
}

func IsDefaultNamespace(namespace string) bool {
	return namespace == DefaultNamespace
}
