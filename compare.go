package utils

import "net/netip"

func IsSameNetworkList(from, to *[]netip.Prefix) bool {
	if from == to {
		return true
	}

	if from == nil || to == nil {
		return false
	}

	if len(*from) != len(*to) {
		return false
	}

	for i, val := range *from {
		if val != (*to)[i] {
			return false
		}
	}

	return true
}

func IsSameStringList(from, to *[]string) bool {
	if from == to {
		return true
	}

	if from == nil || to == nil {
		return false
	}

	if len(*from) != len(*to) {
		return false
	}

	for i, val := range *from {
		if val != (*to)[i] {
			return false
		}
	}

	return true
}
