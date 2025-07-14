// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

// This is a crude way of trying to show an icon to user/admin.
// Ideally we should let the client do the following and provide the info
// from the client but it may require sudo and a bit of an issue
// "sudo dmidecode --string chassis-type"
func DeviceTypeFromOS(os string) string {
	if os == "android" || os == "ios" {
		return "mobile"
	}
	// Any more OS we can do?
	return "laptop"
}