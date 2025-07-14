// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package namehash

import (
	"github.com/google/uuid"
)

func New(name string) string {
	return uuid.NewSHA1(uuid.Nil, []byte(name)).String()
}
