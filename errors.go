// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"errors"
)

var (
	// Please keep alphabetical order
	ErrInternalErr         = errors.New("internal error")
	ErrInvalidAuthProvider = errors.New("invalid auth provider")
	ErrSendAgainTooSoon    = errors.New("send again too soon")
	ErrTokenExpired        = errors.New("token expired")
	ErrTokenNotExists      = errors.New("token does not exist")
)
