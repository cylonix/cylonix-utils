// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package optional

func P[T any](v T) *T {
	copy := v
	return &copy
}

func V[T any](p* T, nilV T) T {
	if p == nil {
		return nilV
	}
	return *p
}

func Copy[T any](p *T) *T {
	if p == nil {
		return nil
	}
	return P(*p)
}

func String(p *string) string {
	return V(p, "")
}

func Bool(p *bool) bool {
	return V(p, false)
}

func Int(p *int) int {
	return V(p, 0)
}

func Int64(p *int64) int64 {
	return V(p, int64(0))
}