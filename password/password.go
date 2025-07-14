// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package password

import (
	"unicode"

	gp "github.com/sethvargo/go-password/password"
	"golang.org/x/crypto/bcrypt"
)

// Password package encapsulates the hashing algorithm so that we can have
// consistent hashing algorithm across the sase modules.

// NewHash generates a new hash for the password.
func NewHash(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// CompareToHash compares hash with its plain text equivalent.
func CompareToHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// IsHash checks if a string is a bcrypt hash by checking if bcrypt.Cost()
// can decode it successfully or not.
func IsHash(s string) bool {
	if _, err := bcrypt.Cost([]byte(s)); err != nil {
		return false
	}
	return true
}

func IsValid(password string) bool {
	if len(password) < 8 {
		return false
	}
	// MD5 is 128 bits and 32 hex byte.
	// If API requester already MD5 hashed the password. Don't hash it.
	if len(password) >= 32 {
		return true
	}
    letters := 0
	x := 2 // At least 2 letters.
	var number, upper, special, xOrMore bool
    for _, c := range password {
        switch {
        case unicode.IsNumber(c):
            number = true
        case unicode.IsUpper(c):
            upper = true
            letters++
        case unicode.IsPunct(c) || unicode.IsSymbol(c):
            special = true
        case unicode.IsLetter(c) || c == ' ':
            letters++
        default:
        }
    }
    xOrMore = letters >= x
	return number && upper && special && xOrMore
}

func New() (string, error) {
	return gp.Generate(8, 2, 2, false, false)
}