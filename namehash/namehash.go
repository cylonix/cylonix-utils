package namehash

import (
	"github.com/google/uuid"
)

func New(name string) string {
	return uuid.NewSHA1(uuid.Nil, []byte(name)).String()
}
