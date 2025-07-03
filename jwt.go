package utils

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

func GenerateJwtToken(claims map[string]interface{}, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	return token.SignedString([]byte(secret))
}

func ParseJwtToken(tokenString string, secret []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

func ToRandomNumber(src string, length float64) int64 {
	id := uuid.NewSHA1(uuid.Nil, []byte(src)).ID()
	seededRand := rand.New(rand.NewSource(int64(id)))
	return seededRand.Int63n(int64(math.Pow(10, length)))
}

func GetRandomNumber(length float64) int64 {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	return seededRand.Int63n(int64(math.Pow(10, length)))
}
