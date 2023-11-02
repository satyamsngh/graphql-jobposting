package auth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"strings"
)

func GenerateToken(claims jwt.RegisteredClaims) (string, error) {

	var privatePEM, err = os.ReadFile("private.pem")
	if err != nil {
		fmt.Errorf("reading auth private key %w", err)
		return "", err
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privatePEM)
	if err != nil {
		fmt.Errorf("parsing auth private key %w", err)
		return "", err
	}
	tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Signing our token with our private key.
	tokenStr, err := tkn.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("signing token %w", err)
	}

	return tokenStr, nil
}

func ValidateToken(token string) error {
	var c jwt.RegisteredClaims
	// Parse the token with the registered claims.
	publicPEM, err := os.ReadFile("pubkey.pem")
	if err != nil {
		fmt.Errorf("reading auth public key %w", err)
		return err
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicPEM)
	if err != nil {
		fmt.Errorf("parsing auth public key %w", err)
		return err
	}

	tkn, err := jwt.ParseWithClaims(token, &c, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return fmt.Errorf("parsing token %w", err)
	}
	// Check if the parsed token is valid.
	if !tkn.Valid {
		return errors.New("invalid token")
	}
	return nil
}

func ExtractTokenFromHeader(r *http.Request) (string, error) {
	// Get the value of the Authorization header
	authHeader := r.Header.Get("Authorization")

	// Check if the Authorization header is present
	if authHeader == "" {
		return "", errors.New("not able to get token")
	}

	// The Authorization header typically has the format "Bearer <token>"
	parts := strings.Split(authHeader, " ")

	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("len is less then 2")
	}

	return parts[1], nil
}
