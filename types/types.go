package types

import (
	jwt "github.com/dgrijalva/jwt-go"
)

// User represents an application user
type User struct {
	ID           int    `json:"id"`
	Login        string `json:"login"`
	Name         string `json:"name"`
	Surname      string `json:"surname"`
	Role         string `json:"role"`
	PasswordHash string `json:"passwordHash"`
	Password     string `json:"password,omitempty"`
}

type JWTPayload struct {
	User
	jwt.StandardClaims
}

// JwtToken represents a JWT token
type JwtToken struct {
	Token string `json:"token"`
}
