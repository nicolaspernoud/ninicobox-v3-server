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

// JWTPayload represents the payload of a JWT
type JWTPayload struct {
	User
	jwt.StandardClaims
}

// JwtToken represents a JWT token
type JwtToken struct {
	Token string `json:"token"`
}

// FileACL represents an ACL for an directory expose with webdav
type FileACL struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Directory   string   `json:"directory"`
	Roles       []string `json:"roles"`
	Permissions string   `json:"permissions"`
}
