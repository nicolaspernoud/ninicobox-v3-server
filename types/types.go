package types

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

// JwtToken represents a JWT token
type JwtToken struct {
	Token string `json:"token"`
}
