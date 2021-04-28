package api

import (
	"time"

	"github.com/keys-pub/keys"
)

// AccountRegisterRequest ...
type AccountRegisterRequest struct {
	Email string `json:"email"`
}

type AccountUnverified struct {
	ID    string `json:"id"`
	Email string `json:"email"`

	VerifyAttempt     int       `json:"verifyAttempt"`
	VerifyEmailCode   string    `json:"verifyEmailCode"`
	VerifyEmailCodeAt time.Time `json:"verifyEmailCodeAt,omitempty"`
}

// Account ...
type Account struct {
	KID      keys.ID `json:"kid"`
	Email    string  `json:"email"`
	Username string  `json:"username"`
}

// SendEmailVerificationResponse ...
type SendEmailVerificationResponse struct {
	Email string  `json:"email"`
	KID   keys.ID `json:"kid"`
}

// AccountCreateRequest ...
type AccountCreateRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// AccountResponse ...
type AccountResponse struct {
	Email    string  `json:"email"`
	KID      keys.ID `json:"kid"`
	Username string  `json:"username"`
}

// AccountVault ...
type AccountVault struct {
	Account keys.ID `json:"account"`
	Vault   keys.ID `json:"vault"`
	Token   string  `json:"token"`
	Usage   int64   `json:"usage"`
}

// AccountVaultsResponse ...
type AccountVaultsResponse struct {
	Vaults []*AccountVault `json:"vaults"`
}

type AccountAuth struct {
	ID   string `json:"id"`
	Data []byte `json:"data"` // Encrypted auth data
}

type AccountAuthsResponse struct {
	Auths []*AccountAuth `json:"auths"`
}

// AccountRegisterInviteRequest ...
type AccountRegisterInviteRequest struct {
	Email string `json:"email"`
}

type AccountRegisterInvite struct {
	Email string `json:"email"`
}
