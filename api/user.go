package api

import "github.com/keys-pub/keys"

type User struct {
	KID      keys.ID `json:"kid"`
	Username string  `json:"username"`
}

type UsersLookupRequest struct {
	KIDs []keys.ID `json:"kids"`
}
