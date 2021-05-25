package api

import "github.com/keys-pub/keys"

type User struct {
	KID  keys.ID `json:"kid"`
	Name string  `json:"name"`
}

type UsersLookupRequest struct {
	KIDs []keys.ID `json:"kids"`
}

type UsersResponse struct {
	Users []*User `json:"users"`
	Index int64   `json:"idx"`
}
