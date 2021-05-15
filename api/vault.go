package api

import (
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore/events"
)

// VaultResponse ...
type VaultResponse struct {
	Vault     []*events.Event `json:"vault" msgpack:"vault"`
	Index     int64           `json:"idx" msgpack:"idx"`
	Truncated bool            `json:"truncated,omitempty" msgpack:"trunc,omitempty"`
}

// VaultStatus ...
type VaultStatus struct {
	ID        keys.ID `json:"id" msgpack:"id"`
	Index     int64   `json:"idx" msgpack:"idx"`
	Timestamp int64   `json:"ts" msgpack:"ts"`
}

// VaultsStatusRequest ...
type VaultsStatusRequest struct {
	Vaults map[keys.ID]string `json:"vaults,omitempty" msgpack:"vaults,omitempty"`
}

// VaultsStatusResponse ...
type VaultsStatusResponse struct {
	Vaults []*VaultStatus `json:"vaults,omitempty" msgpack:"vaults,omitempty"`
}

// Vault ...
type Vault struct {
	ID keys.ID `json:"id" msgpack:"id"`

	Index     int64  `json:"idx,omitempty" msgpack:"idx,omitempty"`
	Timestamp int64  `json:"ts,omitempty" msgpack:"ts,omitempty"`
	Token     string `json:"token,omitempty" msgpack:"token,omitempty"`

	Usage   int64 `json:"usage,omitempty" msgpack:"usage,omitempty"`
	Deleted bool  `json:"del,omitempty" msgpack:"del,omitempty"`

	Team      keys.ID `json:"team" msgpack:"team"`
	CreatedBy keys.ID `json:"createdBy" msgpack:"createdBy"`
}

// VaultToken ...
type VaultToken struct {
	Vault keys.ID `json:"vault"`
	Token string  `json:"token"`
}
