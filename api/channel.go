package api

import (
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore/events"
)

type Encrypted []byte

type Channel struct {
	ID keys.ID `json:"id" msgpack:"id"`

	Index     int64  `json:"idx,omitempty" msgpack:"idx,omitempty"`
	Timestamp int64  `json:"ts,omitempty" msgpack:"ts,omitempty"`
	Token     string `json:"token,omitempty" msgpack:"token,omitempty"`

	Info Encrypted `json:"info,omitempty" msgpack:"info,omitempty"`

	// For team channels
	Team    keys.ID   `json:"team,omitempty" msgpack:"team,omitempty"`
	TeamKey Encrypted `json:"teamKey,omitempty" msgpack:"teamKey,omitempty"`

	// For user channels
	UserKey Encrypted `json:"userKey,omitempty" msgpack:"userKey,omitempty"`
}

func (c *Channel) DecryptInfo(key *keys.EdX25519Key) *ChannelInfo {
	var info ChannelInfo
	if err := Decrypt(c.Info, &info, key); err != nil {
		return nil
	}
	return &info
}

type UserKey struct {
	User keys.ID   `json:"user"`
	Key  Encrypted `json:"key"`
}

type ChannelCreateRequest struct {
	Info Encrypted `json:"info"`

	UserKeys []*UserKey `json:"userKeys,omitempty"`

	Team    keys.ID   `json:"team,omitempty"`
	TeamKey Encrypted `json:"teamKey,omitempty"`
}

type ChannelToken struct {
	Channel keys.ID `json:"channel"`
	Token   string  `json:"token"`
}

type MesssagesResponse struct {
	Messages  []*events.Event `json:"msgs" msgpack:"msgs"`
	Index     int64           `json:"idx" msgpack:"idx"`
	Truncated bool            `json:"truncated,omitempty" msgpack:"trunc,omitempty"`
}

type ChannelsResponse struct {
	Channels []*Channel `json:"channels,omitempty" msgpack:"channels,omitempty"`
}
