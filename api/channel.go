package api

import (
	"github.com/keys-pub/keys"
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

// ChannelInfo for setting channel name or description.
type ChannelInfo struct {
	Name        string `json:"name,omitempty" msgpack:"name,omitempty"`
	Description string `json:"desc,omitempty" msgpack:"desc,omitempty"`
	Topic       string `json:"topic,omitempty" msgpack:"topic,omitempty"`
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

type ChannelUsersAddRequest struct {
	UserKeys []*UserKey `json:"userKeys,omitempty"`
}

type ChannelUsersRemoveRequest struct {
	Users []keys.ID `json:"users,omitempty"`
}

type ChannelUsersResponse struct {
	Users []keys.ID `json:"users,omitempty"`
}

type ChannelToken struct {
	Channel keys.ID `json:"channel"`
	Token   string  `json:"token"`
}

type MesssagesResponse struct {
	Messages  []*Event `json:"msgs" msgpack:"msgs"`
	Index     int64    `json:"idx" msgpack:"idx"`
	Truncated bool     `json:"truncated,omitempty" msgpack:"trunc,omitempty"`
}

type ChannelsResponse struct {
	Channels []*Channel `json:"channels,omitempty" msgpack:"channels,omitempty"`
}
