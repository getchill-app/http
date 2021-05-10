package api

import (
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore/events"
)

type Channel struct {
	ID keys.ID `json:"id" msgpack:"id"`

	Index     int64  `json:"idx,omitempty" msgpack:"idx,omitempty"`
	Timestamp int64  `json:"ts,omitempty" msgpack:"ts,omitempty"`
	Token     string `json:"token,omitempty" msgpack:"token,omitempty"`

	// EncryptedKey is encrypted key (using team key)
	EncryptedKey []byte `json:"ek,omitempty" msgpack:"ek,omitempty"`
	// EncryptedInfo is encrypted msgpack api.ChannelInfo
	EncryptedInfo []byte `json:"einfo,omitempty" msgpack:"einfo,omitempty"`
}

func (c *Channel) Info(key *keys.EdX25519Key) *ChannelInfo {
	var info ChannelInfo
	if err := Decrypt(c.EncryptedInfo, &info, key); err != nil {
		return nil
	}
	return &info
}

type ChannelCreateRequest struct {
	EncryptedInfo []byte `json:"einfo"`
}

type MesssagesResponse struct {
	Messages  []*events.Event `json:"msgs" msgpack:"msgs"`
	Index     int64           `json:"idx" msgpack:"idx"`
	Truncated bool            `json:"truncated,omitempty" msgpack:"trunc,omitempty"`
}

type ChannelToken struct {
	Channel keys.ID `json:"channel"`
	Token   string  `json:"token"`
}

type ChannelsRequest struct {
	Channels map[keys.ID]string `json:"channels,omitempty" msgpack:"channels,omitempty"`
}

type ChannelsResponse struct {
	Channels []*Channel `json:"channels,omitempty" msgpack:"channels,omitempty"`
}

type AccountChannel struct {
	Account keys.ID `json:"account"`
	Channel keys.ID `json:"channel"`
}
