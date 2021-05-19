package api

import (
	"github.com/keys-pub/keys"
)

// MessageCommand encodes other types of messages.
type MessageCommand struct {
	// ChannelInfo sets info.
	ChannelInfo *ChannelInfo `json:"channelInfo,omitempty" msgpack:"channelInfo,omitempty"`
}

// NewMessageForChannelInfo ...
func NewMessageForChannelInfo(channel keys.ID, sender keys.ID, info *ChannelInfo) *Message {
	msg := NewMessage(channel, sender)
	msg.Command = &MessageCommand{ChannelInfo: info}
	return msg
}
