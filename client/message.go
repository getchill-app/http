package client

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http/client"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

type Messages struct {
	Messages  []*api.Message
	Index     int64
	Truncated bool
}

// SendMessage sends message data to the channel.
// Data is encrypted with the channel key before saving.
func (c *Client) SendMessage(ctx context.Context, message *api.Message, channel *keys.EdX25519Key, sender *keys.EdX25519Key) error {
	if channel == nil {
		return errors.Errorf("no api key")
	}

	b, _ := msgpack.Marshal(message)

	encrypted := api.EncryptMessage(b, channel, sender)

	path := dstore.Path("channel", channel.ID(), "messages")
	start := time.Time{}
	total := int64(0)
	progress := func(n int64) {
		total += n
		if start.IsZero() {
			logger.Debugf("Sending request body...")
			start = time.Now()
		}
		if n == 0 {
			logger.Debugf("Sent request body (%d, %s)", total, time.Since(start))
		}
	}

	if _, err := c.Request(ctx, &client.Request{Method: "POST", Path: path, Body: encrypted, Key: channel, Progress: progress}); err != nil {
		return errors.Wrapf(err, "failed to post message")
	}
	return nil
}

// Messages.
// If truncated, there are more results if you call again with the new index.
func (c *Client) Messages(ctx context.Context, channel *keys.EdX25519Key, index int64) (*Messages, error) {
	if channel == nil {
		return nil, errors.Errorf("no channel key")
	}
	path := dstore.Path("channel", channel.ID(), "messages")
	params := url.Values{}
	if index != 0 {
		params.Add("idx", strconv.FormatInt(index, 10))
	}

	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Params: params, Key: channel})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}

	var out api.MesssagesResponse
	if err := msgpack.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}

	msgs := []*api.Message{}
	for _, e := range out.Messages {

		b, pk, err := api.DecryptMessage(e.Data, channel)
		if err != nil {
			return nil, err
		}

		var msg api.Message
		if err := msgpack.Unmarshal(b, &msg); err != nil {
			return nil, err
		}

		if !keys.X25519Match(msg.Sender, pk.ID()) {
			return nil, errors.Errorf("message sender mismatch")
		}

		msg.RemoteIndex = e.Index
		msg.RemoteTimestamp = e.Timestamp

		msgs = append(msgs, &msg)
	}

	return &Messages{
		Messages:  msgs,
		Index:     out.Index,
		Truncated: out.Truncated,
	}, nil
}
