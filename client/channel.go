package client

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http/client"
	"github.com/pkg/errors"
)

// ChannelCreate creates a channel and returns token.
func (c *Client) ChannelCreate(ctx context.Context, channel *keys.EdX25519Key, info *api.ChannelInfo, account *keys.EdX25519Key) (string, error) {
	logger.Debugf("Create channel %s", channel.ID())
	path := dstore.Path("channel", channel.ID())

	encryptedInfo, err := api.Encrypt(info, channel)
	if err != nil {
		return "", err
	}
	req := &api.ChannelCreateRequest{
		EncryptedInfo: encryptedInfo,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	resp, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account})
	if err != nil {
		return "", err
	}
	var ch api.Channel
	if err := json.Unmarshal(resp.Data, &ch); err != nil {
		return "", err
	}

	return ch.Token, nil
}

func (c *Client) Channel(ctx context.Context, channel *keys.EdX25519Key) (*api.Channel, error) {
	logger.Debugf("Get channel %s", channel.ID())
	path := dstore.Path("channel", channel.ID())
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Key: channel})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	var ch api.Channel
	if err := json.Unmarshal(resp.Data, &ch); err != nil {
		return nil, err
	}

	return &ch, nil
}

func (c *Client) Channels(ctx context.Context, tokens []*api.ChannelToken, account *keys.EdX25519Key) ([]*api.Channel, error) {
	statusReq := &api.ChannelsRequest{
		Channels: map[keys.ID]string{},
	}
	for _, ch := range tokens {
		if ch.Token == "" {
			return nil, errors.Errorf("empty token")
		}
		statusReq.Channels[ch.Channel] = ch.Token
	}

	body, err := json.Marshal(statusReq)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	resp, err := c.Request(ctx, &client.Request{Method: "POST", Path: "/channels", Params: params, Body: body, Key: account})
	if err != nil {
		return nil, err
	}

	var out api.ChannelsResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	sort.Slice(out.Channels, func(i, j int) bool {
		return out.Channels[i].Timestamp > out.Channels[j].Timestamp
	})
	return out.Channels, nil
}

func (c *Client) ChannelDelete(ctx context.Context, key *keys.EdX25519Key) error {
	path := dstore.Path("channel", key.ID())
	if _, err := c.Request(ctx, &client.Request{Method: "DELETE", Path: path, Key: key}); err != nil {
		return err
	}
	return nil
}
