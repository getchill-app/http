package client

import (
	"context"
	"encoding/json"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http/client"
)

func (c *Client) Config(ctx context.Context, account *keys.EdX25519Key) (*api.Config, error) {
	path := "/config"
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Key: account})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	var out api.Config
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
