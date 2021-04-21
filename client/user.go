package client

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http/client"
)

func (c *Client) UserLookup(ctx context.Context, field string, value string, account *keys.EdX25519Key) (*api.User, error) {
	path := "/user/lookup"
	params := url.Values{}
	params.Set(field, value)
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Params: params, Key: account})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	var out api.User
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
