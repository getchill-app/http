package client

import (
	"context"
	"encoding/json"
	"time"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
)

func (c *Client) OrgCreate(ctx context.Context, org *keys.EdX25519Key, domain string, account *keys.EdX25519Key) error {
	path := dstore.Path("org", org.ID())
	create := &api.OrgCreateRequest{Domain: domain}
	body, err := json.Marshal(create)
	if err != nil {
		return err
	}
	if _, err := c.Request(ctx, &Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}

func (c *Client) OrgSign(org *keys.EdX25519Key, domain string, ts time.Time) (string, error) {
	return api.OrgSign(org, domain, ts)
}
