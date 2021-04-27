package client

import (
	"context"
	"net/url"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http/client"
)

// ShareSeal shares a secret with expiry.
func (c *Client) ShareSeal(ctx context.Context, key *keys.EdX25519Key, account *keys.EdX25519Key, data []byte, expire time.Duration) error {
	encrypted := keys.BoxSeal(data, key.X25519Key().PublicKey(), key.X25519Key())

	path := dstore.Path("share", key.ID())
	vals := url.Values{}
	vals.Set("expire", expire.String())
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Params: vals, Body: encrypted, Key: account}); err != nil {
		return err
	}
	return nil
}

// ShareOpen opens a secret.
func (c *Client) ShareOpen(ctx context.Context, key *keys.EdX25519Key, account *keys.EdX25519Key) ([]byte, error) {
	path := dstore.Path("share", key.ID())
	vals := url.Values{}
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Params: vals, Key: account})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}

	decrypted, err := keys.BoxOpen(resp.Data, key.X25519Key().PublicKey(), key.X25519Key())
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
