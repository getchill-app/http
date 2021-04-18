package client

import (
	"context"
	"encoding/json"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http/client"
	"github.com/keys-pub/vault/auth"
)

func (c *Client) AccountRegister(ctx context.Context, email string) error {
	path := "/account/register"
	body, _ := json.Marshal(&api.AccountCreateRequest{Email: email})
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body}); err != nil {
		return err
	}
	return nil
}

func (c *Client) AccountRegisterInvite(ctx context.Context, account *keys.EdX25519Key, email string) error {
	path := "/account/register/invite"
	body, _ := json.Marshal(&api.AccountRegisterInviteRequest{Email: email})
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}

func (c *Client) AccountCreate(ctx context.Context, account *keys.EdX25519Key, email string, code string) error {
	path := dstore.Path("account", account.ID())
	body, _ := json.Marshal(&api.AccountCreateRequest{Email: email, Code: code})
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}

func (c *Client) Account(ctx context.Context, account *keys.EdX25519Key) (*api.AccountResponse, error) {
	path := dstore.Path("account", account.ID())
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Key: account})
	if err != nil {
		return nil, err
	}
	var out api.AccountResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AccountAuthSave(ctx context.Context, account *keys.EdX25519Key, auth *auth.Auth) error {
	path := dstore.Path("account", account.ID(), "auths")

	encrypted, err := secretBoxMarshal(auth, account.Seed())
	if err != nil {
		return err
	}
	accountAuth := api.AccountAuth{
		ID:   auth.ID,
		Data: encrypted,
	}
	body, err := json.Marshal(accountAuth)
	if err != nil {
		return err
	}

	if _, err := c.Request(ctx, &client.Request{Method: "POST", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}

func (c *Client) AccountAuths(ctx context.Context, account *keys.EdX25519Key) ([]*auth.Auth, error) {
	path := dstore.Path("account", account.ID(), "auths")
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Key: account})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}

	var out api.AccountAuthsResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}

	auths := []*auth.Auth{}
	for _, accountAuth := range out.Auths {
		var auth auth.Auth
		if err := secretBoxUnmarshal(accountAuth.Data, &auth, account.Seed()); err != nil {
			return nil, err
		}

		auths = append(auths, &auth)
	}

	return auths, nil
}
