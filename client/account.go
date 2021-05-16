package client

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/getchill-app/http/api"
	"github.com/getchill-app/keyring/auth"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http/client"
)

// Register account.
// registerCode is optional if email address was invited explicitly.
func (c *Client) AccountRegister(ctx context.Context, email string, registerCode string) error {
	path := "/account/register"
	body, _ := json.Marshal(&api.AccountRegisterRequest{Email: email, RegisterCode: registerCode})
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body}); err != nil {
		return err
	}
	return nil
}

func (c *Client) AccountInvite(ctx context.Context, email string, account *keys.EdX25519Key) error {
	path := "/account/invite"
	body, _ := json.Marshal(&api.AccountRegisterInviteRequest{Email: email})
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}

func (c *Client) AccountCreate(ctx context.Context, account *keys.EdX25519Key, email string, verifyEmailCode string) error {
	path := dstore.Path("account", account.ID())
	body, _ := json.Marshal(&api.AccountCreateRequest{Email: email, VerifyEmailCode: verifyEmailCode})
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}

func (c *Client) Account(ctx context.Context, account *keys.EdX25519Key) (*api.AccountResponse, error) {
	path := "/account"
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

func (c *Client) AccountSetUsername(ctx context.Context, username string, account *keys.EdX25519Key) error {
	path := "/account/username"
	params := url.Values{}
	params.Set("username", username)
	_, err := c.Request(ctx, &client.Request{Method: "POST", Path: path, Params: params, Key: account})
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) AccountAuthSave(ctx context.Context, auth *auth.Auth, account *keys.EdX25519Key) error {
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
