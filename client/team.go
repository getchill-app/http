package client

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/http/client"
	"github.com/pkg/errors"
)

func (c *Client) TeamCreate(ctx context.Context, team *keys.EdX25519Key, account *keys.EdX25519Key) error {
	return c.TeamCreateDomain(ctx, team, account, "")
}

func (c *Client) TeamCreateDomain(ctx context.Context, team *keys.EdX25519Key, account *keys.EdX25519Key, domain string) error {
	path := dstore.Path("team", team.ID())
	create := &api.TeamCreateRequest{Domain: domain}
	body, err := json.Marshal(create)
	if err != nil {
		return err
	}
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}

func (c *Client) Team(ctx context.Context, team *keys.EdX25519Key) (*api.Team, error) {
	path := dstore.Path("team", team.ID())
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Key: team})
	if err != nil {
		return nil, err
	}
	var out api.Team
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TeamSign(team *keys.EdX25519Key, domain string, ts time.Time) (string, error) {
	return api.TeamSign(team, domain, ts)
}

func (c *Client) TeamCreateVault(ctx context.Context, team keys.ID, account *keys.EdX25519Key, vault *keys.EdX25519Key) (*api.Vault, error) {
	ek, err := api.EncryptKey(vault, team)
	if err != nil {
		return nil, err
	}
	path := dstore.Path("team", team, "vault")
	create := &api.TeamVaultCreateRequest{KID: vault.ID().String(), EncyptedKey: ek}
	body, err := json.Marshal(create)
	if err != nil {
		return nil, err
	}
	resp, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account})
	if err != nil {
		return nil, err
	}

	var out api.Vault
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type TeamVaultsOpts struct {
	EncryptedKeys bool
}

func (c *Client) TeamVaults(ctx context.Context, team *keys.EdX25519Key, opts *TeamVaultsOpts) (*api.TeamVaultsResponse, error) {
	if opts == nil {
		opts = &TeamVaultsOpts{}
	}

	path := dstore.Path("team", team.ID(), "vaults")
	params := url.Values{}
	if opts.EncryptedKeys {
		params.Set("ek", "1")
	}

	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Params: params, Key: team})
	if err != nil {
		return nil, err
	}
	var out api.TeamVaultsResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TeamInvite(ctx context.Context, team *keys.EdX25519Key, invite keys.ID, invitedBy *keys.EdX25519Key) error {
	path := dstore.Path("team", team.ID(), "invite")

	auths := []http.AuthHeader{
		{Header: "Authorization", Key: invitedBy},
		{Header: "Authorization-Team", Key: team},
	}
	ek, err := api.EncryptKey(team, invite)
	if err != nil {
		return err
	}
	req := &api.TeamInviteRequest{
		Invite:       invite.String(),
		EncryptedKey: ek,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Auths: auths}); err != nil {
		return err
	}

	return nil
}

func (c *Client) TeamAccountInvites(ctx context.Context, account *keys.EdX25519Key) ([]*api.TeamInvite, error) {
	path := dstore.Path("account", account.ID(), "invites")
	resp, err := c.Request(ctx, client.GET(path, account))
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.Errorf("resource not found")
	}
	var out api.TeamInvitesResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return out.Invites, nil
}

func (c *Client) TeamAccountInvite(ctx context.Context, account *keys.EdX25519Key, team keys.ID) (*api.TeamInvite, error) {
	invites, err := c.TeamAccountInvites(ctx, account)
	if err != nil {
		return nil, err
	}
	for _, invite := range invites {
		if invite.Team == team {
			return invite, nil
		}
	}
	return nil, nil
}
