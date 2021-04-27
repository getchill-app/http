package client

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/http/client"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
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

func (c *Client) TeamInvite(ctx context.Context, team *keys.EdX25519Key, account *keys.EdX25519Key) (string, error) {
	otk := keys.GenerateEdX25519Key()

	invite := &api.TeamInvite{
		Key: team.Seed()[:],
	}
	b, err := msgpack.Marshal(invite)
	if err != nil {
		return "", err
	}

	if err := c.ShareSeal(ctx, otk, account, b[:], time.Minute*60); err != nil {
		return "", err
	}

	phrase := encoding.MustEncode(otk.Seed()[:], encoding.BIP39)

	return phrase, nil
}

func (c *Client) TeamInviteOpen(ctx context.Context, phrase string, account *keys.EdX25519Key) (*keys.EdX25519Key, error) {
	seed, err := encoding.PhraseToBytes(phrase, true)
	if err != nil {
		return nil, errors.Errorf("invalid phrase")
	}

	otk := keys.NewEdX25519KeyFromSeed(seed)

	b, err := c.ShareOpen(ctx, otk, account)
	if err != nil {
		return nil, err
	}
	var invite api.TeamInvite
	if err := msgpack.Unmarshal(b, &invite); err != nil {
		return nil, err
	}

	if len(invite.Key) != 32 {
		return nil, errors.Errorf("invalid invite key")
	}

	return keys.NewEdX25519KeyFromSeed(keys.Bytes32(invite.Key)), nil
}
