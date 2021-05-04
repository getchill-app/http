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

func (c *Client) TeamCreateChannel(ctx context.Context, team keys.ID, account *keys.EdX25519Key, channel *keys.EdX25519Key) (*api.Vault, error) {
	ek, err := api.EncryptKey(channel, team)
	if err != nil {
		return nil, err
	}
	path := dstore.Path("team", team, "channel")
	create := &api.TeamChannelCreateRequest{KID: channel.ID().String(), EncyptedKey: ek}
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

func (c *Client) TeamChannels(ctx context.Context, team *keys.EdX25519Key, opts *TeamVaultsOpts) (*api.TeamChannelsResponse, error) {
	if opts == nil {
		opts = &TeamVaultsOpts{}
	}

	path := dstore.Path("team", team.ID(), "channels")
	params := url.Values{}
	if opts.EncryptedKeys {
		params.Set("ek", "1")
	}

	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Params: params, Key: team})
	if err != nil {
		return nil, err
	}
	var out api.TeamChannelsResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TeamInvite(ctx context.Context, team *keys.EdX25519Key, email string, account *keys.EdX25519Key) (string, error) {
	otk := keys.GenerateEdX25519Key()
	ek := keys.CryptoBoxSeal(team.Seed()[:], otk.X25519Key().PublicKey())

	path := dstore.Path("/team/invite", otk.ID())
	req := &api.TeamInviteRequest{
		EncryptedKey: ek,
		Email:        email,
	}
	body, _ := json.Marshal(req)
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
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

	path := dstore.Path("/team/invite", otk.ID())
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Key: account})
	if err != nil {
		return nil, err
	}
	var out api.TeamInviteResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}

	decrypted, err := keys.CryptoBoxSealOpen(out.EncryptedKey, otk.X25519Key())
	if err != nil {
		return nil, err
	}
	if len(decrypted) != 32 {
		return nil, errors.Errorf("invalid key")
	}

	return keys.NewEdX25519KeyFromSeed(keys.Bytes32(decrypted)), nil
}
