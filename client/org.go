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

func (c *Client) OrgCreate(ctx context.Context, org *keys.EdX25519Key, account *keys.EdX25519Key) error {
	return c.OrgCreateDomain(ctx, org, account, "")
}

func (c *Client) OrgCreateDomain(ctx context.Context, org *keys.EdX25519Key, account *keys.EdX25519Key, domain string) error {
	path := dstore.Path("org", org.ID())
	create := &api.OrgCreateRequest{Domain: domain}
	body, err := json.Marshal(create)
	if err != nil {
		return err
	}
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}

func (c *Client) Org(ctx context.Context, org *keys.EdX25519Key) (*api.Org, error) {
	path := dstore.Path("org", org.ID())
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Key: org})
	if err != nil {
		return nil, err
	}
	var out api.Org
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) OrgSign(org *keys.EdX25519Key, domain string, ts time.Time) (string, error) {
	return api.OrgSign(org, domain, ts)
}

func (c *Client) OrgCreateVault(ctx context.Context, org keys.ID, account *keys.EdX25519Key, vault *keys.EdX25519Key) (*api.Vault, error) {
	ek, err := encryptKey(vault, org)
	if err != nil {
		return nil, err
	}
	path := dstore.Path("org", org, "vault")
	create := &api.OrgVaultCreateRequest{KID: vault.ID().String(), EncyptedKey: ek}
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

func encryptKey(key *keys.EdX25519Key, to keys.ID) ([]byte, error) {
	pk, err := keys.NewEdX25519PublicKeyFromID(to)
	if err != nil {
		return nil, err
	}
	encryptedKey := keys.CryptoBoxSeal(key.Seed()[:], pk.X25519PublicKey())
	return encryptedKey, nil
}

func DecryptKey(b []byte, key *keys.EdX25519Key) (*keys.EdX25519Key, error) {
	decrypted, err := keys.CryptoBoxSealOpen(b, key.X25519Key())
	if err != nil {
		return nil, err
	}
	if len(decrypted) != 32 {
		return nil, errors.Errorf("invalid encrypted key")
	}
	return keys.NewEdX25519KeyFromSeed(keys.Bytes32(decrypted)), nil
}

type OrgVaultsOpts struct {
	EncryptedKeys bool
}

func (c *Client) OrgVaults(ctx context.Context, org *keys.EdX25519Key, opts *OrgVaultsOpts) (*api.OrgVaultsResponse, error) {
	if opts == nil {
		opts = &OrgVaultsOpts{}
	}

	path := dstore.Path("org", org.ID(), "vaults")
	params := url.Values{}
	if opts.EncryptedKeys {
		params.Set("ek", "1")
	}

	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Params: params, Key: org})
	if err != nil {
		return nil, err
	}
	var out api.OrgVaultsResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) OrgInvite(ctx context.Context, org *keys.EdX25519Key, invite keys.ID, invitedBy *keys.EdX25519Key) error {
	path := dstore.Path("org", org.ID(), "invite")

	auths := []http.AuthHeader{
		{Header: "Authorization", Key: invitedBy},
		{Header: "Authorization-Org", Key: org},
	}
	ek, err := encryptKey(org, invite)
	if err != nil {
		return err
	}
	req := &api.OrgInviteRequest{
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

func (c *Client) OrgAccountInvites(ctx context.Context, account *keys.EdX25519Key) ([]*api.OrgInvite, error) {
	path := dstore.Path("account", account.ID(), "invites")
	resp, err := c.Request(ctx, client.GET(path, account))
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.Errorf("resource not found")
	}
	var out api.OrgInvitesResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return out.Invites, nil
}

func (c *Client) OrgAccountInvite(ctx context.Context, account *keys.EdX25519Key, org keys.ID) (*api.OrgInvite, error) {
	invites, err := c.OrgAccountInvites(ctx, account)
	if err != nil {
		return nil, err
	}
	for _, invite := range invites {
		if invite.Org == org {
			return invite, nil
		}
	}
	return nil, nil
}
