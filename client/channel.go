package client

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http/client"
)

func (c *Client) ChannelCreateWithTeam(ctx context.Context, channel *keys.EdX25519Key, info *api.ChannelInfo, team keys.ID, account *keys.EdX25519Key) (string, error) {
	return c.channelCreate(ctx, channel, info, team, nil, account)
}

func (c *Client) ChannelCreateWithUsers(ctx context.Context, channel *keys.EdX25519Key, info *api.ChannelInfo, users []keys.ID, account *keys.EdX25519Key) (string, error) {
	return c.channelCreate(ctx, channel, info, "", users, account)
}

func (c *Client) channelCreate(ctx context.Context, channel *keys.EdX25519Key, info *api.ChannelInfo, team keys.ID, users []keys.ID, account *keys.EdX25519Key) (string, error) {
	logger.Debugf("Create channel %s", channel.ID())
	path := dstore.Path("channel", channel.ID())

	encryptedInfo, err := api.Encrypt(info, channel)
	if err != nil {
		return "", err
	}
	req := &api.ChannelCreateRequest{
		Info: encryptedInfo,
		Team: team,
	}

	userKeys := []*api.UserKey{}
	for _, user := range users {
		uk, err := api.EncryptKey(channel, user)
		if err != nil {
			return "", err
		}
		userKeys = append(userKeys, &api.UserKey{User: user, Key: uk})
	}
	req.UserKeys = userKeys

	if team != "" {
		tk, err := api.EncryptKey(channel, team)
		if err != nil {
			return "", err
		}
		req.TeamKey = tk
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	resp, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account})
	if err != nil {
		return "", err
	}
	var ch api.Channel
	if err := json.Unmarshal(resp.Data, &ch); err != nil {
		return "", err
	}

	return ch.Token, nil
}

func (c *Client) Channel(ctx context.Context, channel *keys.EdX25519Key, account *keys.EdX25519Key) (*api.Channel, error) {
	logger.Debugf("Get channel %s", channel.ID())
	path := dstore.Path("channel", channel.ID())
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Key: account})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	var ch api.Channel
	if err := json.Unmarshal(resp.Data, &ch); err != nil {
		return nil, err
	}

	return &ch, nil
}

func (c *Client) ChannelUsers(ctx context.Context, channel *keys.EdX25519Key) ([]keys.ID, error) {
	path := dstore.Path("channel", channel.ID(), "users")

	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Key: channel})
	if err != nil {
		return nil, err
	}

	var out api.ChannelUsersResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

func (c *Client) ChannelUsersAdd(ctx context.Context, channel *keys.EdX25519Key, users []keys.ID) error {
	req := &api.ChannelUsersAddRequest{}

	userKeys := []*api.UserKey{}
	for _, user := range users {
		uk, err := api.EncryptKey(channel, user)
		if err != nil {
			return err
		}
		userKeys = append(userKeys, &api.UserKey{User: user, Key: uk})
	}
	req.UserKeys = userKeys

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	path := dstore.Path("channel", channel.ID(), "users/add")

	resp, err := c.Request(ctx, &client.Request{Method: "POST", Path: path, Body: body, Key: channel})
	if err != nil {
		return err
	}
	var ch api.Channel
	if err := json.Unmarshal(resp.Data, &ch); err != nil {
		return err
	}

	return nil
}

func (c *Client) ChannelUsersRemove(ctx context.Context, channel *keys.EdX25519Key, users []keys.ID) error {
	req := &api.ChannelUsersRemoveRequest{Users: users}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	path := dstore.Path("channel", channel.ID(), "users/remove")

	resp, err := c.Request(ctx, &client.Request{Method: "POST", Path: path, Body: body, Key: channel})
	if err != nil {
		return err
	}
	var ch api.Channel
	if err := json.Unmarshal(resp.Data, &ch); err != nil {
		return err
	}

	return nil
}

func (c *Client) Channels(ctx context.Context, team keys.ID, account *keys.EdX25519Key) ([]*api.Channel, error) {
	params := url.Values{}
	if team != "" {
		params.Set("team", team.String())
	}
	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: "/channels", Params: params, Key: account})
	if err != nil {
		return nil, err
	}

	var out api.ChannelsResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	sort.Slice(out.Channels, func(i, j int) bool {
		return out.Channels[i].Timestamp > out.Channels[j].Timestamp
	})
	return out.Channels, nil
}

func (c *Client) ChannelDelete(ctx context.Context, key *keys.EdX25519Key) error {
	path := dstore.Path("channel", key.ID())
	if _, err := c.Request(ctx, &client.Request{Method: "DELETE", Path: path, Key: key}); err != nil {
		return err
	}
	return nil
}
