package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/getchill-app/http/api"
	wsapi "github.com/getchill-app/ws/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/tsutil"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

type Channel struct {
	ID keys.ID `json:"id" msgpack:"id"`

	Index     int64  `json:"idx,omitempty"`
	Timestamp int64  `json:"ts,omitempty"`
	Token     string `json:"token,omitempty"`

	Usage   int64 `json:"usage,omitempty"`
	Deleted bool  `json:"del,omitempty"`

	Team          keys.ID `json:"team,omitempty"`
	CreatedBy     keys.ID `json:"createdBy,omitempty"`
	EncryptedInfo []byte  `json:"info,omitempty"`
	EncryptedKey  []byte  `json:"ek,omitempty"`
}

func (s *Server) putChannel(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	// Auth
	acct, err := s.authAccount(c, "", body)
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	aid := acct.KID

	var req api.ChannelCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}

	cid, err := keys.ParseID(c.Param("cid"))
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

	// Check if existing
	existing, err := s.channel(ctx, cid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if existing != nil {
		if existing.Deleted {
			return s.ErrBadRequest(c, errors.Errorf("channel was deleted"))
		}
		return s.ErrBadRequest(c, errors.Errorf("channel already exists"))
	}

	token := s.GenerateToken()

	// Create channel
	create := &Channel{
		ID:            cid,
		Token:         token,
		CreatedBy:     aid,
		EncryptedInfo: req.EncryptedInfo,
	}
	path := dstore.Path("channels", cid)
	if err := s.fi.Create(ctx, path, dstore.From(create)); err != nil {
		return s.ErrResponse(c, err)
	}

	// Increment account channel count
	channelCount, _, err := s.fi.Increment(ctx, dstore.Path("accounts", aid), "channelCount", 1)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if channelCount > 500 {
		return s.ErrForbidden(c, errors.Errorf("max account channels reached"))
	}

	// Save account channel
	av := &api.AccountChannel{
		Account: aid,
		Channel: cid,
	}
	accountPath := dstore.Path("accounts", aid, "channels", cid)
	if err := s.fi.Create(ctx, accountPath, dstore.From(av)); err != nil {
		return s.ErrResponse(c, err)
	}

	channel, err := s.channel(ctx, cid)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	return JSON(c, http.StatusOK, channel)
}

func (s *Server) putChannelInfo(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	// Auth
	auth, err := s.authAccount(c, "cid", body)
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	cid := auth.KID

	// Check if existing
	existing, err := s.channel(ctx, cid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if existing == nil {
		return s.ErrNotFound(c, errors.Errorf("channel not found"))
	}
	if existing.Deleted {
		return s.ErrBadRequest(c, errors.Errorf("channel was deleted"))
	}

	update := struct {
		Info []byte `json:"info"`
	}{
		Info: body,
	}

	path := dstore.Path("channels", cid)
	if err := s.fi.Set(ctx, path, dstore.From(update), dstore.MergeAll()); err != nil {
		return s.ErrResponse(c, err)
	}

	var out struct{}
	return c.JSON(http.StatusOK, out)
}

func (s *Server) getChannel(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "cid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	channel, err := s.channel(ctx, auth.KID)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if channel == nil {
		return s.ErrNotFound(c, errors.Errorf("channel not found"))
	}
	if channel.Deleted {
		return s.ErrNotFound(c, errors.Errorf("channel was deleted"))
	}

	return JSON(c, http.StatusOK, &api.Channel{
		ID:            channel.ID,
		Index:         channel.Index,
		Timestamp:     channel.Timestamp,
		Token:         channel.Token,
		EncryptedInfo: channel.EncryptedInfo,
		EncryptedKey:  channel.EncryptedKey,
	})
}

func (s *Server) channel(ctx context.Context, kid keys.ID) (*Channel, error) {
	path := dstore.Path("channels", kid)
	var channel Channel
	ok, err := s.fi.Load(ctx, path, &channel)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return &channel, nil
}

func (s *Server) deleteChannel(c echo.Context) error {
	ctx := c.Request().Context()
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())

	auth, err := s.auth(c, newAuthRequest("Authorization", "cid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	cid := auth.KID

	channel, err := s.channel(ctx, cid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if channel == nil {
		return s.ErrNotFound(c, errors.Errorf("channel not found"))
	}
	if channel.Deleted {
		return s.ErrNotFound(c, errors.Errorf("channel was deleted"))
	}

	path := dstore.Path("channels", cid)
	if _, err := s.fi.EventsDelete(ctx, path); err != nil {
		return s.ErrResponse(c, err)
	}

	// Create a deleted channel entry.
	// TODO: Replace channel instead of delete/create.
	create := &Channel{
		ID:      cid,
		Deleted: true,
	}
	if err := s.fi.Create(ctx, path, dstore.From(create)); err != nil {
		return s.ErrResponse(c, err)
	}

	var resp struct{}
	return JSON(c, http.StatusOK, resp)
}

func (s *Server) headChannel(c echo.Context) error {
	ctx := c.Request().Context()
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())

	auth, err := s.auth(c, newAuthRequest("Authorization", "cid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	channel, err := s.channel(ctx, auth.KID)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if channel == nil {
		return s.ErrNotFound(c, errors.Errorf("channel not found"))
	}
	if channel.Deleted {
		return s.ErrNotFound(c, errors.Errorf("channel was deleted"))
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) postChannels(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	// Auth
	if _, err := s.authAccount(c, "", body); err != nil {
		return s.ErrForbidden(c, err)
	}

	var req api.ChannelsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, errors.Errorf("invalid request"))
	}
	paths := []string{}
	for k := range req.Channels {
		kid, err := keys.ParseID(string(k))
		if err != nil {
			return s.ErrBadRequest(c, errors.Errorf("invalid request"))
		}
		paths = append(paths, dstore.Path("channels", kid))
	}

	docs, err := s.fi.GetAll(ctx, paths)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	positions, err := s.fi.EventPositions(ctx, paths)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	channels := make([]*api.Channel, 0, len(docs))
	for _, doc := range docs {
		var channel api.Channel
		if err := doc.To(&channel); err != nil {
			return s.ErrResponse(c, err)
		}
		token := req.Channels[channel.ID]
		if token == "" {
			s.logger.Infof("Missing token for channel %s", channel.ID)
			continue
		}
		if token != channel.Token {
			s.logger.Infof("Invalid token for channel %s", channel.ID)
			continue
		}
		channel.Timestamp = tsutil.Millis(doc.UpdatedAt)
		position := positions[doc.Path]
		if position != nil {
			channel.Index = position.Index
			if position.Timestamp > 0 {
				channel.Timestamp = position.Timestamp
			}
		}
		channels = append(channels, &api.Channel{
			ID:        channel.ID,
			Index:     channel.Index,
			Timestamp: channel.Timestamp,
		})
	}

	out := api.ChannelsResponse{
		Channels: channels,
	}
	return c.JSON(http.StatusOK, out)
}

func (s *Server) notifyChannel(ctx context.Context, t *api.ChannelToken, idx int64) error {
	event := &wsapi.Event{
		Type:  "channel",
		Token: t.Token,
		Channel: &wsapi.Channel{
			KID:   t.Channel,
			Index: idx,
		},
	}
	return s.notifyEvent(ctx, event)
}
