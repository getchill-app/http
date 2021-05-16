package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/getchill-app/http/api"
	wsapi "github.com/getchill-app/ws/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

type Encrypted = api.Encrypted

type Channel struct {
	ID keys.ID `json:"id" msgpack:"id"`

	Index     int64  `json:"idx,omitempty"`
	Timestamp int64  `json:"ts,omitempty"`
	Token     string `json:"token,omitempty"`

	Usage   int64 `json:"usage,omitempty"`
	Deleted bool  `json:"del,omitempty"`

	CreatedBy keys.ID   `json:"createdBy,omitempty"`
	Info      Encrypted `json:"info,omitempty"`

	Team    keys.ID   `json:"team,omitempty"`
	TeamKey Encrypted `json:"teamKey,omitempty"`

	Users []keys.ID `json:"users,omitempty"`
}

type UserChannel struct {
	User    keys.ID   `json:"user"`
	Key     Encrypted `json:"key"`
	Channel keys.ID   `json:"channel"`
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

	// Create channel
	create := &Channel{
		ID:        cid,
		CreatedBy: aid,
		Info:      req.Info,
		TeamKey:   req.TeamKey,
	}

	var token string
	if req.Team != "" {
		team, err := s.findTeam(ctx, req.Team)
		if err != nil {
			return s.ErrBadRequest(c, err)
		}
		if team == nil {
			return s.ErrBadRequest(c, errors.Errorf("invalid team"))
		}
		create.Team = team.ID
		token = team.Token
	} else {
		token = s.GenerateToken()
	}
	create.Token = token

	users := []keys.ID{}
	for _, userKey := range req.UserKeys {
		userChannel := &UserChannel{
			User:    userKey.User,
			Channel: cid,
			Key:     userKey.Key,
		}
		userPath := dstore.Path("users", userKey.User, "channels", cid)
		if err := s.fi.Create(ctx, userPath, dstore.From(userChannel)); err != nil {
			return s.ErrResponse(c, err)
		}
		users = append(users, userKey.User)
	}
	create.Users = users

	path := dstore.Path("channels", cid)
	if err := s.fi.Create(ctx, path, dstore.From(create)); err != nil {
		return s.ErrResponse(c, err)
	}

	event := &wsapi.Event{
		Type: wsapi.ChannelsType,
	}
	if err := s.notifyEvent(ctx, event); err != nil {
		s.logger.Errorf("Failed to notify event: %v", err)
	}

	channel := api.Channel{
		ID:    cid,
		Token: token,
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

	auth, err := s.auth(c, newAuthRequest("Authorization", "", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	aid := auth.KID

	cid, err := keys.ParseID(c.Param("cid"))
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

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

	out := &api.Channel{
		ID:        channel.ID,
		Index:     channel.Index,
		Timestamp: channel.Timestamp,
		Info:      channel.Info,
		TeamKey:   channel.TeamKey,
		Team:      channel.Team,
	}

	if channel.Team == "" {
		var uc UserChannel
		ok, err := s.fi.Load(ctx, dstore.Path("users", aid, "channels", cid), &c)
		if err != nil {
			return s.ErrResponse(c, err)
		}
		if ok {
			out.UserKey = uc.Key
		}
	}

	return JSON(c, http.StatusOK, out)
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

	positions, err := s.fi.EventPositions(ctx, []string{path})
	if err != nil {
		return nil, err
	}
	position, ok := positions[path]
	if ok {
		channel.Index = position.Index
		channel.Timestamp = position.Timestamp
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

	// Remove user channels
	userPaths := []string{}
	for _, user := range channel.Users {
		userPaths = append(userPaths, dstore.Path("users", user, "channels", cid))
	}
	if len(userPaths) > 0 {
		if err := s.fi.DeleteAll(ctx, userPaths); err != nil {
			return s.ErrResponse(c, err)
		}
	}

	// Remove messages
	path := dstore.Path("channels", cid)
	if _, err := s.fi.EventsDelete(ctx, path); err != nil {
		return s.ErrResponse(c, err)
	}

	// Set channel deleted
	deleted := &Channel{
		ID:      cid,
		Deleted: true,
	}
	// TODO: Instead of delete/create, overwrite with deleted entry
	if err := s.fi.Create(ctx, path, dstore.From(deleted)); err != nil {
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

func (s *Server) getChannels(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// Auth
	auth, err := s.auth(c, newAuthRequest("Authorization", "", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	aid := auth.KID

	channels := []*api.Channel{}

	// User channels
	ucs, err := s.userChannels(ctx, aid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	channels = append(channels, ucs...)

	// Team channels
	if c.QueryParam("team") != "" {
		tid, err := keys.ParseID(c.QueryParam("team"))
		if err != nil {
			return s.ErrBadRequest(c, errors.Errorf("invalid team"))
		}
		tcs, err := s.teamChannels(ctx, tid)
		if err != nil {
			return s.ErrResponse(c, err)
		}
		channels = append(channels, tcs...)
	}

	out := &api.ChannelsResponse{
		Channels: channels,
	}
	return c.JSON(http.StatusOK, out)
}

func (s *Server) channelsForUser(ctx context.Context, kid keys.ID) ([]*Channel, map[keys.ID]*UserChannel, error) {
	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("users", kid, "channels"))
	if err != nil {
		return nil, nil, err
	}
	defer iter.Release()

	paths := []string{}
	userMap := map[keys.ID]*UserChannel{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, nil, err
		}
		if doc == nil {
			break
		}
		var c UserChannel
		if err := doc.To(&c); err != nil {
			return nil, nil, err
		}
		userMap[c.Channel] = &c
		paths = append(paths, dstore.Path("channels", c.Channel))
	}

	out := []*Channel{}
	docs, err := s.fi.GetAll(ctx, paths)
	if err != nil {
		return nil, nil, err
	}
	for _, doc := range docs {
		var c Channel
		if err := doc.To(&c); err != nil {
			return nil, nil, err
		}
		out = append(out, &c)
	}
	return out, userMap, nil
}

func (s *Server) userChannels(ctx context.Context, aid keys.ID) ([]*api.Channel, error) {
	channels, userMap, err := s.channelsForUser(ctx, aid)
	if err != nil {
		return nil, err
	}
	out, err := s.fillChannels(ctx, channels)
	if err != nil {
		return nil, err
	}
	for _, c := range out {
		uc := userMap[c.ID]
		if uc != nil {
			c.UserKey = uc.Key
		}
	}
	return out, nil
}

func (s *Server) fillChannels(ctx context.Context, channels []*Channel) ([]*api.Channel, error) {
	paths := []string{}
	for _, channel := range channels {
		paths = append(paths, dstore.Path("channels", channel.ID))
	}
	positions, err := s.fi.EventPositions(ctx, paths)
	if err != nil {
		return nil, err
	}
	out := make([]*api.Channel, 0, len(channels))
	for _, channel := range channels {
		path := dstore.Path("channels", channel.ID)
		position, ok := positions[path]
		if ok {
			channel.Index = position.Index
			channel.Timestamp = position.Timestamp
		}
		c := &api.Channel{
			ID:        channel.ID,
			Index:     channel.Index,
			Timestamp: channel.Timestamp,
			Info:      channel.Info,
			Team:      channel.Team,
			TeamKey:   channel.TeamKey,
		}
		out = append(out, c)
	}

	return out, nil
}

func (s *Server) notifyChannel(ctx context.Context, ct *api.ChannelToken, idx int64) error {
	event := &wsapi.Event{
		Type:  wsapi.ChannelType,
		Token: ct.Token,
		Channel: &wsapi.Channel{
			ID:    ct.Channel,
			Index: idx,
		},
	}
	return s.notifyEvent(ctx, event)
}
