package server

import (
	"encoding/json"

	"github.com/getchill-app/http/api"
	wsapi "github.com/getchill-app/ws/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

func (s *Server) getChannelUsers(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// Auth
	auth, err := s.auth(c, newAuthRequest("Authorization", "cid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	cid := auth.KID

	channelUserPath := dstore.Path("channels", cid, "users")
	iter, err := s.fi.DocumentIterator(ctx, channelUserPath)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	defer iter.Release()

	users := []keys.ID{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return s.ErrResponse(c, err)
		}
		if doc == nil {
			break
		}
		var uc UserChannel
		if err := doc.To(&uc); err != nil {
			return s.ErrResponse(c, err)
		}
		users = append(users, uc.User)
	}
	out := api.ChannelUsersResponse{Users: users}
	return JSON(c, http.StatusOK, out)
}

func (s *Server) postChannelUsersAdd(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	// Auth
	auth, err := s.auth(c, newAuthRequest("Authorization", "cid", body))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	cid := auth.KID

	var req api.ChannelUsersAddRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}

	// Check if existing
	channel, err := s.channel(ctx, cid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if channel == nil {
		return s.ErrNotFound(c, errors.Errorf("channel not found"))
	}
	if channel.Deleted {
		return s.ErrBadRequest(c, errors.Errorf("channel was deleted"))
	}

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

		channelUserPath := dstore.Path("channels", cid, "users", userKey.User)
		if err := s.fi.Create(ctx, channelUserPath, dstore.From(userChannel)); err != nil {
			return s.ErrResponse(c, err)
		}
	}

	event := &wsapi.Event{
		Type: wsapi.ChannelsType,
	}
	if err := s.notifyEvent(ctx, event); err != nil {
		s.logger.Errorf("Failed to notify event: %v", err)
	}

	var out struct{}
	return JSON(c, http.StatusOK, out)
}

func (s *Server) postChannelUsersRemove(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	// Auth
	auth, err := s.auth(c, newAuthRequest("Authorization", "cid", body))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	cid := auth.KID

	var req api.ChannelUsersRemoveRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}

	// Check if existing
	channel, err := s.channel(ctx, cid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if channel == nil {
		return s.ErrNotFound(c, errors.Errorf("channel not found"))
	}
	if channel.Deleted {
		return s.ErrBadRequest(c, errors.Errorf("channel was deleted"))
	}

	for _, user := range req.Users {
		userPath := dstore.Path("users", user, "channels", cid)
		if _, err := s.fi.Delete(ctx, userPath); err != nil {
			return s.ErrResponse(c, err)
		}

		channelUserPath := dstore.Path("channels", cid, "users", user)
		if _, err := s.fi.Delete(ctx, channelUserPath); err != nil {
			return s.ErrResponse(c, err)
		}
	}

	event := &wsapi.Event{
		Type: wsapi.ChannelsType,
	}
	if err := s.notifyEvent(ctx, event); err != nil {
		s.logger.Errorf("Failed to notify event: %v", err)
	}

	var out struct{}
	return JSON(c, http.StatusOK, out)
}
