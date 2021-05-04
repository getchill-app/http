package server

import (
	"io/ioutil"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

func (s *Server) listMessages(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "cid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	cid := auth.KID

	// Check if existing
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

	limit := 1000
	path := dstore.Path("channels", cid)
	resp, err := s.events(c, path, limit)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if len(resp.Events) == 0 && resp.Index == 0 {
		return s.ErrNotFound(c, errors.Errorf("channel not found"))
	}
	truncated := false
	if len(resp.Events) >= limit {
		// TODO: This is a lie if the number of results are exactly equal to limit
		truncated = true
	}

	out := &api.MesssagesResponse{
		Messages:  resp.Events,
		Index:     resp.Index,
		Truncated: truncated,
	}

	return Msgpack(c, http.StatusOK, out)
}

func (s *Server) postMessage(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// TODO: max channel size

	if c.Request().Body == nil {
		return s.ErrBadRequest(c, errors.Errorf("no body data"))
	}
	b, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	auth, err := s.auth(c, newAuthRequest("Authorization", "cid", b))
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

	_, idx, err := s.fi.EventsAdd(ctx, path, [][]byte{b})
	if err != nil {
		return err
	}

	// Increment usage
	if _, _, err := s.fi.Increment(ctx, path, "usage", int64(len(b))); err != nil {
		return s.ErrResponse(c, err)
	}

	// If we have a channel token, notify.
	doc, err := s.fi.Get(ctx, path)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if doc != nil {
		var channel Channel
		if err := doc.To(&channel); err != nil {
			return s.ErrResponse(c, err)
		}
		vt := &api.ChannelToken{Channel: cid, Token: channel.Token}
		if err := s.notifyChannel(ctx, vt, idx); err != nil {
			return err
		}
	}
	var out struct{}
	return JSON(c, http.StatusOK, out)
}
