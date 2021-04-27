package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/keys-pub/keys"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

func (s *Server) putShare(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 512)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	// Auth
	if _, err := s.authAccount(c, "", body); err != nil {
		return s.ErrForbidden(c, err)
	}

	kid, err := keys.ParseID(c.Param("kid"))
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

	expire := time.Minute * 5
	if c.QueryParam("expire") != "" {
		e, err := time.ParseDuration(c.QueryParam("expire"))
		if err != nil {
			return s.ErrBadRequest(c, err)
		}
		expire = e
	}
	const maxExpire = 60 * time.Minute
	if expire > maxExpire {
		return s.ErrBadRequest(c, errors.Errorf("max expire is %s", maxExpire))
	}

	key := fmt.Sprintf("s-%s", kid)
	if err := s.rds.Set(ctx, key, string(body)); err != nil {
		return s.ErrResponse(c, err)
	}

	if err := s.rds.Expire(ctx, key, expire); err != nil {
		return s.ErrResponse(c, err)
	}

	var resp struct{}
	return JSON(c, http.StatusOK, resp)
}

func (s *Server) getShare(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// Auth
	if _, err := s.authAccount(c, "", nil); err != nil {
		return s.ErrForbidden(c, err)
	}

	kid, err := keys.ParseID(c.Param("kid"))
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

	key := fmt.Sprintf("s-%s", kid)
	out, err := s.rds.Get(ctx, key)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if out == "" {
		return s.ErrNotFound(c, nil)
	}
	// Delete after get
	if err := s.rds.Delete(ctx, key); err != nil {
		return s.ErrResponse(c, err)
	}
	return c.Blob(http.StatusOK, echo.MIMEOctetStream, []byte(out))
}
