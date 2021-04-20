package server

import (
	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

func (s *Server) getUserLookup(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// Auth
	if _, err := s.authAccount(c, "", nil); err != nil {
		return s.ErrForbidden(c, err)
	}
	email := c.QueryParam("email")
	acct, err := s.findAccountByEmail(ctx, email)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if acct == nil {
		return s.ErrNotFound(c, errors.Errorf("account not found"))
	}

	out := &api.User{
		KID:      acct.KID,
		Username: acct.Username,
	}
	return c.JSON(http.StatusOK, out)
}