package server

import (
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
)

func (s *Server) getConfig(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())

	// Auth
	_, err := s.authAccount(c, "", nil)
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	return JSON(c, http.StatusOK, s.config)
}
