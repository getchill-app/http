package server

import (
	"encoding/json"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

func (s *Server) postAccountAuth(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())

	request := c.Request()
	ctx := request.Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	// Auth
	acct, err := s.authAccount(c, "aid", body)
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	aid := acct.KID

	var accountAuth api.AccountAuth
	if err := json.Unmarshal(body, &accountAuth); err != nil {
		return s.ErrBadRequest(c, err)
	}

	path := dstore.Path("accounts", aid, "auths", accountAuth.ID)
	if err := s.fi.Create(ctx, path, dstore.From(accountAuth)); err != nil {
		return s.ErrResponse(c, err)
	}

	var resp struct{}
	return JSON(c, http.StatusOK, resp)
}

func (s *Server) getAccountAuths(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())

	request := c.Request()
	ctx := request.Context()

	// Auth
	acct, err := s.authAccount(c, "aid", nil)
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	aid := acct.KID

	path := dstore.Path("accounts", aid, "auths")
	iter, err := s.fi.DocumentIterator(ctx, path)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	defer iter.Release()

	accountAuths := []*api.AccountAuth{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return s.ErrResponse(c, err)
		}
		if doc == nil {
			break
		}
		var accountAuth api.AccountAuth
		if err := doc.To(&accountAuth); err != nil {
			return s.ErrResponse(c, err)
		}
		accountAuths = append(accountAuths, &accountAuth)
	}

	out := api.AccountAuthsResponse{Auths: accountAuths}
	return JSON(c, http.StatusOK, out)
}

func (s *Server) deleteAuth(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())

	request := c.Request()
	ctx := request.Context()

	// Auth
	acct, err := s.authAccount(c, "aid", nil)
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	aid := acct.KID

	id := c.Param("id")
	if id == "" {
		return s.ErrBadRequest(c, errors.Errorf("empty id"))
	}

	path := dstore.Path("accounts", aid, "auths", id)
	ok, err := s.fi.Delete(ctx, path)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if !ok {
		return s.ErrNotFound(c, errors.Errorf("auth not found"))
	}

	var resp struct{}
	return JSON(c, http.StatusOK, resp)
}
