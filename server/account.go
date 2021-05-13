package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

func (s *Server) putAccount(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	auth, err := s.auth(c, newAuthRequest("Authorization", "aid", body))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	aid := auth.KID

	// TODO: Random delay/throttle so can't time error paths?

	var req api.AccountCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}
	if err := checkmail.ValidateFormat(req.Email); err != nil {
		return s.ErrBadRequest(c, errors.Errorf("invalid email"))
	}

	unverifiedAcct, err := s.findUnverifiedAccountByEmail(ctx, req.Email)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if unverifiedAcct == nil {
		return s.ErrBadRequest(c, errors.Errorf("invalid code"))
	}

	// Increment attempt
	unverifiedPath := dstore.Path("accounts-unverified", unverifiedAcct.ID)
	attempts, _, err := s.fi.Increment(ctx, unverifiedPath, "verifyAttempt", 1)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if attempts > 5 {
		return s.ErrBadRequest(c, errors.Errorf("invalid code"))
	}

	if s.clock.Now().Sub(unverifiedAcct.VerifyEmailCodeAt) > time.Hour {
		return s.ErrBadRequest(c, errors.Errorf("invalid code"))
	}
	if subtle.ConstantTimeCompare([]byte(unverifiedAcct.VerifyEmailCode), []byte(req.VerifyEmailCode)) != 1 {
		return s.ErrBadRequest(c, errors.Errorf("invalid code"))
	}

	// Create account
	path := dstore.Path("accounts", aid)
	acct := &api.Account{
		Email: req.Email,
		KID:   aid,
	}

	if err := s.fi.Create(ctx, path, dstore.From(acct)); err != nil {
		switch err.(type) {
		case dstore.ErrPathExists:
			return s.ErrConflict(c, errors.Errorf("account already exists"))
		}
		return s.ErrResponse(c, err)
	}

	var out struct{}
	return JSON(c, http.StatusOK, out)
}

func (s *Server) getAccount(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	acct, err := s.authAccount(c, "", nil)
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	out := &api.AccountResponse{
		Email:    acct.Email,
		KID:      acct.KID,
		Username: acct.Username,
	}
	return c.JSON(http.StatusOK, out)
}

func (s *Server) findAccount(ctx context.Context, kid keys.ID) (*api.Account, error) {
	if kid == "" {
		return nil, errors.Errorf("empty kid")
	}
	path := dstore.Path("accounts", kid)

	doc, err := s.fi.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}

	var acct api.Account
	if err := doc.To(&acct); err != nil {
		return nil, err
	}

	return &acct, nil
}

func (s *Server) findAccountByEmail(ctx context.Context, email string) (*api.Account, error) {
	iter, err := s.fi.DocumentIterator(ctx, "accounts", dstore.Where("email", "==", strings.ToLower(email)))
	if err != nil {
		return nil, err
	}
	defer iter.Release()
	doc, err := iter.Next()
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}
	var acct api.Account
	if err := doc.To(&acct); err != nil {
		return nil, err
	}
	return &acct, nil
}

func (s *Server) postAccountUsername(c echo.Context) error {
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

	if acct.Username != "" {
		return s.ErrBadRequest(c, errors.Errorf("username already set"))
	}

	username := c.QueryParam("username")

	if len(username) > 16 {
		return s.ErrBadRequest(c, errors.Errorf("invalid username"))
	}
	match, _ := regexp.MatchString("^[a-z0-9]*$", username)
	if !match {
		return s.ErrBadRequest(c, errors.Errorf("invalid username"))
	}

	// Check unique
	indexPath := dstore.Path("index", "accounts", "usernames", username)
	index := struct {
		KID keys.ID `json:"kid"`
	}{
		KID: acct.KID,
	}
	if err := s.fi.Create(ctx, indexPath, dstore.From(index)); err != nil {
		return err
	}

	update := struct {
		Username string `json:"username"`
	}{
		Username: username,
	}

	path := dstore.Path("accounts", aid)
	if err := s.fi.Set(ctx, path, dstore.From(update), dstore.MergeAll()); err != nil {
		return err
	}

	var out struct{}
	return c.JSON(http.StatusOK, out)
}
