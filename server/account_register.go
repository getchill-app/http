package server

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/badoux/checkmail"
	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

const accountsUnverified = "accounts-unverified"

func (s *Server) putAccountRegister(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	var req api.AccountRegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}

	if err := checkmail.ValidateFormat(req.Email); err != nil {
		return s.ErrBadRequest(c, errors.Errorf("invalid email"))
	}
	email := strings.ToLower(req.Email)

	// If using register code, check that otherwise check email address
	if req.RegisterCode != "" {
		valid, err := s.isRegisterCodeValid(ctx, req.RegisterCode)
		if err != nil {
			return s.ErrResponse(c, err)
		}
		if !valid {
			return s.ErrBadRequest(c, errors.Errorf("invalid code"))
		}
	} else {
		invited, err := s.isEmailInvited(ctx, email)
		if err != nil {
			return s.ErrResponse(c, err)
		}
		if !invited {
			return s.ErrBadRequest(c, errors.Errorf("not invited"))
		}
	}

	// See if there is an existing unverified account
	acct, err := s.findUnverifiedAccountByEmail(ctx, email)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	// TODO: Throttle if already exists
	// TODO: Don't send email if already sent recently
	if acct == nil {
		id := encoding.MustEncode(keys.RandBytes(32), encoding.Base62)
		path := dstore.Path(accountsUnverified, id)
		acct = &api.AccountUnverified{
			ID:    id,
			Email: req.Email,
		}

		if err := s.fi.Create(ctx, path, dstore.From(acct)); err != nil {
			return s.ErrResponse(c, err)
		}
	}

	if err := s.sendEmailVerification(c, acct); err != nil {
		return s.ErrResponse(c, err)
	}
	var out struct{}
	return JSON(c, http.StatusOK, out)
}

func (s *Server) findUnverifiedAccountByEmail(ctx context.Context, email string) (*api.AccountUnverified, error) {
	iter, err := s.fi.DocumentIterator(ctx, accountsUnverified, dstore.Where("email", "==", email))
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
	var acct api.AccountUnverified
	if err := doc.To(&acct); err != nil {
		return nil, err
	}
	return &acct, nil
}

func (s *Server) sendEmailVerification(c echo.Context, acct *api.AccountUnverified) error {
	ctx := c.Request().Context()

	// TODO: Throttle exponential backoff

	verifyCode := keys.RandDigits(6)
	update := struct {
		VerifyAttempt     int       `json:"verifyAttempt"`
		VerifyEmailCode   string    `json:"verifyEmailCode"`
		VerifyEmailCodeAt time.Time `json:"verifyEmailCodeAt"`
	}{
		VerifyAttempt:     0,
		VerifyEmailCode:   verifyCode,
		VerifyEmailCodeAt: s.clock.Now(),
	}

	path := dstore.Path(accountsUnverified, acct.ID)
	if err := s.fi.Set(ctx, path, dstore.From(update), dstore.MergeAll()); err != nil {
		return err
	}

	if s.emailer == nil {
		return errors.Errorf("no emailer set")
	}
	if err := s.emailer.SendVerificationEmail(acct.Email, verifyCode); err != nil {
		return err
	}
	return nil
}

func (s *Server) putAccountInvite(c echo.Context) error {
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

	var req api.AccountRegisterInviteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}

	if err := s.accountInvite(ctx, req.Email, "", aid); err != nil {
		return s.ErrResponse(c, err)
	}

	var out struct{}
	return JSON(c, http.StatusOK, out)
}

func (s *Server) accountInvite(ctx context.Context, email string, registerCode string, from keys.ID) error {
	if email != "" {
		if err := checkmail.ValidateFormat(email); err != nil {
			return newError(http.StatusBadRequest, errors.Errorf("invalid email"))
		}
	}
	invite := api.AccountRegisterInvite{
		Email:        email,
		RegisterCode: registerCode,
	}

	id := encoding.MustEncode(keys.RandBytes(32), encoding.Base62)
	if err := s.fi.Set(ctx, dstore.Path("account-invites", id), dstore.From(invite)); err != nil {
		return err
	}
	return nil
}

func (s *Server) isEmailInvited(ctx context.Context, email string) (bool, error) {
	iter, err := s.fi.DocumentIterator(ctx, "account-invites", dstore.Where("email", "==", email))
	if err != nil {
		return false, err
	}
	defer iter.Release()
	doc, err := iter.Next()
	if err != nil {
		return false, err
	}
	return doc != nil, nil
}

func (s *Server) isRegisterCodeValid(ctx context.Context, registerCode string) (bool, error) {
	iter, err := s.fi.DocumentIterator(ctx, "account-invites", dstore.Where("registerCode", "==", registerCode))
	if err != nil {
		return false, err
	}
	defer iter.Release()
	doc, err := iter.Next()
	if err != nil {
		return false, err
	}
	return doc != nil, nil
}
