package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
)

func (s *Server) putTeam(c echo.Context) error {
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

	tid, err := keys.ParseID(c.Param("tid"))
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

	var req api.TeamCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}

	token := s.GenerateToken()
	team := &api.Team{
		ID:        tid,
		Domain:    req.Domain,
		CreatedBy: aid,
		Token:     token,
	}

	if req.Domain != "" {
		existing, err := s.findTeamByDomain(ctx, req.Domain)
		if err != nil {
			return s.ErrResponse(c, err)
		}
		if existing != nil {
			return s.ErrConflict(c, errors.Errorf("team domain already exists"))
		}

		// Verify team
		// TODO: Rate limit
		if err := s.verifyTeam(ctx, team); err != nil {
			return s.ErrBadRequest(c, errors.Wrapf(err, "failed to verify domain"))
		}
		team.VerifiedAt = s.clock.Now()
	}

	path := dstore.Path("teams", tid)
	if err := s.fi.Create(ctx, path, dstore.From(team)); err != nil {
		switch err.(type) {
		case dstore.ErrPathExists:
			return s.ErrConflict(c, errors.Errorf("team already exists"))
		}
		return s.ErrResponse(c, err)
	}

	return JSON(c, http.StatusOK, team)
}

func (s *Server) findTeamByDomain(ctx context.Context, domain string) (*api.Team, error) {
	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("teams"), dstore.Where("domain", "==", domain))
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
	var team api.Team
	if err := doc.To(&team); err != nil {
		return nil, err
	}
	return &team, nil
}

func (s *Server) getTeam(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "tid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	team, err := s.findTeam(ctx, auth.KID)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if team == nil {
		return s.ErrNotFound(c, errors.Errorf("team not found"))
	}
	return c.JSON(http.StatusOK, team)
}

func (s *Server) findTeam(ctx context.Context, id keys.ID) (*api.Team, error) {
	if id == "" {
		return nil, errors.Errorf("empty kid")
	}
	path := dstore.Path("teams", id)

	doc, err := s.fi.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, nil
	}

	var team api.Team
	if err := doc.To(&team); err != nil {
		return nil, err
	}

	return &team, nil
}

func (s *Server) verifyTeam(ctx context.Context, team *api.Team) error {
	url := fmt.Sprintf("https://%s/.well-known/getchill.txt", team.Domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	res, err := s.client.Request(ctx, req)
	if err != nil {
		return err
	}
	if err := team.Verify(string(res)); err != nil {
		return err
	}
	return nil
}

func (s *Server) channelsForTeam(ctx context.Context, kid keys.ID) ([]*Channel, error) {
	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("channels"), dstore.Where("team", "==", kid.String()))
	if err != nil {
		return nil, err
	}
	defer iter.Release()

	ovs := []*Channel{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		var ov Channel
		if err := doc.To(&ov); err != nil {
			return nil, err
		}
		ovs = append(ovs, &ov)
	}
	return ovs, nil
}

func (s *Server) teamChannels(ctx context.Context, tid keys.ID) ([]*api.Channel, error) {
	channels, err := s.channelsForTeam(ctx, tid)
	if err != nil {
		return nil, err
	}
	return s.fillChannels(ctx, channels)
}

func (s *Server) putTeamInvite(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 512)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	// Auth
	acct, err := s.authAccount(c, "", body)
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	id, err := keys.ParseID(c.Param("id"))
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

	var req api.TeamInviteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}

	registerCode := keys.RandPhrase()
	if err := s.accountInvite(ctx, req.Email, registerCode, acct.KID); err != nil {
		return s.ErrResponse(c, err)
	}

	invite := api.TeamInvite{
		TeamKey:      req.TeamKey,
		Email:        req.Email,
		RegisterCode: registerCode,
		CreatedAt:    s.clock.Now(),
	}

	// TODO: Invite expiry?

	path := dstore.Path("invites", id)
	if err := s.fi.Set(ctx, path, dstore.From(invite)); err != nil {
		return s.ErrResponse(c, err)
	}

	var resp struct{}
	return JSON(c, http.StatusOK, resp)
}

func (s *Server) getTeamInvite(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// Auth
	acct, err := s.authAccount(c, "", nil)
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	id, err := keys.ParseID(c.Param("id"))
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

	path := dstore.Path("invites", id)
	doc, err := s.fi.Get(ctx, path)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if doc == nil {
		return s.ErrNotFound(c, errors.Errorf("invite not found"))
	}
	// Delete the invite after it is requested
	if _, err := s.fi.Delete(ctx, path); err != nil {
		return s.ErrResponse(c, err)
	}

	var invite api.TeamInvite
	if err := doc.To(&invite); err != nil {
		return s.ErrResponse(c, err)
	}

	if invite.Email != "" && invite.Email != acct.Email {
		return s.ErrForbidden(c, errors.Errorf("invalid email"))
	}

	resp := &api.TeamInviteResponse{
		TeamKey:      invite.TeamKey,
		RegisterCode: invite.RegisterCode,
	}
	return JSON(c, http.StatusOK, resp)
}
