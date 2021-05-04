package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
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

func (s *Server) findTeam(ctx context.Context, kid keys.ID) (*api.Team, error) {
	if kid == "" {
		return nil, errors.Errorf("empty kid")
	}
	path := dstore.Path("teams", kid)

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

type teamChannel struct {
	KID          keys.ID `json:"kid"`
	EncryptedKey []byte  `json:"ek"`
}

func (s *Server) channelsForTeam(c echo.Context, kid keys.ID) ([]*teamChannel, error) {
	ctx := c.Request().Context()
	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("teams", kid, "channels"))
	if err != nil {
		return nil, err
	}
	defer iter.Release()

	ovs := []*teamChannel{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		var ov teamChannel
		if err := doc.To(&ov); err != nil {
			return nil, err
		}
		ovs = append(ovs, &ov)
	}
	return ovs, nil
}

func (s *Server) putTeamChannel(c echo.Context) error {
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

	var req api.TeamChannelCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}
	cid, err := keys.ParseID(req.KID)
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

	team, err := s.findTeam(ctx, tid)
	if err != nil {
		return s.ErrBadRequest(c, err)
	}
	if team == nil {
		return s.ErrBadRequest(c, errors.Errorf("invalid team"))
	}

	// Create
	create := &Channel{
		ID:        cid,
		Token:     team.Token,
		Team:      tid,
		CreatedBy: aid,
	}
	path := dstore.Path("channels", cid)
	if err := s.fi.Create(ctx, path, dstore.From(create)); err != nil {
		return s.ErrResponse(c, err)
	}

	ov := &teamChannel{
		KID:          cid,
		EncryptedKey: req.EncyptedKey,
	}
	teamPath := dstore.Path("teams", tid, "channels", cid)
	if err := s.fi.Create(ctx, teamPath, dstore.From(ov)); err != nil {
		return s.ErrResponse(c, err)
	}

	return JSON(c, http.StatusOK, create)
}

func (s *Server) getTeamChannels(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "tid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	includeEncryptedKey := c.QueryParam("ek") == "1"

	channels, err := s.channelsForTeam(c, auth.KID)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	paths := []string{}
	ekm := map[keys.ID][]byte{}
	for _, channel := range channels {
		paths = append(paths, dstore.Path("channels", channel.KID))
		ekm[channel.KID] = channel.EncryptedKey
	}

	docs, err := s.fi.GetAll(ctx, paths)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	positions, err := s.fi.EventPositions(ctx, paths)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	tcs := make([]*api.Channel, 0, len(docs))
	for _, doc := range docs {
		var channel Channel
		if err := doc.To(&channel); err != nil {
			return s.ErrResponse(c, err)
		}
		channel.Timestamp = tsutil.Millis(doc.UpdatedAt)
		position := positions[doc.Path]
		if position != nil {
			channel.Index = position.Index
			if position.Timestamp > 0 {
				channel.Timestamp = position.Timestamp
			}
		}
		out := &api.Channel{
			ID:        channel.ID,
			Index:     channel.Index,
			Timestamp: channel.Timestamp,
			Token:     channel.Token,
		}
		if includeEncryptedKey {
			out.EncryptedKey = ekm[channel.ID]
		}
		tcs = append(tcs, out)
	}

	out := &api.TeamChannelsResponse{
		Channels: tcs,
	}
	return c.JSON(http.StatusOK, out)
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

	if err := s.accountInvite(ctx, req.Email, acct.KID); err != nil {
		return s.ErrResponse(c, err)
	}

	invite := api.TeamInvite{
		EncryptedKey: req.EncryptedKey,
		Email:        req.Email,
		CreatedAt:    s.clock.Now(),
	}

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
		EncryptedKey: invite.EncryptedKey,
	}
	return JSON(c, http.StatusOK, resp)
}
