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

type teamVault struct {
	KID          keys.ID `json:"kid"`
	EncryptedKey []byte  `json:"ek"`
}

func (s *Server) vaultsForTeam(c echo.Context, kid keys.ID) ([]*teamVault, error) {
	ctx := c.Request().Context()
	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("teams", kid, "vaults"))
	if err != nil {
		return nil, err
	}
	defer iter.Release()

	ovs := []*teamVault{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		var ov teamVault
		if err := doc.To(&ov); err != nil {
			return nil, err
		}
		ovs = append(ovs, &ov)
	}
	return ovs, nil
}

func (s *Server) putTeamVault(c echo.Context) error {
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

	var req api.TeamVaultCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}
	vid, err := keys.ParseID(req.KID)
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

	// Create vault
	create := &api.Vault{
		ID:        vid,
		Token:     team.Token,
		Team:      tid,
		CreatedBy: aid,
	}
	path := dstore.Path("vaults", vid)
	if err := s.fi.Create(ctx, path, dstore.From(create)); err != nil {
		return s.ErrResponse(c, err)
	}

	ov := &teamVault{
		KID:          vid,
		EncryptedKey: req.EncyptedKey,
	}
	teamVaultPath := dstore.Path("teams", tid, "vaults", vid)
	if err := s.fi.Create(ctx, teamVaultPath, dstore.From(ov)); err != nil {
		return s.ErrResponse(c, err)
	}

	return JSON(c, http.StatusOK, create)
}

func (s *Server) getTeamVaults(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "tid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	includeEncryptedKey := c.QueryParam("ek") == "1"

	ovs, err := s.vaultsForTeam(c, auth.KID)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	paths := []string{}
	ekm := map[keys.ID][]byte{}
	for _, ov := range ovs {
		paths = append(paths, dstore.Path("vaults", ov.KID))
		ekm[ov.KID] = ov.EncryptedKey
	}

	docs, err := s.fi.GetAll(ctx, paths)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	positions, err := s.fi.EventPositions(ctx, paths)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	vaults := make([]*api.TeamVault, 0, len(docs))
	for _, doc := range docs {
		var vault api.Vault
		if err := doc.To(&vault); err != nil {
			return s.ErrResponse(c, err)
		}
		vault.Timestamp = tsutil.Millis(doc.UpdatedAt)
		position := positions[doc.Path]
		if position != nil {
			vault.Index = position.Index
			if position.Timestamp > 0 {
				vault.Timestamp = position.Timestamp
			}
		}
		out := &api.TeamVault{
			ID:        vault.ID,
			Index:     vault.Index,
			Timestamp: vault.Timestamp,
			Token:     vault.Token,
		}
		if includeEncryptedKey {
			out.EncryptedKey = ekm[vault.ID]
		}
		vaults = append(vaults, out)
	}

	out := &api.TeamVaultsResponse{
		Vaults: vaults,
	}
	return c.JSON(http.StatusOK, out)
}
