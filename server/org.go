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

func (s *Server) putOrg(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	auth, err := s.auth(c, newAuthRequest("Authorization", "", body))
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	oid, err := keys.ParseID(c.Param("oid"))
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

	var req api.OrgCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}
	if req.Domain == "" {
		return s.ErrBadRequest(c, errors.Errorf("empty domain"))
	}

	existing, err := s.findOrgByDomain(ctx, req.Domain)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if existing != nil {
		return s.ErrConflict(c, errors.Errorf("org domain already exists"))
	}

	org := &api.Org{
		Domain:    req.Domain,
		KID:       oid,
		CreatedBy: auth.KID,
	}
	// Verify org
	// TODO: Rate limit
	if err := s.verifyOrg(ctx, org); err != nil {
		return s.ErrBadRequest(c, errors.Wrapf(err, "failed to verify domain"))
	}
	org.VerifiedAt = s.clock.Now()

	path := dstore.Path("orgs", oid)
	if err := s.fi.Create(ctx, path, dstore.From(org)); err != nil {
		switch err.(type) {
		case dstore.ErrPathExists:
			return s.ErrConflict(c, errors.Errorf("org already exists"))
		}
		return s.ErrResponse(c, err)
	}

	accountOrgPath := dstore.Path("accounts", auth.KID, "orgs", oid)
	if err := s.fi.Create(ctx, accountOrgPath, dstore.From(org)); err != nil {
		return s.ErrResponse(c, err)
	}
	orgAccountPath := dstore.Path("orgs", oid, "accounts", auth.KID)
	ao := accountOrg{
		KID: auth.KID,
	}
	if err := s.fi.Create(ctx, orgAccountPath, dstore.From(ao)); err != nil {
		return s.ErrResponse(c, err)
	}

	return JSON(c, http.StatusOK, org)
}

type accountOrg struct {
	KID keys.ID `json:"kid"`
}

func (s *Server) findOrgByDomain(ctx context.Context, domain string) (*api.Org, error) {
	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("orgs"), dstore.Where("domain", "==", domain))
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
	var org api.Org
	if err := doc.To(&org); err != nil {
		return nil, err
	}
	return &org, nil
}

// func (s *Server) findOrg(ctx context.Context, kid keys.ID) (*api.Org, error) {
// 	if kid == "" {
// 		return nil, errors.Errorf("empty kid")
// 	}
// 	path := dstore.Path("orgs", kid)

// 	doc, err := s.fi.Get(ctx, path)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if doc == nil {
// 		return nil, nil
// 	}

// 	var org api.Org
// 	if err := doc.To(&org); err != nil {
// 		return nil, err
// 	}

// 	return &org, nil
// }

func (s *Server) verifyOrg(ctx context.Context, org *api.Org) error {
	url := fmt.Sprintf("https://%s/.well-known/getchill.txt", org.Domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	res, err := s.client.Request(ctx, req)
	if err != nil {
		return err
	}
	if err := org.Verify(string(res)); err != nil {
		return err
	}
	return nil
}

func (s *Server) getOrgsForAccount(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "aid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("accounts", auth.KID, "orgs"))
	if err != nil {
		return s.ErrResponse(c, err)
	}
	defer iter.Release()

	orgs := []*api.Org{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return s.ErrResponse(c, err)
		}
		if doc == nil {
			break
		}
		var org api.Org
		if err := doc.To(&org); err != nil {
			return s.ErrResponse(c, err)
		}
		orgs = append(orgs, &org)
	}

	out := api.OrgsResponse{Orgs: orgs}
	return c.JSON(http.StatusOK, out)
}

type orgVault struct {
	KID          keys.ID `json:"kid"`
	EncryptedKey []byte  `json:"ek"`
}

func (s *Server) vaultsForOrg(c echo.Context, kid keys.ID) ([]*orgVault, error) {
	ctx := c.Request().Context()
	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("orgs", kid, "vaults"))
	if err != nil {
		return nil, err
	}
	defer iter.Release()

	ovs := []*orgVault{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if doc == nil {
			break
		}
		var ov orgVault
		if err := doc.To(&ov); err != nil {
			return nil, err
		}
		ovs = append(ovs, &ov)
	}
	return ovs, nil
}

func (s *Server) putOrgVault(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	auth, err := s.auth(c, newAuthRequest("Authorization", "oid", body))
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	var req api.OrgVaultCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, err)
	}
	if req.KID == "" {
		return s.ErrBadRequest(c, errors.Errorf("empty kid"))
	}
	vid := req.KID

	token, err := s.GenerateToken()
	if err != nil {
		return s.ErrResponse(c, err)
	}

	// Create vault
	create := &api.Vault{
		ID:    vid,
		Token: token,
	}
	path := dstore.Path("vaults", vid)
	if err := s.fi.Create(ctx, path, dstore.From(create)); err != nil {
		return s.ErrResponse(c, err)
	}

	ov := &orgVault{
		KID:          vid,
		EncryptedKey: req.EncyptedKey,
	}
	orgVaultPath := dstore.Path("orgs", auth.KID, "vaults", vid)
	if err := s.fi.Create(ctx, orgVaultPath, dstore.From(ov)); err != nil {
		return s.ErrResponse(c, err)
	}

	return JSON(c, http.StatusOK, create)
}

func (s *Server) getVaultsForOrg(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "oid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	includeEncryptedKey := c.QueryParam("ek") == "1"

	ovs, err := s.vaultsForOrg(c, auth.KID)
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

	vaults := make([]*api.OrgVault, 0, len(docs))
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
		out := &api.OrgVault{
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

	out := &api.OrgVaultsResponse{
		Vaults: vaults,
	}
	return c.JSON(http.StatusOK, out)
}
