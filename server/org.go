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

	existing, err := s.findOrgByDomain(ctx, req.Domain)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if existing != nil {
		return s.ErrConflict(c, errors.Errorf("org domain already exists"))
	}

	org := &api.Org{
		Domain:  req.Domain,
		KID:     oid,
		Account: auth.KID,
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

	return JSON(c, http.StatusOK, org)
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
