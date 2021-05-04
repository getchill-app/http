package server

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/getchill-app/http/api"
	wsapi "github.com/getchill-app/ws/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/tsutil"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

func (s *Server) putVault(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// Auth
	acct, err := s.authAccount(c, "", nil)
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	aid := acct.KID

	vid, err := keys.ParseID(c.Param("vid"))
	if err != nil {
		return s.ErrBadRequest(c, err)
	}

	// Check if existing
	existing, err := s.vault(ctx, vid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if existing != nil {
		if existing.Deleted {
			return s.ErrBadRequest(c, errors.Errorf("vault was deleted"))
		}
		return s.ErrBadRequest(c, errors.Errorf("vault already exists"))
	}

	token := s.GenerateToken()

	// Create vault
	create := &api.Vault{
		ID:        vid,
		Token:     token,
		CreatedBy: aid,
	}
	path := dstore.Path("vaults", vid)
	if err := s.fi.Create(ctx, path, dstore.From(create)); err != nil {
		return s.ErrResponse(c, err)
	}

	// Increment account vault count
	vaultCount, _, err := s.fi.Increment(ctx, dstore.Path("accounts", aid), "vaultCount", 1)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if vaultCount > 500 {
		return s.ErrForbidden(c, errors.Errorf("max account vaults reached"))
	}

	// Save account vault
	av := &api.AccountVault{
		Account: aid,
		Vault:   vid,
	}
	accountPath := dstore.Path("accounts", aid, "vaults", vid)
	if err := s.fi.Create(ctx, accountPath, dstore.From(av)); err != nil {
		return s.ErrResponse(c, err)
	}

	vault, err := s.vault(ctx, vid)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	return JSON(c, http.StatusOK, vault)
}

func (s *Server) getVault(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "vid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	vault, err := s.vault(ctx, auth.KID)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if vault == nil {
		return s.ErrNotFound(c, errors.Errorf("vault not found"))
	}
	if vault.Deleted {
		return s.ErrNotFound(c, errors.Errorf("vault was deleted"))
	}

	return JSON(c, http.StatusOK, vault)
}

func (s *Server) vault(ctx context.Context, kid keys.ID) (*api.Vault, error) {
	path := dstore.Path("vaults", kid)
	var vault api.Vault
	ok, err := s.fi.Load(ctx, path, &vault)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return &vault, nil
}

func (s *Server) vaults(ctx context.Context, kids []keys.ID) (map[keys.ID]*api.Vault, error) {
	m := map[keys.ID]*api.Vault{}
	paths := []string{}
	for _, kid := range kids {
		paths = append(paths, dstore.Path("vaults", kid))
	}
	docs, err := s.fi.GetAll(ctx, paths)
	if err != nil {
		return nil, err
	}
	for _, doc := range docs {
		var vault api.Vault
		if err := doc.To(&vault); err != nil {
			return nil, err
		}
		m[vault.ID] = &vault
	}
	return m, nil
}

func (s *Server) listVault(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "vid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	vid := auth.KID

	// Check if existing
	vault, err := s.vault(ctx, vid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if vault == nil {
		return s.ErrNotFound(c, errors.Errorf("vault not found"))
	}
	if vault.Deleted {
		return s.ErrNotFound(c, errors.Errorf("vault was deleted"))
	}

	limit := 1000
	path := dstore.Path("vaults", vid)
	resp, err := s.events(c, path, limit)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if len(resp.Events) == 0 && resp.Index == 0 {
		return s.ErrNotFound(c, errors.Errorf("vault not found"))
	}
	truncated := false
	if len(resp.Events) >= limit {
		// TODO: This is a lie if the number of results are exactly equal to limit
		truncated = true
	}

	out := &api.VaultResponse{
		Vault:     resp.Events,
		Index:     resp.Index,
		Truncated: truncated,
	}

	return Msgpack(c, http.StatusOK, out)
}

func (s *Server) postVault(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// TODO: max vault size

	if c.Request().Body == nil {
		return s.ErrBadRequest(c, errors.Errorf("no body data"))
	}
	b, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	auth, err := s.auth(c, newAuthRequest("Authorization", "vid", b))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	vid := auth.KID

	vault, err := s.vault(ctx, vid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if vault == nil {
		return s.ErrNotFound(c, errors.Errorf("vault not found"))
	}
	if vault.Deleted {
		return s.ErrNotFound(c, errors.Errorf("vault was deleted"))
	}

	var data [][]byte
	total := int64(0)
	if err := msgpack.Unmarshal(b, &data); err != nil {
		return s.ErrBadRequest(c, err)
	}

	path := dstore.Path("vaults", vid)

	_, idx, err := s.fi.EventsAdd(ctx, path, data)
	if err != nil {
		return err
	}

	// Increment usage
	for _, d := range data {
		total += int64(len(d))
	}
	if _, _, err := s.fi.Increment(ctx, path, "usage", total); err != nil {
		return s.ErrResponse(c, err)
	}

	// If we have a vault token, notify.
	doc, err := s.fi.Get(ctx, path)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if doc != nil {
		var vault api.Vault
		if err := doc.To(&vault); err != nil {
			return s.ErrResponse(c, err)
		}
		vt := &api.VaultToken{KID: vid, Token: vault.Token}
		if err := s.notifyVault(ctx, vt, idx); err != nil {
			return err
		}
	}
	var out struct{}
	return JSON(c, http.StatusOK, out)
}

func (s *Server) deleteVault(c echo.Context) error {
	ctx := c.Request().Context()
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())

	auth, err := s.auth(c, newAuthRequest("Authorization", "vid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	vid := auth.KID

	vault, err := s.vault(ctx, vid)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if vault == nil {
		return s.ErrNotFound(c, errors.Errorf("vault not found"))
	}
	if vault.Deleted {
		return s.ErrNotFound(c, errors.Errorf("vault was deleted"))
	}

	path := dstore.Path("vaults", vid)
	if _, err := s.fi.EventsDelete(ctx, path); err != nil {
		return s.ErrResponse(c, err)
	}

	// Create an deleted vault entry.
	create := &api.Vault{
		ID:      vid,
		Deleted: true,
	}
	if err := s.fi.Create(ctx, path, dstore.From(create)); err != nil {
		return s.ErrResponse(c, err)
	}

	var resp struct{}
	return JSON(c, http.StatusOK, resp)
}

func (s *Server) headVault(c echo.Context) error {
	ctx := c.Request().Context()
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())

	auth, err := s.auth(c, newAuthRequest("Authorization", "vid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}

	vault, err := s.vault(ctx, auth.KID)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	if vault == nil {
		return s.ErrNotFound(c, errors.Errorf("vault not found"))
	}
	if vault.Deleted {
		return s.ErrNotFound(c, errors.Errorf("vault was deleted"))
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) postVaultsStatus(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	body, err := readBody(c, false, 64*1024)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	var req api.VaultsStatusRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return s.ErrBadRequest(c, errors.Errorf("invalid request"))
	}
	paths := []string{}
	for k := range req.Vaults {
		kid, err := keys.ParseID(string(k))
		if err != nil {
			return s.ErrBadRequest(c, errors.Errorf("invalid request"))
		}
		paths = append(paths, dstore.Path("vaults", kid))
	}

	docs, err := s.fi.GetAll(ctx, paths)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	positions, err := s.fi.EventPositions(ctx, paths)
	if err != nil {
		return s.ErrResponse(c, err)
	}

	vaults := make([]*api.VaultStatus, 0, len(docs))
	for _, doc := range docs {
		var vault api.Vault
		if err := doc.To(&vault); err != nil {
			return s.ErrResponse(c, err)
		}
		token := req.Vaults[vault.ID]
		if token == "" {
			s.logger.Infof("Missing token for vault %s", vault.ID)
			continue
		}
		if token != vault.Token {
			s.logger.Infof("Invalid token for vault %s", vault.ID)
			continue
		}
		vault.Timestamp = tsutil.Millis(doc.UpdatedAt)
		position := positions[doc.Path]
		if position != nil {
			vault.Index = position.Index
			if position.Timestamp > 0 {
				vault.Timestamp = position.Timestamp
			}
		}
		vaults = append(vaults, &api.VaultStatus{
			ID:        vault.ID,
			Index:     vault.Index,
			Timestamp: vault.Timestamp,
		})
	}

	out := api.VaultsStatusResponse{
		Vaults: vaults,
	}
	return c.JSON(http.StatusOK, out)
}

func (s *Server) notifyVault(ctx context.Context, vt *api.VaultToken, idx int64) error {
	event := &wsapi.Event{
		Type:  "vault",
		Token: vt.Token,
		Vault: &wsapi.Vault{
			KID:   vt.KID,
			Index: idx,
		},
	}
	return s.notifyEvent(ctx, event)
}
