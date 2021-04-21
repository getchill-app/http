package server

import (
	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
)

func (s *Server) getAccountVaults(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// Auth
	acct, err := s.authAccount(c, "aid", nil)
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	aid := acct.KID

	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("accounts", aid, "vaults"))
	if err != nil {
		return s.ErrResponse(c, err)
	}
	defer iter.Release()

	avs := []*api.AccountVault{}
	kids := []keys.ID{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return s.ErrResponse(c, err)
		}
		if doc == nil {
			break
		}
		var av api.AccountVault
		if err := doc.To(&av); err != nil {
			return s.ErrResponse(c, err)
		}
		avs = append(avs, &av)
		kids = append(kids, av.Vault)
	}

	vm, err := s.vaults(ctx, kids)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	for _, av := range avs {
		vault, ok := vm[av.Vault]
		if ok {
			av.Token = vault.Token
			av.Usage = vault.Usage
		}
	}

	out := api.AccountVaultsResponse{Vaults: avs}
	return c.JSON(http.StatusOK, out)
}
