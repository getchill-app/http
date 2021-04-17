package server

import (
	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
)

func (s *Server) getAccountOrgInvites(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	auth, err := s.auth(c, newAuthRequest("Authorization", "aid", nil))
	if err != nil {
		return s.ErrForbidden(c, err)
	}
	iter, err := s.fi.DocumentIterator(ctx, dstore.Path("accounts", auth.KID, "org-invites"))
	if err != nil {
		return s.ErrResponse(c, err)
	}
	defer iter.Release()

	invites := []*api.OrgInvite{}
	for {
		doc, err := iter.Next()
		if err != nil {
			return s.ErrResponse(c, err)
		}
		if doc == nil {
			break
		}
		var invite api.OrgInvite
		if err := doc.To(&invite); err != nil {
			return s.ErrResponse(c, err)
		}
		invites = append(invites, &invite)
	}

	out := api.OrgInvitesResponse{Invites: invites}
	return c.JSON(http.StatusOK, out)
}
