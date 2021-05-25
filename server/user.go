package server

import (
	"context"
	"strconv"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/dstore/events"
	"github.com/keys-pub/keys/http"
	"github.com/labstack/echo/v4"
)

func (s *Server) getUsers(c echo.Context) error {
	s.logger.Infof("Server %s %s", c.Request().Method, c.Request().URL.String())
	ctx := c.Request().Context()

	// Auth
	if _, err := s.authAccount(c, "", nil); err != nil {
		return s.ErrForbidden(c, err)
	}

	idx, _ := strconv.ParseInt(c.QueryParam("idx"), 10, 64)
	users, idx, err := s.usersFromIndex(ctx, idx)
	if err != nil {
		return s.ErrResponse(c, err)
	}
	out := api.UsersResponse{Users: users, Index: idx}
	return JSON(c, http.StatusOK, out)
}

func (s *Server) usersFromIndex(ctx context.Context, idx int64) ([]*api.User, int64, error) {
	eventPath := dstore.Path("changes", "accounts")
	iter, err := s.fi.Events(ctx, eventPath, events.Index(idx))
	if err != nil {
		return nil, 0, err
	}
	paths := []string{}
	set := dstore.NewStringSet()
	for {
		event, err := iter.Next()
		if err != nil {
			return nil, 0, err
		}
		if event == nil {
			break
		}
		kid := event.Document["kid"].(string)
		if set.Contains(kid) {
			continue
		}
		path := dstore.Path("accounts", kid)
		paths = append(paths, path)
		set.Add(kid)
		idx = event.Index
	}

	users := []*api.User{}
	docs, err := s.fi.GetAll(ctx, paths)
	if err != nil {
		return nil, 0, err
	}
	for _, doc := range docs {
		var acct api.Account
		if err := doc.To(&acct); err != nil {
			return nil, 0, err
		}
		users = append(users, &api.User{
			KID:  acct.KID,
			Name: acct.Username,
		})
	}
	return users, idx, nil
}
