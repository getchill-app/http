package server

import (
	"encoding/json"
	"io/ioutil"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/dstore/events"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/labstack/echo/v4"
	"github.com/vmihailenco/msgpack/v4"

	"github.com/pkg/errors"
)

// TODO: Support If-Modified-Since

// TODO: Turn off logging

// Server ...
type Server struct {
	fi     Fire
	rds    Redis
	clock  tsutil.Clock
	logger Logger
	client http.Client

	// URL (base) of form http(s)://host:port with no trailing slash to help
	// authorization checks in testing where the host is ambiguous.
	URL string

	config api.Config

	emailer Emailer
}

// Fire defines interface for remote store (like Firestore).
type Fire interface {
	dstore.Documents
	events.Events
}

// New creates a Server.
func New(fi Fire, rds Redis, config api.Config, client http.Client, clock tsutil.Clock, logger Logger) *Server {
	return &Server{
		fi:     fi,
		rds:    rds,
		client: client,
		config: config,
		clock:  clock,
		logger: logger,
	}
}

// Emailer sends emails.
type Emailer interface {
	SendVerificationEmail(email string, code string) error
}

// SetEmailer sets emailer.
func (s *Server) SetEmailer(emailer Emailer) {
	s.emailer = emailer
}

// NewHandler returns http.Handler for Server.
func NewHandler(s *Server) http.Handler {
	return newHandler(s)
}

func newHandler(s *Server) *echo.Echo {
	e := echo.New()
	e.HTTPErrorHandler = s.ErrorHandler
	s.AddRoutes(e)
	return e
}

// AddRoutes adds routes to an Echo instance.
func (s *Server) AddRoutes(e *echo.Echo) {
	e.GET("/config", s.getConfig)

	// Vault
	e.PUT("/vault/:vid", s.putVault)
	e.GET("/vault/:vid", s.getVault)
	e.POST("/vault/:vid/events", s.postVault)
	e.GET("/vault/:vid/events", s.listVault)
	e.DELETE("/vault/:vid", s.deleteVault)
	e.HEAD("/vault/:vid", s.headVault)
	e.POST("/vaults/status", s.postVaultsStatus)

	// Accounts
	e.PUT("/account/register", s.putAccountRegister)
	e.PUT("/account/:aid", s.putAccount)
	e.PUT("/account/invite", s.putAccountInvite)
	e.GET("/account", s.getAccount)
	e.POST("/account/username", s.postAccountUsername)

	e.GET("/account/:aid/vaults", s.getAccountVaults)

	e.POST("/account/:aid/auths", s.postAccountAuth)
	e.GET("/account/:aid/auths", s.getAccountAuths)
	e.DELETE("/account/:aid/auth/:id", s.deleteAuth)

	// Team
	e.PUT("/team/:tid", s.putTeam)
	e.GET("/team/:tid", s.getTeam)
	e.PUT("/team/:tid/vault", s.putTeamVault)
	e.GET("/team/:tid/vaults", s.getTeamVaults)

	// User
	e.GET("/user/lookup", s.getUserLookup)

	// Share
	e.GET("/share/:kid", s.getShare)
	e.PUT("/share/:kid", s.putShare)
}

// SetClock sets clock.
func (s *Server) SetClock(clock tsutil.Clock) {
	s.clock = clock
}

// JSON response.
func JSON(c echo.Context, status int, i interface{}) error {
	var b []byte
	switch v := i.(type) {
	case []byte:
		b = v
	default:
		mb, err := json.Marshal(i)
		if err != nil {
			panic(err)
		}
		b = mb
	}
	return c.Blob(status, echo.MIMEApplicationJSONCharsetUTF8, b)
}

// Msgpack response.
func Msgpack(c echo.Context, status int, i interface{}) error {
	var b []byte
	switch v := i.(type) {
	case []byte:
		b = v
	default:
		mb, err := msgpack.Marshal(i)
		if err != nil {
			panic(err)
		}
		b = mb
	}
	return c.Blob(status, echo.MIMEApplicationMsgpack, b)
}

func readBody(c echo.Context, required bool, maxLength int) ([]byte, error) {
	br := c.Request().Body
	if br == nil {
		if !required {
			return []byte{}, nil
		}
		return nil, newError(http.StatusBadRequest, errors.Errorf("missing body"))
	}
	b, err := ioutil.ReadAll(br)
	if err != nil {
		return nil, newError(http.StatusInternalServerError, err)
	}
	if len(b) > maxLength {
		// TODO: Check length before reading data
		return nil, newError(http.StatusRequestEntityTooLarge, errors.Errorf("request too large"))
	}
	if len(b) == 0 && required {
		return nil, newError(http.StatusBadRequest, errors.Errorf("no body data"))
	}
	return b, nil
}
