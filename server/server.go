package server

import (
	"encoding/json"
	"io/ioutil"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/dstore/events"
	"github.com/keys-pub/keys/encoding"
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

	// internalKey for encrypting between internal services.
	internalKey *[32]byte

	// tokenKey for JWT vault tokens
	tokenKey []byte

	emailer Emailer
}

// Fire defines interface for remote store (like Firestore).
type Fire interface {
	dstore.Documents
	events.Events
}

// New creates a Server.
func New(fi Fire, rds Redis, client http.Client, clock tsutil.Clock, logger Logger) *Server {
	return &Server{
		fi:     fi,
		rds:    rds,
		client: client,
		clock:  clock,
		logger: logger,
	}
}

// Emailer sends emails.
type Emailer interface {
	SendVerificationEmail(email string, code string) error
}

// SetTokenKey for setting token key.
func (s *Server) SetTokenKey(tokenKey string) error {
	if tokenKey == "" {
		return errors.Errorf("empty token key")
	}
	k, err := encoding.Decode(tokenKey, encoding.Hex)
	if err != nil {
		return err
	}
	s.tokenKey = k
	return nil
}

// SetEmailer sets emailer.
func (s *Server) SetEmailer(emailer Emailer) {
	s.emailer = emailer
}

// SetInternalKey for encrypting between internal services.
func (s *Server) SetInternalKey(internalKey string) error {
	if internalKey == "" {
		return errors.Errorf("empty internal key")
	}
	sk, err := encoding.Decode(internalKey, encoding.Hex)
	if err != nil {
		return err
	}
	s.internalKey = keys.Bytes32(sk)
	return nil
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
	e.PUT("/account/register/invite", s.putAccountRegisterInvite)
	e.GET("/account", s.getAccount)
	e.POST("/account/username", s.postAccountUsername)

	e.GET("/account/:aid/vaults", s.getAccountVaults)
	e.GET("/account/:aid/orgs", s.getOrgsForAccount)
	e.GET("/account/:aid/invites", s.getAccountOrgInvites)

	e.POST("/account/:aid/auths", s.postAccountAuth)
	e.GET("/account/:aid/auths", s.getAccountAuths)
	e.DELETE("/account/:aid/auth/:id", s.deleteAuth)

	// Org
	e.PUT("/org/:oid", s.putOrg)
	e.GET("/org/:oid", s.getOrg)
	e.PUT("/org/:oid/vault", s.putOrgVault)
	e.GET("/org/:oid/vaults", s.getVaultsForOrg)
	e.PUT("/org/:oid/invite", s.putOrgInvite)

	// User
	e.GET("/user/lookup", s.getUserLookup)
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
