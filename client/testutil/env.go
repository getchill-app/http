package testutil

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"github.com/getchill-app/http/api"
	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

type Env struct {
	clock        tsutil.Clock
	fi           server.Fire
	serverClient http.Client
	srv          *server.Server
	httpServer   *httptest.Server
	handler      http.Handler
}

func (e *Env) SetEmailer(emailer server.Emailer) {
	e.srv.SetEmailer(emailer)
}

func (e *Env) SetProxy(urs string, fn http.ProxyFn) {
	e.serverClient.SetProxy(urs, fn)
}

func NewEnv(t *testing.T, logLevel server.LogLevel) (*Env, func()) {
	return NewEnvWithOptions(t, &EnvOptions{logLevel: logLevel})
}

// type handlerFn func(w http.ResponseWriter, req *http.Request) bool

// type proxyHandler struct {
// 	handlerFn handlerFn
// 	handler   http.Handler
// }

// func (p proxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
// 	if !p.handlerFn(w, req) {
// 		p.handler.ServeHTTP(w, req)
// 	}
// }

type EnvOptions struct {
	fi       server.Fire
	clock    tsutil.Clock
	logLevel server.LogLevel
	// handlerFn handlerFn
}

func NewEnvWithOptions(t *testing.T, opts *EnvOptions) (*Env, func()) {
	if opts == nil {
		opts = &EnvOptions{}
	}
	if opts.clock == nil {
		opts.clock = tsutil.NewTestClock()
	}
	if opts.fi == nil {
		mem := dstore.NewMem()
		mem.SetClock(opts.clock)
		opts.fi = mem
	}
	rds := server.NewRedisTest(opts.clock)
	serverClient := http.NewClient()

	serverLogger := server.NewLogger(opts.logLevel)
	config := api.Config{RelayURL: "test.getchill.app", RelayAuth: "testRelayAuthToken"}
	srv := server.New(opts.fi, rds, config, serverClient, opts.clock, serverLogger)
	srv.SetClock(opts.clock)
	emailer := NewTestEmailer()
	srv.SetEmailer(emailer)

	handler := server.NewHandler(srv)
	// if opts.handlerFn != nil {
	// 	handler = proxyHandler{
	// 		handlerFn: opts.handlerFn,
	// 		handler:   server.NewHandler(srv),
	// 	}
	// }

	BootstrapInvite(t, opts.fi, "alice@keys.pub")

	httpServer := httptest.NewServer(handler)
	srv.URL = httpServer.URL
	closeFn := func() { httpServer.Close() }

	return &Env{
		clock:        opts.clock,
		fi:           opts.fi,
		serverClient: serverClient,
		srv:          srv,
		httpServer:   httpServer,
		handler:      handler,
	}, closeFn
}

type TestEmailer struct {
	sentVerificationEmail map[string]string
}

func NewTestEmailer() *TestEmailer {
	return &TestEmailer{sentVerificationEmail: map[string]string{}}
}

func (t *TestEmailer) SentVerificationEmail(email string) string {
	s := t.sentVerificationEmail[email]
	return s
}

func (t *TestEmailer) SendVerificationEmail(email string, code string) error {
	t.sentVerificationEmail[email] = code
	return nil
}

func Seed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

func BootstrapInvite(t *testing.T, fi server.Fire, email string) {
	invite := api.AccountRegisterInvite{
		Email: email,
	}
	err := fi.Set(context.TODO(), dstore.Path("account-invites", email), dstore.From(invite))
	require.NoError(t, err)
}
