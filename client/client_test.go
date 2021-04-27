package client_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"

	"github.com/getchill-app/http/api"
	"github.com/getchill-app/http/client"
	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

type env struct {
	clock        tsutil.Clock
	fi           server.Fire
	serverClient http.Client
	srv          *server.Server
	httpServer   *httptest.Server
	handler      http.Handler
}

func newEnv(t *testing.T, logLevel server.LogLevel) (*env, func()) {
	return newEnvWithOptions(t, &envOptions{logLevel: logLevel})
}

type handlerFn func(w http.ResponseWriter, req *http.Request) bool

type proxyHandler struct {
	handlerFn handlerFn
	handler   http.Handler
}

func (p proxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !p.handlerFn(w, req) {
		p.handler.ServeHTTP(w, req)
	}
}

type envOptions struct {
	fi        server.Fire
	clock     tsutil.Clock
	logLevel  server.LogLevel
	handlerFn handlerFn
}

func newEnvWithOptions(t *testing.T, opts *envOptions) (*env, func()) {
	if opts == nil {
		opts = &envOptions{}
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
	emailer := newTestEmailer()
	srv.SetEmailer(emailer)

	handler := server.NewHandler(srv)
	if opts.handlerFn != nil {
		handler = proxyHandler{
			handlerFn: opts.handlerFn,
			handler:   server.NewHandler(srv),
		}
	}

	bootstrapInvite(t, opts.fi, "alice@keys.pub")

	httpServer := httptest.NewServer(handler)
	srv.URL = httpServer.URL
	closeFn := func() { httpServer.Close() }

	return &env{
		clock:        opts.clock,
		fi:           opts.fi,
		serverClient: serverClient,
		srv:          srv,
		httpServer:   httpServer,
		handler:      handler,
	}, closeFn
}

func newTestClient(t *testing.T, env *env) *client.Client {
	cl, err := client.New(env.httpServer.URL)
	require.NoError(t, err)
	cl.SetHTTPClient(env.httpServer.Client())
	cl.SetClock(env.clock)
	return cl
}

type testEmailer struct {
	sentVerificationEmail map[string]string
}

func newTestEmailer() *testEmailer {
	return &testEmailer{sentVerificationEmail: map[string]string{}}
}

func (t *testEmailer) SentVerificationEmail(email string) string {
	s := t.sentVerificationEmail[email]
	return s
}

func (t *testEmailer) SendVerificationEmail(email string, code string) error {
	t.sentVerificationEmail[email] = code
	return nil
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

func bootstrapInvite(t *testing.T, fi server.Fire, email string) {
	invite := api.AccountRegisterInvite{
		Email: email,
	}
	err := fi.Set(context.TODO(), dstore.Path("account-invites", email), dstore.From(invite))
	require.NoError(t, err)
}
