package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
)

type testServerEnv struct {
	Server  *server.Server
	Handler http.Handler
	Emailer *testEmailer
	// Addr if started
	Addr string
}

func testFire(t *testing.T, clock tsutil.Clock) server.Fire {
	fi := dstore.NewMem()
	fi.SetClock(clock)
	fi.SetMode(dstore.FirestoreCompatibilityMode)
	return fi
}

func TestFireCreatedAt(t *testing.T) {
	clock := tsutil.NewTestClock()
	fi := testFire(t, clock)

	err := fi.Set(context.TODO(), "/test/a", dstore.Data([]byte{0x01}))
	require.NoError(t, err)

	doc, err := fi.Get(context.TODO(), "/test/a")
	require.NoError(t, err)
	require.NotNil(t, doc)

	ftime := doc.CreatedAt.Format(http.TimeFormat)
	require.Equal(t, "Fri, 13 Feb 2009 23:31:30 GMT", ftime)
	ftime = doc.CreatedAt.Format(tsutil.RFC3339Milli)
	require.Equal(t, "2009-02-13T23:31:30.001Z", ftime)
}

type env struct {
	clock    tsutil.Clock
	fi       server.Fire
	client   http.Client
	logLevel server.LogLevel
}

func newEnv(t *testing.T) *env {
	clock := tsutil.NewTestClock()
	fi := testFire(t, clock)
	return newEnvWithFire(t, fi, clock)
}

func newEnvWithFire(t *testing.T, fi server.Fire, clock tsutil.Clock) *env {
	client := http.NewClient()
	return &env{
		clock:    clock,
		fi:       fi,
		client:   client,
		logLevel: server.NoLevel,
	}
}

func newTestServerEnv(t *testing.T, env *env) *testServerEnv {
	rds := server.NewRedisTest(env.clock)
	srv := server.New(env.fi, rds, env.client, env.clock, server.NewLogger(env.logLevel))
	err := srv.SetInternalKey("6a169a699f7683c04d127504a12ace3b326e8b56a61a9b315cf6b42e20d6a44a")
	require.NoError(t, err)
	err = srv.SetTokenKey("f41deca7f9ef4f82e53cd7351a90bc370e2bf15ed74d147226439cfde740ac18")
	require.NoError(t, err)
	emailer := newTestEmailer()
	srv.SetEmailer(emailer)
	handler := server.NewHandler(srv)
	return &testServerEnv{
		Server:  srv,
		Handler: handler,
		Emailer: emailer,
	}
}

func (s *testServerEnv) Serve(req *http.Request) (int, nethttp.Header, []byte) {
	rr := httptest.NewRecorder()
	s.Handler.ServeHTTP(rr, req)
	return rr.Code, rr.Header(), rr.Body.Bytes()
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

func testJSONMarshal(t *testing.T, i interface{}) []byte {
	b, err := json.Marshal(i)
	require.NoError(t, err)
	return b
}

func testJSONUnmarshal(t *testing.T, b []byte, v interface{}) {
	err := json.Unmarshal(b, v)
	require.NoError(t, err)
}

func TestSpew(t *testing.T) {
	// To avoid import warning when we use spew
	spew.Sdump("testing")
}
