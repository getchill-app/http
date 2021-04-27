package server_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/stretchr/testify/require"
)

func TestShare(t *testing.T) {
	// api.SetLogger(api.NewLogger(api.DebugLevel))

	env := newEnv(t)
	// env.logLevel = server.DebugLevel
	srv := newTestServerEnv(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	testAccountCreate(t, env, srv, alice, "alice@keys.pub", "alice")

	key := keys.NewEdX25519KeyFromSeed(testSeed(0xc1))

	// PUT /share/:kid (1m)
	content := []byte("test1")
	contentHash := http.ContentHash(content)
	req, err := http.NewAuthRequest("PUT", dstore.Path("share", key.ID())+"?expire=1m", bytes.NewReader(content), contentHash, env.clock.Now(), alice)
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	require.Equal(t, `{}`, string(body))
	require.Equal(t, http.StatusOK, code)

	// GET /share/:kid
	req, err = http.NewAuthRequest("GET", dstore.Path("share", key.ID()), nil, "", env.clock.Now(), alice)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, string(content), string(body))

	// GET (again)
	req, err = http.NewAuthRequest("GET", dstore.Path("share", key.ID()), nil, "", env.clock.Now(), alice)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"resource not found"}}`, string(body))

	// PUT /share/:kid (expire 1ms)
	req, err = http.NewAuthRequest("PUT", dstore.Path("share", key.ID())+"?expire=1ms", bytes.NewReader(content), contentHash, env.clock.Now(), alice)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))
	time.Sleep(time.Millisecond)

	// GET (after expire)
	req, err = http.NewAuthRequest("GET", dstore.Path("share", key.ID()), nil, "", env.clock.Now(), alice)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"resource not found"}}`, string(body))

	// PUT /share/:kid (30m)
	req, err = http.NewAuthRequest("PUT", dstore.Path("share", key.ID())+"?expire=120m", bytes.NewReader(content), contentHash, env.clock.Now(), alice)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusBadRequest, code)
	require.Equal(t, `{"error":{"code":400,"message":"max expire is 1h0m0s"}}`, string(body))
}
