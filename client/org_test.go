package client_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/stretchr/testify/require"
)

func TestOrg(t *testing.T) {
	env, closeFn := newEnv(t, server.NoLevel)
	defer closeFn()
	cl := newTestClient(t, env)
	ctx := context.TODO()

	alice := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x01}, 32)))
	org := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x30}, 32)))

	st, err := cl.OrgSign(org, "test.domain", time.Now())
	require.NoError(t, err)

	env.client.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Err: http.Err{Code: 404}}
	})

	err = cl.OrgCreate(ctx, org, "test.domain", alice)
	require.EqualError(t, err, "failed to verify domain: http error 404 (400)")

	env.client.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(st)}
	})

	err = cl.OrgCreate(ctx, org, "test.domain", alice)
	require.NoError(t, err)

}
