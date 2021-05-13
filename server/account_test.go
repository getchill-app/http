package server_test

import (
	"testing"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/stretchr/testify/require"
)

func TestAccountCreate(t *testing.T) {
	env := newEnv(t)
	// env.logLevel = server.DebugLevel
	srv := newTestServerEnv(t, env)
	clock := env.clock

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	testAccountCreate(t, env, srv, alice, "alice@keys.pub", "alice")

	// GET /account
	req, err := http.NewAuthRequest("GET", "/account", nil, "", clock.Now(), alice)
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	account := api.Account{}
	testJSONUnmarshal(t, body, &account)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, alice.ID(), account.KID)
	require.Equal(t, "alice@keys.pub", account.Email)
}

func TestAccountInvalidEmail(t *testing.T) {
	env := newEnv(t)
	// env.logLevel = server.DebugLevel
	srv := newTestServerEnv(t, env)
	clock := env.clock
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	// PUT /account/register (invalid email)
	req, err := http.NewJSONRequest("PUT", "/account/register", &api.AccountCreateRequest{Email: "invalid"}, http.WithTimestamp(clock.Now()), http.SignedWith(alice))
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	require.Equal(t, http.StatusBadRequest, code)
	require.Equal(t, `{"error":{"code":400,"message":"invalid email"}}`, string(body))
}

func TestAccountEmailCodeExpired(t *testing.T) {
	// TODO
}

func TestAccountEmailCodeTooManyAttempts(t *testing.T) {
	// TODO
}

func testAccountCreate(t *testing.T, env *env, srv *testServerEnv, key *keys.EdX25519Key, email string, username string) {
	// PUT /account/register
	req, err := http.NewJSONRequest("PUT", "/account/register", &api.AccountRegisterRequest{Email: email}, http.WithTimestamp(env.clock.Now()), http.SignedWith(key))
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))
	verifyEmailCode := srv.Emailer.SentVerificationEmail("alice@keys.pub")
	require.NotEmpty(t, verifyEmailCode)

	// PUT /account/:aid
	createReq := &api.AccountCreateRequest{Email: email, VerifyEmailCode: verifyEmailCode}
	req, err = http.NewJSONRequest("PUT", dstore.Path("account", key.ID()), createReq, http.WithTimestamp(env.clock.Now()), http.SignedWith(key))
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))
}

func TestAccountInvalidCode(t *testing.T) {
	env := newEnv(t)
	// env.logLevel = server.DebugLevel
	srv := newTestServerEnv(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	// PUT /account/register
	req, err := http.NewJSONRequest("PUT", "/account/register", &api.AccountRegisterRequest{Email: "alice@keys.pub"}, http.WithTimestamp(env.clock.Now()), http.SignedWith(alice))
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))

	// PUT /account/:aid
	createReq := &api.AccountCreateRequest{Email: "alice@keys.pub", VerifyEmailCode: "invalidCode"}
	req, err = http.NewJSONRequest("PUT", dstore.Path("account", alice.ID()), createReq, http.WithTimestamp(env.clock.Now()), http.SignedWith(alice))
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusBadRequest, code)
	require.Equal(t, `{"error":{"code":400,"message":"invalid code"}}`, string(body))
}
