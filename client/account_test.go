package client_test

import (
	"context"
	"testing"

	"github.com/getchill-app/http/client"
	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/auth"
	"github.com/stretchr/testify/require"
)

func TestAccount(t *testing.T) {
	env, closeFn := newEnv(t, server.NoLevel)
	defer closeFn()
	emailer := newTestEmailer()
	env.srv.SetEmailer(emailer)
	client := newTestClient(t, env)
	ctx := context.TODO()
	var err error

	err = client.AccountRegister(ctx, "alice@keys.pub")
	require.NoError(t, err)
	code := emailer.SentVerificationEmail("alice@keys.pub")
	require.NotEmpty(t, code)

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	err = client.AccountCreate(ctx, alice, "alice@keys.pub", code)
	require.NoError(t, err)

	resp, err := client.Account(ctx, alice)
	require.NoError(t, err)
	require.Equal(t, "alice@keys.pub", resp.Email)

	mk := keys.Rand32()
	pw, err := auth.NewPassword("testpassword", mk)
	require.NoError(t, err)

	err = client.AccountAuthSave(ctx, alice, pw)
	require.NoError(t, err)

	out, err := client.AccountAuths(ctx, alice)
	require.NoError(t, err)
	require.Equal(t, 1, len(out))

	err = client.AccountRegister(ctx, "invalid")
	require.EqualError(t, err, "invalid email (400)")
}

func testAccount(t *testing.T, cl *client.Client, emailer *testEmailer, key *keys.EdX25519Key, email string) {
	var err error
	ctx := context.TODO()

	err = cl.AccountRegister(ctx, email)
	require.NoError(t, err)
	code := emailer.SentVerificationEmail(email)
	require.NotEmpty(t, code)
	err = cl.AccountCreate(ctx, key, email, code)
	require.NoError(t, err)
}
