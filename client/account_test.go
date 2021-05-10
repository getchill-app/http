package client_test

import (
	"context"
	"testing"

	"github.com/getchill-app/http/client"
	"github.com/getchill-app/http/client/testutil"
	"github.com/getchill-app/http/server"
	"github.com/getchill-app/keyring/auth"
	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestAccount(t *testing.T) {
	env, closeFn := testutil.NewEnv(t, server.NoLevel)
	defer closeFn()
	emailer := testutil.NewTestEmailer()
	env.SetEmailer(emailer)
	client := testutil.NewTestClient(t, env)
	ctx := context.TODO()
	var err error

	err = client.AccountRegister(ctx, "alice@keys.pub")
	require.NoError(t, err)
	code := emailer.SentVerificationEmail("alice@keys.pub")
	require.NotEmpty(t, code)

	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	err = client.AccountCreate(ctx, alice, "alice@keys.pub", code)
	require.NoError(t, err)

	err = client.AccountSetUsername(ctx, "alice", alice)
	require.NoError(t, err)
	err = client.AccountSetUsername(ctx, "alice2", alice)
	require.EqualError(t, err, "username already set (400)")

	resp, err := client.Account(ctx, alice)
	require.NoError(t, err)
	require.Equal(t, "alice@keys.pub", resp.Email)
	require.Equal(t, "alice", resp.Username)

	lookup, err := client.UserLookup(ctx, "email", "alice@keys.pub", alice)
	require.NoError(t, err)
	require.Equal(t, lookup.KID, alice.ID())
	require.Equal(t, lookup.Username, "alice")

	lookup, err = client.UserLookup(ctx, "email", "unknown+test@keys.pub", alice)
	require.NoError(t, err)
	require.Nil(t, lookup)

	lookup, err = client.UserLookup(ctx, "email", "", alice)
	require.NoError(t, err)
	require.Nil(t, lookup)

	lookup, err = client.UserLookup(ctx, "kid", alice.ID().String(), alice)
	require.NoError(t, err)
	require.Equal(t, lookup.KID, alice.ID())
	require.Equal(t, lookup.Username, "alice")

	mk := keys.Rand32()
	pw, err := auth.NewPassword("testpassword", mk)
	require.NoError(t, err)

	err = client.AccountAuthSave(ctx, pw, alice)
	require.NoError(t, err)

	out, err := client.AccountAuths(ctx, alice)
	require.NoError(t, err)
	require.Equal(t, 1, len(out))

	err = client.AccountRegister(ctx, "invalid")
	require.EqualError(t, err, "invalid email (400)")
}

func testAccount(t *testing.T, cl *client.Client, emailer *testutil.TestEmailer, key *keys.EdX25519Key, email string, username string) {
	var err error
	ctx := context.TODO()

	err = cl.AccountRegister(ctx, email)
	require.NoError(t, err)
	code := emailer.SentVerificationEmail(email)
	require.NotEmpty(t, code)
	err = cl.AccountCreate(ctx, key, email, code)
	require.NoError(t, err)
	err = cl.AccountSetUsername(ctx, username, key)
	require.NoError(t, err)
}
