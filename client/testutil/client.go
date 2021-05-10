package testutil

import (
	"context"
	"testing"

	"github.com/getchill-app/http/client"
	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func NewTestClient(t *testing.T, env *Env) *client.Client {
	cl, err := client.New(env.httpServer.URL)
	require.NoError(t, err)
	cl.SetHTTPClient(env.httpServer.Client())
	cl.SetClock(env.clock)
	return cl
}

func TestAccount(t *testing.T, cl *client.Client, emailer *TestEmailer, key *keys.EdX25519Key, email string, username string) {
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
