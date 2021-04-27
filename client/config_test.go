package client_test

import (
	"context"
	"testing"

	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	env, closeFn := newEnv(t, server.NoLevel)
	defer closeFn()
	emailer := newTestEmailer()
	env.srv.SetEmailer(emailer)
	ctx := context.TODO()
	var err error

	aliceClient := newTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	testAccount(t, aliceClient, emailer, alice, "alice@keys.pub", "alice")

	config, err := aliceClient.Config(ctx, alice)
	require.NoError(t, err)
	require.Equal(t, "test.getchill.app", config.RelayURL)
	require.Equal(t, "testRelayAuthToken", config.RelayAuth)
}
