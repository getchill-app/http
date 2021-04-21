package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/getchill-app/http/api"
	"github.com/getchill-app/http/client"
	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/stretchr/testify/require"
)

func TestTeamSetup(t *testing.T) {
	env, closeFn := newEnv(t, server.NoLevel)
	defer closeFn()
	emailer := newTestEmailer()
	env.srv.SetEmailer(emailer)
	ctx := context.TODO()
	var err error

	aliceClient := newTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	team := keys.NewEdX25519KeyFromSeed(testSeed(0x30))

	testAccount(t, aliceClient, emailer, alice, "alice@keys.pub", "alice")

	err = aliceClient.TeamCreate(ctx, team, alice)
	require.NoError(t, err)

	out, err := aliceClient.Team(ctx, team)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), out.CreatedBy)
}

func TestTeamDomain(t *testing.T) {
	env, closeFn := newEnv(t, server.NoLevel)
	defer closeFn()
	emailer := newTestEmailer()
	env.srv.SetEmailer(emailer)
	ctx := context.TODO()
	var err error

	aliceClient := newTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	team := keys.NewEdX25519KeyFromSeed(testSeed(0x30))

	testAccount(t, aliceClient, emailer, alice, "alice@keys.pub", "alice")

	st, err := aliceClient.TeamSign(team, "test.domain", time.Now())
	require.NoError(t, err)

	env.serverClient.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Err: http.Err{Code: 404}}
	})

	err = aliceClient.TeamCreateDomain(ctx, team, alice, "test.domain")
	require.EqualError(t, err, "failed to verify domain: http error 404 (400)")

	env.serverClient.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(st)}
	})

	err = aliceClient.TeamCreateDomain(ctx, team, alice, "test.domain")
	require.NoError(t, err)

	out, err := aliceClient.Team(ctx, team)
	require.NoError(t, err)
	require.Equal(t, "test.domain", out.Domain)

	// Create channel
	channel := keys.GenerateEdX25519Key()
	created, err := aliceClient.TeamCreateVault(ctx, team.ID(), alice, channel)
	require.NoError(t, err)
	require.NotEmpty(t, created.Token)

	respVaults, err := aliceClient.TeamVaults(ctx, team, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(respVaults.Vaults))
	require.Equal(t, channel.ID(), respVaults.Vaults[0].ID)

	respVaults, err = aliceClient.TeamVaults(ctx, team, &client.TeamVaultsOpts{EncryptedKeys: true})
	require.NoError(t, err)
	require.Equal(t, 1, len(respVaults.Vaults))
	require.Equal(t, channel.ID(), respVaults.Vaults[0].ID)

	channelOut, err := api.DecryptKey(respVaults.Vaults[0].EncryptedKey, team)
	require.NoError(t, err)
	require.Equal(t, channelOut, channel)

	// Bob
	bobClient := newTestClient(t, env)
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))

	// Alice register invite bob
	err = aliceClient.AccountRegisterInvite(ctx, alice, "bob@keys.pub")
	require.NoError(t, err)

	testAccount(t, bobClient, emailer, bob, "bob@keys.pub", "bob")

	// Alice invite bob to team
	err = aliceClient.TeamInvite(ctx, team, bob.ID(), alice)
	require.NoError(t, err)

	// Get invite
	invites, err := bobClient.TeamAccountInvites(ctx, bob)
	require.NoError(t, err)
	require.Equal(t, 1, len(invites))
	require.Equal(t, "test.domain", invites[0].Domain)
	teamOut, err := api.DecryptKey(invites[0].EncryptedKey, bob)
	require.NoError(t, err)
	require.Equal(t, teamOut, team)

	respVaults, err = bobClient.TeamVaults(ctx, team, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(respVaults.Vaults))
	require.Equal(t, channel.ID(), respVaults.Vaults[0].ID)
}

// To keep import
var _ = spew.Sdump("testing")