package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/getchill-app/http/api"
	"github.com/getchill-app/http/client/testutil"
	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/stretchr/testify/require"
)

func TestTeamSetup(t *testing.T) {
	env, closeFn := testutil.NewEnv(t, server.NoLevel)
	defer closeFn()
	emailer := testutil.NewTestEmailer()
	env.SetEmailer(emailer)
	ctx := context.TODO()
	var err error

	aliceClient := testutil.NewTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	team := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x30))

	testAccount(t, aliceClient, emailer, alice, "alice@keys.pub", "alice")

	err = aliceClient.TeamCreate(ctx, team, alice)
	require.NoError(t, err)

	out, err := aliceClient.Team(ctx, team)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), out.CreatedBy)
}

func TestTeamCreateChannel(t *testing.T) {
	env, closeFn := testutil.NewEnv(t, server.NoLevel)
	defer closeFn()
	emailer := testutil.NewTestEmailer()
	env.SetEmailer(emailer)
	ctx := context.TODO()
	var err error

	aliceClient := testutil.NewTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	team := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x30))

	testAccount(t, aliceClient, emailer, alice, "alice@keys.pub", "alice")

	err = aliceClient.TeamCreate(ctx, team, alice)
	require.NoError(t, err)

	out, err := aliceClient.Team(ctx, team)
	require.NoError(t, err)
	require.Equal(t, team.ID(), out.ID)

	// Create channel
	channel := keys.GenerateEdX25519Key()
	info := &api.ChannelInfo{Name: "testing"}
	token, err := aliceClient.ChannelCreateWithTeam(ctx, channel, info, team.ID(), alice)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	channels, err := aliceClient.Channels(ctx, team.ID(), alice)
	require.NoError(t, err)
	require.Equal(t, 1, len(channels))
	require.Equal(t, channel.ID(), channels[0].ID)
	channelOut, err := api.DecryptKey(channels[0].TeamKey, team)
	require.NoError(t, err)
	require.Equal(t, channelOut, channel)

	// Bob
	bobClient := testutil.NewTestClient(t, env)
	bob := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x02))

	// Alice invite bob
	phrase, err := aliceClient.TeamInvite(ctx, team, "bob@keys.pub", alice)
	require.NoError(t, err)

	testAccount(t, bobClient, emailer, bob, "bob@keys.pub", "bob")

	teamOut, err := bobClient.TeamInviteOpen(ctx, phrase, bob)
	require.NoError(t, err)
	require.Equal(t, teamOut.TeamKey, team)

	channels, err = bobClient.Channels(ctx, team.ID(), bob)
	require.NoError(t, err)
	require.Equal(t, 1, len(channels))
	require.Equal(t, channel.ID(), channels[0].ID)

	// Charlie
	charlieClient := testutil.NewTestClient(t, env)
	charlie := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x03))

	err = aliceClient.AccountInvite(ctx, "charlie@keys.pub", alice)
	require.NoError(t, err)

	testAccount(t, charlieClient, emailer, charlie, "charlie@keys.pub", "charlie")

	// Try to open bob's invite
	phrase, err = aliceClient.TeamInvite(ctx, team, "dan@keys.pub", alice)
	require.NoError(t, err)
	_, err = charlieClient.TeamInviteOpen(ctx, phrase, charlie)
	require.EqualError(t, err, "invalid email (403)")
}

func TestTeamDomain(t *testing.T) {
	env, closeFn := testutil.NewEnv(t, server.NoLevel)
	defer closeFn()
	emailer := testutil.NewTestEmailer()
	env.SetEmailer(emailer)
	ctx := context.TODO()
	var err error

	aliceClient := testutil.NewTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	team := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x30))

	testAccount(t, aliceClient, emailer, alice, "alice@keys.pub", "alice")

	st, err := aliceClient.TeamSign(team, "test.domain", time.Now())
	require.NoError(t, err)

	env.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Err: http.Err{Code: 404}}
	})

	err = aliceClient.TeamCreateDomain(ctx, team, alice, "test.domain")
	require.EqualError(t, err, "failed to verify domain: http error 404 (400)")

	env.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(st)}
	})

	err = aliceClient.TeamCreateDomain(ctx, team, alice, "test.domain")
	require.NoError(t, err)

	out, err := aliceClient.Team(ctx, team)
	require.NoError(t, err)
	require.Equal(t, "test.domain", out.Domain)
}

// To keep import
var _ = spew.Sdump("testing")
