package client_test

import (
	"context"
	"testing"

	"github.com/getchill-app/http/api"
	"github.com/getchill-app/http/client/testutil"
	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestChannel(t *testing.T) {
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

	channelKey := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xc0))
	info := &api.ChannelInfo{Name: "testing"}
	token, err := aliceClient.ChannelCreate(ctx, channelKey, info, alice)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	channelOut, err := aliceClient.Channel(ctx, channelKey)
	require.NoError(t, err)
	require.NotEmpty(t, token, channelOut.Token)

	msg := api.NewMessage(channelKey.ID(), alice.ID()).WithText("hi bob")
	err = aliceClient.SendMessage(ctx, msg, channelKey, alice)
	require.NoError(t, err)

	// Bob
	bobClient := testutil.NewTestClient(t, env)
	bob := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x02))
	err = aliceClient.AccountInvite(ctx, "bob@keys.pub", alice)
	require.NoError(t, err)
	testAccount(t, bobClient, emailer, bob, "bob@keys.pub", "bob")

	msgs, err := bobClient.Messages(ctx, channelKey, 0)
	require.NoError(t, err)
	require.Equal(t, 1, len(msgs.Messages))
	require.Equal(t, "hi bob", msgs.Messages[0].Text)

	channel, err := bobClient.Channel(ctx, channelKey)
	require.NoError(t, err)
	require.Equal(t, "testing", channel.Info(channelKey).Name)

	tokens := []*api.ChannelToken{{Channel: channelKey.ID(), Token: channel.Token}}
	channels, err := bobClient.Channels(ctx, tokens, bob)
	require.NoError(t, err)
	require.Equal(t, 1, len(channels))
	require.Equal(t, int64(1), channels[0].Index)
}
