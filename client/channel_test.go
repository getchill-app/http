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

func TestChannels(t *testing.T) {
	env, closeFn := testutil.NewEnv(t, server.NoLevel) // server.DebugLevel)
	defer closeFn()
	emailer := testutil.NewTestEmailer()
	env.SetEmailer(emailer)
	ctx := context.TODO()
	var err error

	aliceClient := testutil.NewTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	bob := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x02))

	testAccount(t, aliceClient, emailer, alice, "alice@keys.pub", "alice")

	channelsOut, err := aliceClient.Channels(ctx, "", alice)
	require.NoError(t, err)
	require.Empty(t, channelsOut)

	channelKey := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xc0))
	info := &api.ChannelInfo{Name: "testing"}
	token, err := aliceClient.ChannelCreateWithUsers(ctx, channelKey, info, []keys.ID{alice.ID(), bob.ID()}, alice)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	channel, err := aliceClient.Channel(ctx, channelKey, alice)
	require.NoError(t, err)
	require.NotEmpty(t, token, channel.Token)
	require.NotEmpty(t, token, channel.UserKey)

	channels, err := aliceClient.Channels(ctx, "", alice)
	require.NoError(t, err)
	require.Equal(t, 1, len(channels))
	require.Equal(t, int64(0), channels[0].Index)

	msg := api.NewMessage(channelKey.ID(), alice.ID()).WithText("hi bob")
	err = aliceClient.SendMessage(ctx, msg, channelKey, alice)
	require.NoError(t, err)

	// Bob
	bobClient := testutil.NewTestClient(t, env)
	err = aliceClient.AccountInvite(ctx, "bob@keys.pub", alice)
	require.NoError(t, err)
	testAccount(t, bobClient, emailer, bob, "bob@keys.pub", "bob")

	msgs, err := bobClient.Messages(ctx, channelKey, 0)
	require.NoError(t, err)
	require.Equal(t, 1, len(msgs.Messages))
	require.Equal(t, "hi bob", msgs.Messages[0].Text)

	channel, err = bobClient.Channel(ctx, channelKey, bob)
	require.NoError(t, err)
	var infoOut api.ChannelInfo
	err = api.Decrypt(channel.Info, &infoOut, channelKey)
	require.NoError(t, err)
	require.Equal(t, "testing", infoOut.Name)

	channels, err = bobClient.Channels(ctx, "", bob)
	require.NoError(t, err)
	require.Equal(t, 1, len(channels))
	require.Equal(t, keys.ID("kex1tw2r0t02l7lg7sd38ktw6jwj75wddsnxek8vc2ztq4fwcjgjhrws4efqvl"), channels[0].ID)
	require.Equal(t, int64(1), channels[0].Index)
	channelKeyOut, err := api.DecryptKey(channels[0].UserKey, bob)
	require.NoError(t, err)
	require.Equal(t, channelKeyOut, channelKey)

	// Add charlie
	charlie := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x03))
	charlieClient := testutil.NewTestClient(t, env)
	err = aliceClient.AccountInvite(ctx, "charlie@keys.pub", alice)
	require.NoError(t, err)
	testAccount(t, charlieClient, emailer, charlie, "charlie@keys.pub", "charlie")

	err = aliceClient.ChannelUsersAdd(ctx, channelKey, []keys.ID{charlie.ID()})
	require.NoError(t, err)

	channels, err = charlieClient.Channels(ctx, "", charlie)
	require.NoError(t, err)
	require.Equal(t, 1, len(channels))
	require.Equal(t, keys.ID("kex1tw2r0t02l7lg7sd38ktw6jwj75wddsnxek8vc2ztq4fwcjgjhrws4efqvl"), channels[0].ID)

	users, err := charlieClient.ChannelUsers(ctx, channelKey)
	require.NoError(t, err)
	require.Equal(t, []keys.ID{
		keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"),
		keys.ID("kex1a4yj333g68pvd6hfqvufqkv4vy54jfe6t33ljd3kc9rpfty8xlgs2u3qxr"),
		keys.ID("kex1syuhwr4g05t4744r23nvxnr7en9cmz53knhr0gja7c84hr7fkw2quf6zcg"),
	}, users)
}
