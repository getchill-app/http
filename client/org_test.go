package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/getchill-app/http/client"
	"github.com/getchill-app/http/server"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/http"
	"github.com/stretchr/testify/require"
)

func TestOrg(t *testing.T) {
	env, closeFn := newEnv(t, server.DebugLevel)
	defer closeFn()
	ctx := context.TODO()

	aliceClient := newTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	org := keys.NewEdX25519KeyFromSeed(testSeed(0x30))

	err := aliceClient.AccountCreate(ctx, alice, "alice@keys.pub")
	require.NoError(t, err)

	st, err := aliceClient.OrgSign(org, "test.domain", time.Now())
	require.NoError(t, err)

	env.serverClient.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Err: http.Err{Code: 404}}
	})

	err = aliceClient.OrgCreate(ctx, org, "test.domain", alice)
	require.EqualError(t, err, "failed to verify domain: http error 404 (400)")

	env.serverClient.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(st)}
	})

	err = aliceClient.OrgCreate(ctx, org, "test.domain", alice)
	require.NoError(t, err)

	out, err := aliceClient.Org(ctx, org)
	require.NoError(t, err)
	require.Equal(t, "test.domain", out.Domain)

	// Create channel
	channel := keys.GenerateEdX25519Key()
	created, err := aliceClient.OrgCreateVault(ctx, org, channel)
	require.NoError(t, err)
	require.NotEmpty(t, created.Token)

	respVaults, err := aliceClient.OrgVaults(ctx, org, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(respVaults.Vaults))
	require.Equal(t, channel.ID(), respVaults.Vaults[0].ID)

	respVaults, err = aliceClient.OrgVaults(ctx, org, &client.OrgVaultsOpts{EncryptedKeys: true})
	require.NoError(t, err)
	require.Equal(t, 1, len(respVaults.Vaults))
	require.Equal(t, channel.ID(), respVaults.Vaults[0].ID)

	channelOut, err := client.DecryptKey(respVaults.Vaults[0].EncryptedKey, org)
	require.NoError(t, err)
	require.Equal(t, channelOut, channel)

	// Bob
	bobClient := newTestClient(t, env)
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))
	err = bobClient.AccountCreate(ctx, bob, "bob@keys.pub")
	require.NoError(t, err)

	// Alice invite bob
	err = aliceClient.OrgInvite(ctx, org, bob.ID(), alice)
	require.NoError(t, err)

	// Get invite
	invites, err := bobClient.OrgAccountInvites(ctx, bob)
	require.NoError(t, err)
	require.Equal(t, 1, len(invites))
	require.Equal(t, "test.domain", invites[0].Domain)
	orgOut, err := client.DecryptKey(invites[0].EncryptedKey, bob)
	require.NoError(t, err)
	require.Equal(t, orgOut, org)

	// Accept invite
	err = bobClient.OrgInviteAccept(ctx, bob, orgOut)
	require.NoError(t, err)

	respVaults, err = bobClient.OrgVaults(ctx, org, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(respVaults.Vaults))
	require.Equal(t, channel.ID(), respVaults.Vaults[0].ID)
}

// To keep import
var _ = spew.Sdump("testing")
