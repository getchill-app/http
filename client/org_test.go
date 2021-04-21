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

func TestOrgSetup(t *testing.T) {
	env, closeFn := newEnv(t, server.NoLevel)
	defer closeFn()
	emailer := newTestEmailer()
	env.srv.SetEmailer(emailer)
	ctx := context.TODO()
	var err error

	aliceClient := newTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	org := keys.NewEdX25519KeyFromSeed(testSeed(0x30))

	testAccount(t, aliceClient, emailer, alice, "alice@keys.pub", "alice")

	err = aliceClient.OrgCreate(ctx, org, alice)
	require.NoError(t, err)

	out, err := aliceClient.Org(ctx, org)
	require.NoError(t, err)
	require.Equal(t, alice.ID(), out.CreatedBy)
}

func TestOrgDomain(t *testing.T) {
	env, closeFn := newEnv(t, server.NoLevel)
	defer closeFn()
	emailer := newTestEmailer()
	env.srv.SetEmailer(emailer)
	ctx := context.TODO()
	var err error

	aliceClient := newTestClient(t, env)
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	org := keys.NewEdX25519KeyFromSeed(testSeed(0x30))

	testAccount(t, aliceClient, emailer, alice, "alice@keys.pub", "alice")

	st, err := aliceClient.OrgSign(org, "test.domain", time.Now())
	require.NoError(t, err)

	env.serverClient.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Err: http.Err{Code: 404}}
	})

	err = aliceClient.OrgCreateDomain(ctx, org, alice, "test.domain")
	require.EqualError(t, err, "failed to verify domain: http error 404 (400)")

	env.serverClient.SetProxy("https://test.domain/.well-known/getchill.txt", func(ctx context.Context, req *http.Request) http.ProxyResponse {
		return http.ProxyResponse{Body: []byte(st)}
	})

	err = aliceClient.OrgCreateDomain(ctx, org, alice, "test.domain")
	require.NoError(t, err)

	out, err := aliceClient.Org(ctx, org)
	require.NoError(t, err)
	require.Equal(t, "test.domain", out.Domain)

	// Create channel
	channel := keys.GenerateEdX25519Key()
	created, err := aliceClient.OrgCreateVault(ctx, org.ID(), alice, channel)
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

	channelOut, err := api.DecryptKey(respVaults.Vaults[0].EncryptedKey, org)
	require.NoError(t, err)
	require.Equal(t, channelOut, channel)

	// Bob
	bobClient := newTestClient(t, env)
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))

	// Alice register invite bob
	err = aliceClient.AccountRegisterInvite(ctx, alice, "bob@keys.pub")
	require.NoError(t, err)

	testAccount(t, bobClient, emailer, bob, "bob@keys.pub", "bob")

	// Alice invite bob to org
	err = aliceClient.OrgInvite(ctx, org, bob.ID(), alice)
	require.NoError(t, err)

	// Get invite
	invites, err := bobClient.OrgAccountInvites(ctx, bob)
	require.NoError(t, err)
	require.Equal(t, 1, len(invites))
	require.Equal(t, "test.domain", invites[0].Domain)
	orgOut, err := api.DecryptKey(invites[0].EncryptedKey, bob)
	require.NoError(t, err)
	require.Equal(t, orgOut, org)

	respVaults, err = bobClient.OrgVaults(ctx, org, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(respVaults.Vaults))
	require.Equal(t, channel.ID(), respVaults.Vaults[0].ID)
}

// To keep import
var _ = spew.Sdump("testing")
