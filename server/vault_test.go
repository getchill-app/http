package server_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/firestore"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestVault(t *testing.T) {
	env := newEnv(t)
	// env.logLevel = server.DebugLevel
	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	vault := keys.NewEdX25519KeyFromSeed(testSeed(0xc0))

	testVault(t, env, vault, alice)
}

func TestVaultFirestore(t *testing.T) {
	if os.Getenv("TEST_FIRESTORE") != "1" {
		t.Skip()
	}
	// firestore.SetContextLogger(firestore.NewContextLogger(firestore.DebugLevel))
	env := newEnvWithFire(t, testFirestore(t), tsutil.NewTestClock())
	// env.logLevel = server.DebugLevel

	alice := keys.GenerateEdX25519Key()
	vault := keys.GenerateEdX25519Key()
	testVault(t, env, vault, alice)
}

func testVault(t *testing.T, env *env, vault *keys.EdX25519Key, alice *keys.EdX25519Key) {
	srv := newTestServerEnv(t, env)
	clock := env.clock

	testAccountCreate(t, env, srv, alice, "alice@keys.pub", "alice")

	rand := keys.GenerateEdX25519Key()

	// GET /vault/:vid (not found)
	req, err := http.NewAuthRequest("GET", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"vault not found"}}`, string(body))

	// GET /vault/:vid/events (not found)
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID(), "events"), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"vault not found"}}`, string(body))

	// HEAD /vault/:vid (not found)
	req, err = http.NewAuthRequest("HEAD", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, _ = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)

	// DELETE /vault/:vid (not found)
	req, err = http.NewAuthRequest("DELETE", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, _ = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)

	// PUT /vault/:vid
	req, err = http.NewAuthRequest("PUT", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), alice)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	var create api.Vault
	testJSONUnmarshal(t, []byte(body), &create)
	require.Equal(t, http.StatusOK, code)
	require.NotEmpty(t, create.Token)
	require.Equal(t, vault.ID(), create.ID)

	// POST /vault/:vid/events
	vaultData := [][]byte{
		[]byte("test1"),
	}
	data, err := msgpack.Marshal(vaultData)
	require.NoError(t, err)
	req, err = http.NewAuthRequest("POST", dstore.Path("vault", vault.ID(), "events"), bytes.NewReader(data), http.ContentHash(data), clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))

	// GET /vault/:vid/events
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID(), "events"), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	var resp api.VaultResponse
	err = msgpack.Unmarshal([]byte(body), &resp)
	require.NoError(t, err)
	require.Equal(t, int64(1), resp.Index)
	require.Equal(t, 1, len(resp.Vault))
	require.Equal(t, []byte("test1"), resp.Vault[0].Data)

	// HEAD /vault/:vid
	req, err = http.NewAuthRequest("HEAD", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, _ = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)

	// GET /vault/:vid/events?idx=next
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID(), "events")+"?idx="+strconv.Itoa(int(resp.Index)), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	var resp2 api.VaultResponse
	err = msgpack.Unmarshal([]byte(body), &resp2)
	require.NoError(t, err)
	require.Equal(t, 0, len(resp2.Vault))
	require.Equal(t, resp.Index, resp2.Index)

	// POST /vault/:vid/events
	vaultData2 := [][]byte{
		[]byte("test2"),
		[]byte("test3"),
	}
	data2, err := msgpack.Marshal(vaultData2)
	require.NoError(t, err)
	req, err = http.NewAuthRequest("POST", dstore.Path("vault", vault.ID(), "events"), bytes.NewReader(data2), http.ContentHash(data2), clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))

	// GET /vault/:vid/events?idx=next
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID(), "events")+"?idx="+strconv.Itoa(int(resp.Index)), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	var resp3 api.VaultResponse
	err = msgpack.Unmarshal([]byte(body), &resp3)
	require.NoError(t, err)
	require.Equal(t, 2, len(resp3.Vault))
	require.Equal(t, []byte("test2"), resp3.Vault[0].Data)
	require.Equal(t, []byte("test3"), resp3.Vault[1].Data)

	// POST /vault/:vid/events
	vaultData3 := [][]byte{
		[]byte("test4"),
		[]byte("test5"),
		[]byte("test6"),
		[]byte("test7"),
		[]byte("test8"),
		[]byte("test9"),
	}
	data3, err := msgpack.Marshal(vaultData3)
	require.NoError(t, err)
	req, err = http.NewAuthRequest("POST", dstore.Path("vault", vault.ID(), "events"), bytes.NewReader(data3), http.ContentHash(data3), clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))

	// GET /vault/:vid/events?idx=next
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID(), "events")+"?idx="+strconv.Itoa(int(resp3.Index)), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	var resp4 api.VaultResponse
	err = msgpack.Unmarshal([]byte(body), &resp4)
	require.NoError(t, err)
	require.Equal(t, 6, len(resp4.Vault))
	require.Equal(t, []byte("test4"), resp4.Vault[0].Data)
	require.Equal(t, []byte("test5"), resp4.Vault[1].Data)
	require.Equal(t, []byte("test6"), resp4.Vault[2].Data)
	require.Equal(t, []byte("test7"), resp4.Vault[3].Data)
	require.Equal(t, []byte("test8"), resp4.Vault[4].Data)
	require.Equal(t, []byte("test9"), resp4.Vault[5].Data)

	// DEL (invalid auth)
	req, err = http.NewAuthRequest("DELETE", dstore.Path("vault", vault.ID()), nil, "", env.clock.Now(), rand)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, `{"error":{"code":403,"message":"invalid kid"}}`, string(body))
	require.Equal(t, http.StatusForbidden, code)

	// DEL /vault/:vid
	req, err = http.NewAuthRequest("DELETE", dstore.Path("vault", vault.ID()), nil, "", env.clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))

	// DEL /vault/:vid (again)
	req, err = http.NewAuthRequest("DELETE", dstore.Path("vault", vault.ID()), nil, "", env.clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"vault was deleted"}}`, string(body))

	// GET /vault/:vid
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"vault was deleted"}}`, string(body))

	// GET /vault/:vid/events
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID(), "events"), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"vault was deleted"}}`, string(body))

	// HEAD /vault/:vid
	req, err = http.NewAuthRequest("HEAD", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"vault was deleted"}}`, string(body))

	// POST /vault/:vid/events (deleted)
	req, err = http.NewAuthRequest("POST", dstore.Path("vault", vault.ID(), "events"), bytes.NewReader(data), http.ContentHash(data), clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"vault was deleted"}}`, string(body))
}

func TestVaultAuthFirestore(t *testing.T) {
	if os.Getenv("TEST_FIRESTORE") != "1" {
		t.Skip()
	}
	firestore.SetContextLogger(firestore.NewContextLogger(firestore.DebugLevel))
	fs := testFirestore(t)

	clock := tsutil.NewTestClock()
	env := newEnvWithFire(t, fs, clock)
	// env.logLevel = server.DebugLevel

	alice := keys.GenerateEdX25519Key()
	vault := keys.GenerateEdX25519Key()

	testVaultAuth(t, env, vault, alice)
}

func TestVaultAuth(t *testing.T) {
	env := newEnv(t)
	// env.logLevel = server.DebugLevel
	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	vault := keys.NewEdX25519KeyFromSeed(testSeed(0xc0))
	testVaultAuth(t, env, vault, alice)
}

func testVaultAuth(t *testing.T, env *env, vault *keys.EdX25519Key, alice *keys.EdX25519Key) {
	srv := newTestServerEnv(t, env)
	clock := env.clock

	randKey := keys.GenerateEdX25519Key()

	testAccountCreate(t, env, srv, alice, "alice@keys.pub", "alice")

	// GET /vault/:vid (no auth)
	req, err := http.NewRequest("GET", dstore.Path("vault", vault.ID()), nil)
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, `{"error":{"code":403,"message":"missing Authorization header"}}`, string(body))

	// GET /vault/:vid (invalid key)
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), randKey)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, `{"error":{"code":403,"message":"invalid kid"}}`, string(body))

	// POST /vault/:vid/events (invalid key)
	vaultData := [][]byte{[]byte("test1")}
	data, err := msgpack.Marshal(vaultData)
	require.NoError(t, err)
	req, err = http.NewAuthRequest("POST", dstore.Path("vault", vault.ID(), "events"), bytes.NewReader(data), http.ContentHash(data), clock.Now(), randKey)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, `{"error":{"code":403,"message":"invalid kid"}}`, string(body))

	// GET /vault/:vid
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"vault not found"}}`, string(body))

	// Replay last request
	reqReplay, err := http.NewRequest("GET", req.URL.String(), nil)
	reqReplay.Header.Set("Authorization", req.Header.Get("Authorization"))
	require.NoError(t, err)
	code, _, body = srv.Serve(reqReplay)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, `{"error":{"code":403,"message":"nonce collision"}}`, string(body))

	// GET /vault/:vid (invalid authorization)
	authHeader := req.Header.Get("Authorization")
	sig := strings.Split(authHeader, ":")[1]
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), randKey)
	require.NoError(t, err)
	req.Header.Set("Authorization", randKey.ID().String()+":"+sig)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, `{"error":{"code":403,"message":"invalid kid"}}`, string(body))
}

func TestVaultAccount(t *testing.T) {
	env := newEnv(t)
	// env.logLevel = server.DebugLevel
	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))

	srv := newTestServerEnv(t, env)
	clock := env.clock
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	vault := keys.NewEdX25519KeyFromSeed(testSeed(0xc0))

	// PUT /vault/:aid (as alice, no account)
	req, err := http.NewAuthRequest("PUT", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), alice)
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, `{"error":{"code":403,"message":"account auth failed"}}`, string(body))

	testAccountCreate(t, env, srv, alice, "alice@keys.pub", "alice")

	// // PUT /vault/:aid (as alice, unverified)
	// req, err = http.NewAuthRequest("PUT", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), alice)
	// require.NoError(t, err)
	// code, _, body = srv.Serve(req)
	// require.Equal(t, http.StatusForbidden, code)
	// require.Equal(t, `{"error":{"code":403,"message":"account email is not verified"}}`, string(body))

	// testVerifyEmail(t, env, srv, alice, "alice@keys.pub")

	// PUT /vault/:aid (as alice, ok)
	req, err = http.NewAuthRequest("PUT", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), alice)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	var create api.VaultToken
	testJSONUnmarshal(t, []byte(body), &create)
	require.Equal(t, http.StatusOK, code)
	require.NotEmpty(t, create.Token)

	// POST /vault/:vid/events
	vault1 := [][]byte{
		bytes.Repeat([]byte{0x01}, 1024),
		bytes.Repeat([]byte{0x02}, 1024),
		bytes.Repeat([]byte{0x03}, 1024),
	}
	data1, err := msgpack.Marshal(vault1)
	require.NoError(t, err)
	req, err = http.NewAuthRequest("POST", dstore.Path("vault", vault.ID(), "events"), bytes.NewReader(data1), http.ContentHash(data1), clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))

	// GET /accounts/:aid/vaults
	req, err = http.NewAuthRequest("GET", dstore.Path("account", alice.ID(), "vaults"), nil, "", clock.Now(), alice)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	var resp api.AccountVaultsResponse
	err = json.Unmarshal(body, &resp)
	require.NoError(t, err)
	require.Equal(t, 1, len(resp.Vaults))
	require.Equal(t, int64(3072), resp.Vaults[0].Usage)
}

func TestVaultMax(t *testing.T) {
	env := newEnv(t)
	// env.logLevel = server.DebugLevel
	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))

	srv := newTestServerEnv(t, env)
	clock := env.clock
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	testAccountCreate(t, env, srv, alice, "alice@keys.pub", "alice")

	// Add too many vaults
	for i := 0; i < 500; i++ {
		vault := keys.GenerateEdX25519Key()
		req, err := http.NewAuthRequest("PUT", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), alice)
		require.NoError(t, err)
		code, _, _ := srv.Serve(req)
		require.Equal(t, http.StatusOK, code)
	}

	req, err := http.NewAuthRequest("PUT", dstore.Path("vault", keys.GenerateEdX25519Key().ID()), nil, "", clock.Now(), alice)
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, `{"error":{"code":403,"message":"max account vaults reached"}}`, string(body))
}

func TestVaultStatus(t *testing.T) {
	env := newEnv(t)
	// env.logLevel = server.DebugLevel
	// keys.SetLogger(keys.NewLogger(keys.DebugLevel))
	srv := newTestServerEnv(t, env)
	clock := env.clock

	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	testAccountCreate(t, env, srv, alice, "alice@keys.pub", "alice")
	vault := keys.NewEdX25519KeyFromSeed(testSeed(0xc0))

	// PUT /vault/:vid
	req, err := http.NewAuthRequest("PUT", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), alice)
	require.NoError(t, err)
	code, _, body := srv.Serve(req)
	var create api.Vault
	testJSONUnmarshal(t, []byte(body), &create)
	require.Equal(t, http.StatusOK, code)
	require.NotEmpty(t, create.Token)
	require.Equal(t, vault.ID(), create.ID)

	// GET /vault/:vid
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", vault.ID()), nil, "", clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	out := api.Vault{}
	testJSONUnmarshal(t, []byte(body), &out)
	require.Equal(t, vault.ID(), out.ID)
	require.Equal(t, create.Token, out.Token)

	// GET /vault/:vid (unknown)
	unknown := keys.GenerateEdX25519Key()
	req, err = http.NewAuthRequest("GET", dstore.Path("vault", unknown.ID()), nil, "", clock.Now(), unknown)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, `{"error":{"code":404,"message":"vault not found"}}`, string(body))

	// POST /vault/:vid/events
	vault1 := [][]byte{bytes.Repeat([]byte{0x01}, 1024)}
	data1, err := msgpack.Marshal(vault1)
	require.NoError(t, err)
	req, err = http.NewAuthRequest("POST", dstore.Path("vault", vault.ID(), "events"), bytes.NewReader(data1), http.ContentHash(data1), clock.Now(), vault)
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, `{}`, string(body))

	// POST /vaults/status
	statusReq := api.VaultsStatusRequest{
		Vaults: map[keys.ID]string{vault.ID(): create.Token},
	}
	req, err = http.NewRequest("POST", "/vaults/status", bytes.NewReader(testJSONMarshal(t, statusReq)))
	require.NoError(t, err)
	code, _, body = srv.Serve(req)
	var statusResp api.VaultsStatusResponse
	testJSONUnmarshal(t, []byte(body), &statusResp)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, 1, len(statusResp.Vaults))
	require.Equal(t, vault.ID(), statusResp.Vaults[0].ID)
	require.Equal(t, int64(1234567890016), statusResp.Vaults[0].Timestamp)
	require.Equal(t, int64(1), statusResp.Vaults[0].Index)
}
