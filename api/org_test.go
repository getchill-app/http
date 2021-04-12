package api_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestOrgSignVerify(t *testing.T) {
	orgKey := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x30}, 32)))
	st, err := api.OrgSign(orgKey, "test.domain", time.Now())
	require.NoError(t, err)

	org := &api.Org{KID: orgKey.ID(), Domain: "other.domain"}
	err = org.Verify(st)
	require.EqualError(t, err, "invalid statement domain")

	org2 := &api.Org{KID: keys.ID("otherkey"), Domain: "test.domain"}
	err = org2.Verify(st)
	require.EqualError(t, err, "invalid kid")

	org3 := &api.Org{KID: orgKey.ID(), Domain: "test.domain"}
	err = org3.Verify(st)
	require.NoError(t, err)
}
