package api_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/getchill-app/http/api"
	"github.com/keys-pub/keys"
	"github.com/stretchr/testify/require"
)

func TestTeamSignVerify(t *testing.T) {
	teamKey := keys.NewEdX25519KeyFromSeed(keys.Bytes32(bytes.Repeat([]byte{0x30}, 32)))
	st, err := api.TeamSign(teamKey, "test.domain", time.Now())
	require.NoError(t, err)

	team := &api.Team{ID: teamKey.ID(), Domain: "other.domain"}
	err = team.Verify(st)
	require.EqualError(t, err, "invalid statement domain")

	team2 := &api.Team{ID: keys.ID("otherkey"), Domain: "test.domain"}
	err = team2.Verify(st)
	require.EqualError(t, err, "invalid kid")

	team3 := &api.Team{ID: teamKey.ID(), Domain: "test.domain"}
	err = team3.Verify(st)
	require.NoError(t, err)
}
