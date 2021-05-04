package api_test

import (
	"testing"

	"github.com/getchill-app/http/api"
	"github.com/stretchr/testify/require"
)

func TestMessageCommandDB(t *testing.T) {
	cmd := api.MessageCommand{}

	val, err := cmd.Value()
	require.NoError(t, err)
	b := val.([]byte)

	var out api.MessageCommand
	out.Scan(b)
	require.Equal(t, cmd, out)
}
