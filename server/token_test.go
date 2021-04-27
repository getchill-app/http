package server_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokens(t *testing.T) {
	// SetContextLogger(NewContextLogger(DebugLevel))
	// firestore.SetContextLogger(NewContextLogger(DebugLevel))

	env := newEnv(t)
	serverEnv := newTestServerEnv(t, env)
	server := serverEnv.Server

	token := server.GenerateToken()
	require.Equal(t, 22, len(token))
}
