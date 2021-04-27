package server

import (
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
)

func (s *Server) GenerateToken() string {
	return encoding.MustEncode(keys.RandBytes(16), encoding.Base62)
}
