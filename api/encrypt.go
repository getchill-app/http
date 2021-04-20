package api

import (
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

func EncryptKey(key *keys.EdX25519Key, to keys.ID) ([]byte, error) {
	pk, err := keys.NewEdX25519PublicKeyFromID(to)
	if err != nil {
		return nil, err
	}
	encryptedKey := keys.CryptoBoxSeal(key.Seed()[:], pk.X25519PublicKey())
	return encryptedKey, nil
}

func DecryptKey(b []byte, key *keys.EdX25519Key) (*keys.EdX25519Key, error) {
	decrypted, err := keys.CryptoBoxSealOpen(b, key.X25519Key())
	if err != nil {
		return nil, err
	}
	if len(decrypted) != 32 {
		return nil, errors.Errorf("invalid encrypted key")
	}
	return keys.NewEdX25519KeyFromSeed(keys.Bytes32(decrypted)), nil
}
