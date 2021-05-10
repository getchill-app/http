package api

import (
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
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

// EncryptMessage does crypto_box_seal(pk+crypto_box(b)).
func EncryptMessage(b []byte, channel *keys.EdX25519Key, sender *keys.EdX25519Key) []byte {
	pk := channel.X25519Key().PublicKey()
	sk := sender.X25519Key()
	boxSealed := keys.BoxSeal(b, pk, sk)
	box := append(sk.Public(), boxSealed...)
	return keys.CryptoBoxSeal(box, pk)
}

// DecryptMessage returning sender public key.
func DecryptMessage(b []byte, key *keys.EdX25519Key) ([]byte, *keys.X25519PublicKey, error) {
	if key == nil {
		return nil, nil, errors.Errorf("failed to decrypt message: no key")
	}
	box, err := keys.CryptoBoxSealOpen(b, key.X25519Key())
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to decrypt message")
	}
	if len(box) < 32 {
		return nil, nil, errors.Wrapf(errors.Errorf("not enough bytes"), "failed to decrypt message")
	}
	pk := keys.NewX25519PublicKey(keys.Bytes32(box[:32]))
	encrypted := box[32:]

	decrypted, err := keys.BoxOpen(encrypted, pk, key.X25519Key())
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to decrypt message")
	}

	return decrypted, pk, nil
}

func Encrypt(i interface{}, key *keys.EdX25519Key) ([]byte, error) {
	b, err := msgpack.Marshal(i)
	if err != nil {
		return nil, err
	}
	encryptedKey := keys.CryptoBoxSeal(b, key.X25519Key().PublicKey())
	return encryptedKey, nil
}

func Decrypt(b []byte, v interface{}, key *keys.EdX25519Key) error {
	decrypted, err := keys.CryptoBoxSealOpen(b, key.X25519Key())
	if err != nil {
		return err
	}
	if err := msgpack.Unmarshal(decrypted, v); err != nil {
		return err
	}
	return nil
}
