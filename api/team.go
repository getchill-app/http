package api

import (
	"encoding/json"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

type Team struct {
	ID         keys.ID   `json:"id"`
	CreatedBy  keys.ID   `json:"createdBy"`
	Token      string    `json:"token"`
	Domain     string    `json:"domain,omitempty"`
	VerifiedAt time.Time `json:"verifiedAt,omitempty"`
}

// TeamCreateRequest ...
type TeamCreateRequest struct {
	Domain string `json:"domain"`
}

// TeamsResponse ...
type TeamsResponse struct {
	Teams []*Team `json:"teams"`
}

// TeamVaultCreateRequest ...
type TeamVaultCreateRequest struct {
	KID         string `json:"kid"`
	EncyptedKey []byte `json:"ek"`
}

// TeamVault ...
type TeamVault struct {
	ID           keys.ID `json:"id" msgpack:"id"`
	Index        int64   `json:"idx" msgpack:"idx"`
	Timestamp    int64   `json:"ts" msgpack:"ts"`
	Token        string  `json:"token" msgpack:"token"`
	EncryptedKey []byte  `json:"ek,omitempty" msgpack:"ek,omitempty"`
}

// TeamsVaultsResponse ...
type TeamVaultsResponse struct {
	Vaults []*TeamVault `json:"vaults"`
}

type TeamStatement struct {
	KID       keys.ID `json:"kid"`
	Domain    string  `json:"domain"`
	Timestamp int64   `json:"ts"`
}

// TeamInviteRequest ...
type TeamInviteRequest struct {
	Invite       string `json:"invite"`
	EncryptedKey []byte `json:"ek"`
}

// TeamInvite ...
type TeamInvite struct {
	Team      keys.ID `json:"team"`
	Domain    string  `json:"domain"`
	Invite    keys.ID `json:"invite"`
	InvitedBy keys.ID `json:"invitedBy"`
	// EncryptedKey is encrypted team key for the invite
	EncryptedKey []byte `json:"ek"`
}

func (i TeamInvite) DecryptKey(key *keys.EdX25519Key) (*keys.EdX25519Key, error) {
	return DecryptKey(i.EncryptedKey, key)
}

// TeamInvitesResponse ...
type TeamInvitesResponse struct {
	Invites []*TeamInvite `json:"invites"`
}

func TeamSign(team *keys.EdX25519Key, domain string, ts time.Time) (string, error) {
	st := &TeamStatement{
		KID:       team.ID(),
		Domain:    domain,
		Timestamp: tsutil.Millis(ts),
	}
	b, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	return saltpack.SignArmored(b, team)
}

func (o Team) Verify(s string) error {
	b, pk, err := saltpack.VerifyArmored(s)
	if err != nil {
		return err
	}
	if pk != o.ID {
		return errors.Errorf("invalid kid")
	}
	var st TeamStatement
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if pk != st.KID {
		return errors.Errorf("invalid statement kid")
	}
	if string(st.Domain) != o.Domain {
		return errors.Errorf("invalid statement domain")
	}
	return nil
}
