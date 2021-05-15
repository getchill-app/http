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

type TeamStatement struct {
	KID       keys.ID `json:"kid"`
	Domain    string  `json:"domain"`
	Timestamp int64   `json:"ts"`
}

type TeamInviteRequest struct {
	TeamKey Encrypted `json:"tk"`
	Email   string    `json:"email,omitempty"`
}

type TeamInviteResponse struct {
	TeamKey      Encrypted `json:"tk"`
	RegisterCode string    `json:"registerCode,omitempty"`
}

type TeamInvite struct {
	TeamKey      Encrypted `json:"tk"`
	Email        string    `json:"email,omitempty"`
	RegisterCode string    `json:"registerCode,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
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
