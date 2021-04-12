package api

import (
	"encoding/json"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/saltpack"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

type Org struct {
	KID        keys.ID   `json:"id"`
	Domain     string    `json:"domain"`
	Account    keys.ID   `json:"account"`
	VerifiedAt time.Time `json:"verifiedAt,omitempty"`
}

// OrgCreateRequest ...
type OrgCreateRequest struct {
	Domain string `json:"domain"`
}

type OrgStatement struct {
	KID       keys.ID `json:"kid"`
	Domain    string  `json:"domain"`
	Timestamp int64   `json:"ts"`
}

func OrgSign(org *keys.EdX25519Key, domain string, ts time.Time) (string, error) {
	st := &OrgStatement{
		KID:       org.ID(),
		Domain:    domain,
		Timestamp: tsutil.Millis(ts),
	}
	b, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	return saltpack.SignArmored(b, org)
}

func (o Org) Verify(s string) error {
	b, pk, err := saltpack.VerifyArmored(s)
	if err != nil {
		return err
	}
	if pk != o.KID {
		return errors.Errorf("invalid kid")
	}
	var st OrgStatement
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if pk != o.KID {
		return errors.Errorf("invalid statement kid")
	}
	if string(st.Domain) != o.Domain {
		return errors.Errorf("invalid statement domain")
	}
	return nil
}
