package serveforme

import (
	"context"
	"errors"

	oidc "github.com/coreos/go-oidc/v3/oidc"
)

type Identity struct {
	Issuer   string `json:"issuer,omitempty"`
	ClientID string `json:"clientID,omitempty"`
	Subject  string `json:"subject"`
}

var (
	ErrInvalidIdentity = errors.New("invalid identity")
)

func (i *Identity) Verify(ctx context.Context, token string) error {
	provider, err := oidc.NewProvider(ctx, i.Issuer)
	if err != nil {
		return err
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: i.ClientID}).Verify(ctx, token)
	if err != nil {
		return err
	}
	if i.Subject != idToken.Subject {
		return ErrInvalidIdentity
	}
	return nil
}
