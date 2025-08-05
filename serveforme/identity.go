package serveforme

import (
	"context"
	"errors"
	"fmt"
	"strings"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

type Identity struct {
	Issuer   string `json:"issuer,omitempty"`
	ClientID string `json:"clientID,omitempty"`
	Subject  string `json:"subject"`
}

var (
	ErrInvalidIdentity = errors.New("invalid identity")
)

// NewIdentityFromTokenSource creates a new Identity from a TokenSource.
func NewIdentityFromTokenSource(ctx context.Context, ts TokenSource) (*Identity, error) {
	idToken, err := ts.Get(ctx)
	if err != nil {
		return nil, err
	}
	tok, _, err := jwt.NewParser().ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	issuer, err := tok.Claims.GetIssuer()
	if err != nil {
		return nil, err
	}
	audiences, err := tok.Claims.GetAudience()
	if err != nil {
		return nil, err
	}
	if len(audiences) != 1 {
		return nil, fmt.Errorf("exactly one audience is expected, got [%s]", strings.Join(audiences, ", "))
	}
	clientID := audiences[0]
	subject, err := tok.Claims.GetSubject()
	if err != nil {
		return nil, err
	}
	return &Identity{
		Issuer:   issuer,
		ClientID: clientID,
		Subject:  subject,
	}, nil
}

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
