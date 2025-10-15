/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.
Copyright 2026 Nscale.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/jose"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrKeyFormat is raised when something is wrong with the
	// encryption keys.
	ErrKeyFormat = errors.New("key format error")

	// ErrTokenVerification is raised when token verification fails.
	ErrTokenVerification = errors.New("failed to verify token")
)

type TokenType string

const (
	// TokenTypeFederated is used for federated tokens e.g. huamns.
	TokenTypeFederated TokenType = "fed"
	// TokenTypeServiceAccount is used for service accounts.
	TokenTypeServiceAccount TokenType = "sa"
	// TokenTypeService is used by services acting on behalf of users.
	// TODO: delete me, services should use mTLS alone.
	TokenTypeService TokenType = "svc"
)

type FederatedClaims struct {
	// Provider is the backend identity provider.
	Provider string `json:"idp"`
	// ClientID is the oauth2 client that the user is using.
	ClientID string `json:"cid"`
	// UserID is set when the token is issued to a user.
	// TODO: this should be the subject.
	UserID string `json:"uid"`
	// Scope is the set of scopes requested by the client, and is used to
	// populate the userinfo response.
	Scope Scope `json:"sco"`
}

type ServiceAccountClaims struct {
	// OrganizationID is the identifier of the organization.
	OrganizationID string `json:"oid"`
}

type ServiceClaims struct {
	//nolint: tagliatelle
	X509Thumbprint string `json:"x5t@S256,omitempty"`
}

// Claims is an application specific set of claims.
// TODO: this technically isn't conformant to oauth2 in that we don't specify
// the client_id claim, and there are probably others.
type Claims struct {
	jwt.Claims `json:",inline"`
	// Type is the type of access token this is.
	Type TokenType `json:"typ"`
	// Federated is set when the type is a federated user.
	Federated *FederatedClaims `json:"fed,omitempty"`
	// ServiceAccount is set when the type is a service account.
	ServiceAccount *ServiceAccountClaims `json:"sa,omitempty"`
	// Service is set when the type is a service.
	Service *ServiceClaims `json:"svc,omitempty"`
}

// RefreshTokenClaims is a basic set of JWT claims, plus a wrapper for the
// IdP's refresh token.
type RefreshTokenClaims struct {
	jwt.Claims `json:",inline"`
	// Federated is set when the type is a federated user.
	Federated *FederatedClaims `json:"fed,omitempty"`
}

// Tokens is the set of tokens and metadata returned by a token issue.
type Tokens struct {
	Expiry                 time.Time
	AccessToken            string
	RefreshToken           *string
	LastAuthenticationTime time.Time
}

// IssueInfo controls how the access token is encoded.
type IssueInfo struct {
	// Issuer should be from the HTTP Host header, as requested by the client.
	Issuer string
	// Audience should be from the HTTP Host header, as only we can decipher the token.
	Audience string
	// Subject is the user, or service account ID, the token is valid for.  This is used
	// for RBAC.
	Subject string
	// Type is the type of access token this is.
	Type TokenType `json:"typ"`
	// Federated is set when the type is a federated user.
	Federated *FederatedClaims `json:"fed,omitempty"`
	// ServiceAccount is set when the type is a service account.
	ServiceAccount *ServiceAccountClaims `json:"sa,omitempty"`
	// Service is set when the type is a service.
	Service *ServiceClaims `json:"svc,omitempty"`
	// Duration is the token lifetime.  Please note this should only be used for
	// service account tokens that by definition need to be long lived.
	Duration *time.Duration
	// Interactive declares whether this is an interactive login
	// or not (e.g. cookie based).
	Interactive bool `json:"int"`
	// AuthorizationCodeID is required when doing code exchange and records the
	AuthorizationCodeID *string
}

// expiry calculates when the token should expire.  By default we use the duration
// defined by the authenticator.  If the token is federated, we pick the lower of
// the default, and the expiry time of the federated acces token.  If the token
// is for a service account, these need to be long lived for automation, so we can
// override the default for this only.
func (a *Authenticator) expiry(now time.Time, info *IssueInfo) time.Time {
	if info.Duration != nil {
		return now.Add(*info.Duration)
	}

	return now.Add(a.options.AccessTokenDuration)
}

// updateSession updates the user record to indicate the current access token and single-use refresh
// token bound to a specific client.  This ensures only a single session can be active per-client
// at a time, tokens are automatically revoked when reissued etc.
func (a *Authenticator) updateSession(ctx context.Context, user *unikornv1.User, info *IssueInfo, tokens *Tokens, authorizationCodeID *string) (time.Time, error) {
	session, err := user.Session(info.Federated.ClientID)
	if err != nil {
		user.Spec.Sessions = append(user.Spec.Sessions, unikornv1.UserSession{
			ClientID: info.Federated.ClientID,
		})

		session = &user.Spec.Sessions[len(user.Spec.Sessions)-1]
	} else {
		a.InvalidateToken(ctx, session.AccessToken)
	}

	session.AccessToken = tokens.AccessToken

	if tokens.RefreshToken != nil {
		session.RefreshToken = *tokens.RefreshToken
	}

	if info.Interactive {
		session.LastAuthentication = &metav1.Time{
			Time: time.Now(),
		}
	}

	if authorizationCodeID != nil {
		session.AuthorizationCodeID = *authorizationCodeID
	}

	if err := a.client.Update(ctx, user); err != nil {
		return time.Time{}, err
	}

	lastAuthenticationTime := time.Now()

	if session.LastAuthentication != nil {
		lastAuthenticationTime = session.LastAuthentication.Time
	}

	return lastAuthenticationTime, nil
}

// Issue issues a new JWT access token.
func (a *Authenticator) Issue(ctx context.Context, info *IssueInfo) (*Tokens, error) {
	now := time.Now()

	expiry := a.expiry(now, info)

	nowRFC7519 := jwt.NewNumericDate(now)
	atExpiresAtRFC7519 := jwt.NewNumericDate(expiry)
	rtExpiresAtRFC7519 := jwt.NewNumericDate(now.Add(a.options.RefreshTokenDuration))

	atClaims := &Claims{
		Claims: jwt.Claims{
			ID:      uuid.New().String(),
			Subject: info.Subject,
			Audience: jwt.Audience{
				info.Audience,
			},
			Issuer:    info.Issuer,
			IssuedAt:  nowRFC7519,
			NotBefore: nowRFC7519,
			Expiry:    atExpiresAtRFC7519,
		},
		Type:           info.Type,
		Federated:      info.Federated,
		ServiceAccount: info.ServiceAccount,
		Service:        info.Service,
	}

	at, err := a.jwtIssuer.EncodeJWEToken(ctx, atClaims, jose.TokenTypeAccessToken)
	if err != nil {
		return nil, err
	}

	tokens := &Tokens{
		AccessToken:            at,
		Expiry:                 expiry,
		LastAuthenticationTime: time.Now(),
	}

	if info.Federated != nil {
		user, err := a.getUser(ctx, info.Federated.UserID)
		if err != nil {
			return nil, err
		}

		rtClaims := &RefreshTokenClaims{
			Claims: jwt.Claims{
				ID:      uuid.New().String(),
				Subject: info.Subject,
				Audience: jwt.Audience{
					info.Audience,
				},
				Issuer:    info.Issuer,
				IssuedAt:  nowRFC7519,
				NotBefore: nowRFC7519,
				Expiry:    rtExpiresAtRFC7519,
			},
			Federated: info.Federated,
		}

		rt, err := a.jwtIssuer.EncodeJWEToken(ctx, rtClaims, jose.TokenTypeRefreshToken)
		if err != nil {
			return nil, err
		}

		tokens.RefreshToken = &rt

		authTime, err := a.updateSession(ctx, user, info, tokens, info.AuthorizationCodeID)
		if err != nil {
			return nil, err
		}

		tokens.LastAuthenticationTime = authTime
	}

	return tokens, nil
}

type VerifyInfo struct {
	Issuer   string
	Audience string
	Token    string
}

// Verify checks the access token parses and validates.
func (a *Authenticator) Verify(ctx context.Context, info *VerifyInfo) (*Claims, error) {
	// The verification process is very expensive, so we add a cache in here to
	// improve interactivity.  Once this is in place, then the network latency becomes
	// the bottle neck, presumably this is the TLS handshake.  Similar code can be
	// in the remote client-side verification middleware.
	if value, ok := a.tokenCache.Get(info.Token); ok {
		claims, ok := value.(*Claims)
		if !ok {
			return nil, fmt.Errorf("%w: failed to assert cache claims", ErrTokenVerification)
		}

		return claims, nil
	}

	// Parse and verify the claims with the public key.
	claims := &Claims{}

	if err := a.jwtIssuer.DecodeJWEToken(ctx, info.Token, claims, jose.TokenTypeAccessToken); err != nil {
		return nil, fmt.Errorf("failed to decrypt claims: %w", err)
	}

	// Verify the claims.
	expected := jwt.Expected{
		AnyAudience: jwt.Audience{
			info.Audience,
		},
		Issuer: info.Issuer,
		Time:   time.Now(),
	}

	if err := claims.ValidateWithLeeway(expected, a.options.TokenVerificationLeeway); err != nil {
		return nil, fmt.Errorf("failed to validate claims: %w", err)
	}

	if err := a.verifyServiceAccount(ctx, info, claims); err != nil {
		return nil, err
	}

	// Ensure the access token is valid for the current user session...
	if err := a.verifyUserSession(ctx, info, claims); err != nil {
		return nil, err
	}

	// The cache entry needs a timeout as a federated user may have had their rights
	// recinded and we don't know about it, and long lived tokens e.g. service accounts,
	// could still be valid for months...
	timeout := time.Hour

	if tokenExpiresIn := time.Until(claims.Expiry.Time()); tokenExpiresIn < timeout {
		timeout = tokenExpiresIn
	}

	a.tokenCache.Add(info.Token, claims, timeout)

	return claims, nil
}

func (a *Authenticator) verifyServiceAccount(ctx context.Context, info *VerifyInfo, claims *Claims) error {
	if claims.Type != TokenTypeServiceAccount {
		return nil
	}

	organization := &unikornv1.Organization{}

	if err := a.client.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: claims.ServiceAccount.OrganizationID}, organization); err != nil {
		return err
	}

	serviceAccount := &unikornv1.ServiceAccount{}

	if err := a.client.Get(ctx, client.ObjectKey{Namespace: organization.Status.Namespace, Name: claims.Subject}, serviceAccount); err != nil {
		return err
	}

	if info.Token != serviceAccount.Spec.AccessToken {
		return fmt.Errorf("%w: service account token invalid", ErrTokenVerification)
	}

	return nil
}

func (a *Authenticator) verifyUserSession(ctx context.Context, info *VerifyInfo, claims *Claims) error {
	if claims.Type != TokenTypeFederated {
		return nil
	}

	// TODO: the subject should be the user ID anyway...
	user, err := a.userdb.GetActiveUser(ctx, claims.Subject)
	if err != nil {
		return err
	}

	lookupSession := func(session unikornv1.UserSession) bool {
		return session.ClientID == claims.Federated.ClientID
	}

	index := slices.IndexFunc(user.Spec.Sessions, lookupSession)
	if index < 0 {
		return fmt.Errorf("%w: no active session for token", ErrTokenVerification)
	}

	if user.Spec.Sessions[index].AccessToken != info.Token {
		return fmt.Errorf("%w: token invalid for active session", ErrTokenVerification)
	}

	return nil
}

// InvalidateToken immediately invalidates the token so it's unusable again.
// TODO: this only considers caching in the identity service, it's still usable.
func (a *Authenticator) InvalidateToken(ctx context.Context, token string) {
	a.tokenCache.Remove(token)
}
