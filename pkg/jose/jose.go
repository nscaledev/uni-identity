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

package jose

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spf13/pflag"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	coordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// ErrKeyFormat is raised when something is wrong with the
	// encryption keys.
	ErrKeyFormat = errors.New("key format error")

	// ErrTokenVerification is raised when token verification fails.
	ErrTokenVerification = errors.New("failed to verify token")

	// ErrMissingKey is raised when a key is missing from a secret.
	ErrMissingKey = errors.New("failed to lookup key")

	// ErrContextError is raised when a required value cannot be retrieved
	// from a context.
	ErrContextError = errors.New("value missing from context")

	// ErrJOSE is raised when something is wrong with a JWT.
	ErrJOSE = errors.New("jose error")
)

type Options struct {
	// IssuerSecretName is the name of the secret that contains our managed
	// signing key.
	IssuerSecretName string

	// RotationPeriod is used to tweak the period for certificate rotation
	// detection.
	RotationPeriod time.Duration
}

// AddFlags registers flags with the provided flag set.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.IssuerSecretName, "jose-tls-secret", "", "TLS sgning key used for JWS/JWE.")
	f.DurationVar(&o.RotationPeriod, "jose-tls-rotation-period", time.Minute, "How often to poll for signing key updates")
}

// JWTIssuer is in charge of API token issue and verification.
// It is expected that the keys come from a mounted kubernetes.io/tls
// secret, and that is managed by cert-manager.  As a result the keys
// will rotate every 60 days (by default), so you MUST ensure they are
// not cached in perpetuity.  Additionally, due to horizontal scale-out
// these secrets need to be shared between all replicas so that a token
// issued by one, can be verified by another.  As such if you ever do
// cache the certificate load, it will need to be coordinated between
// all instances.
type JWTIssuer struct {
	options *Options

	// client is the Kubernetes client for certificate management.
	client client.Client

	// namespace is where we are running so we can find leases and secrets.
	namespace string
}

// NewJWTIssuer returns a new JWT issuer and validator.
func NewJWTIssuer(client client.Client, namespace string, options *Options) *JWTIssuer {
	return &JWTIssuer{
		client:    client,
		namespace: namespace,
		options:   options,
	}
}

type CoordinationClientGetter interface {
	Client() (coordinationv1.CoordinationV1Interface, error)
}

type InClusterCoordinationClientGetter struct{}

func (*InClusterCoordinationClientGetter) Client() (coordinationv1.CoordinationV1Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	coordination, err := coordinationv1.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return coordination, nil
}

// Run starts the certificate management loop.
// The certificate itself is managed by cert-manager, as a reissue duration of N
// and a lifetime of 2N.  Tokens may be issued for a maximum duration of N.  Tokens
// issued just before the certificates N will be able to be verified until their
// expiration.  Now, to pull this off we need to:
//
//   - Keep a primary copy of the current key pair so we can see when it changes.
//     with reference to the master copy managed by cert-manager.
//   - When it does change, we need to demote the primary copy to the secondary,
//     then update the new primary.
//
// Tokens will always be issued by the current primary, but may be verified by
// either the primary or secondary.
//
// As identity is hoizontally scalable, we have another pain in the arse that
// is split brain, so use leadership election to ease the burden.
func (i *JWTIssuer) Run(ctx context.Context, coordinationClientGetter CoordinationClientGetter) error {
	coordination, err := coordinationClientGetter.Client()
	if err != nil {
		return err
	}

	id, err := os.Hostname()
	if err != nil {
		return err
	}

	id += "_" + string(uuid.NewUUID())

	// TODO: logging is not in JSON and breaks jq.
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Namespace: i.namespace,
			Name:      "unikorn-identity-jose-tls",
		},
		Client: coordination,
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	lec := leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: 15 * time.Second,
		RenewDeadline: 10 * time.Second,
		RetryPeriod:   2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: i.StartLeading,
			OnStoppedLeading: i.StopLeading,
		},
	}

	elector, err := leaderelection.NewLeaderElector(lec)
	if err != nil {
		return err
	}

	go elector.Run(ctx)

	return nil
}

const SigningKeyName = "unikorn-identity-jose"

// StartLeading does certificate rotation handling.
// NOTE: there is a startup penalty waiting for the first tick, but on the first
// invocation it's expected there won't be any traffic immediately anyway.
//
//nolint:cyclop
func (i *JWTIssuer) StartLeading(ctx context.Context) {
	log := log.FromContext(ctx)

	ticker := time.NewTicker(i.options.RotationPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Get the cert-manager secret and extract the private key.
			var secret corev1.Secret

			if err := i.client.Get(ctx, client.ObjectKey{Namespace: i.namespace, Name: i.options.IssuerSecretName}, &secret); err != nil {
				log.Error(err, "JOSE signing key secret not ready")
				break
			}

			privateKey, ok := secret.Data[corev1.TLSPrivateKeyKey]
			if !ok {
				log.Info("JOSE signing key secret doesn't contain a private key")
				break
			}

			var signingKeys unikornv1.SigningKey

			if err := i.client.Get(ctx, client.ObjectKey{Namespace: i.namespace, Name: SigningKeyName}, &signingKeys); err != nil {
				if !kerrors.IsNotFound(err) {
					log.Error(err, "unable to get JOSE signing keys")
					break
				}

				signingKeys := &unikornv1.SigningKey{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: i.namespace,
						Name:      SigningKeyName,
					},
					Spec: unikornv1.SigningKeySpec{
						PrivateKeys: []unikornv1.PrivateKey{
							{
								PEM: privateKey,
							},
						},
					},
				}

				if err := i.client.Create(ctx, signingKeys); err != nil {
					log.Error(err, "failed to create signing keys")
					break
				}

				break
			}

			// Up to date.
			if slices.Equal(signingKeys.Spec.PrivateKeys[0].PEM, privateKey) {
				break
			}

			// The new private key becomes the primary at the head of the
			// list, and is used to sign. The old primary is retained as it's
			// used to verify existing issued tokens.
			keys := []unikornv1.PrivateKey{
				{
					PEM: privateKey,
				},
				signingKeys.Spec.PrivateKeys[0],
			}

			signingKeys.Spec.PrivateKeys = keys

			if err := i.client.Update(ctx, &signingKeys); err != nil {
				log.Error(err, "failed to update JOSE primary key")
				break
			}
		}
	}
}

func (i *JWTIssuer) StopLeading() {
}

func parsePrivatekey(pemData []byte) (crypto.PrivateKey, error) {
	block, rest := pem.Decode(pemData)
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: Key encoding has extra data", ErrKeyFormat)
	}

	switch block.Type {
	// PKCS1
	case "RSA PRIVATE KEY":
		return nil, fmt.Errorf("%w: RSA key unsupported", ErrKeyFormat)
	// PKCS8
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return key, nil
	// SEC1
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return key, nil
	}

	return nil, fmt.Errorf("%w: unknown key type %s", ErrKeyFormat, block.Type)
}

type PublicKeyer interface {
	Public() crypto.PublicKey
}

func getKeyID(key crypto.PublicKey) (string, error) {
	// Use the public key, so you cannot (easily) get the private key.
	serialized, err := json.Marshal(key)
	if err != nil {
		return "", err
	}

	// Likewise hash it to make it even more impossible...
	sum := sha256.Sum256(serialized)

	// And stringify the result.
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// GetJSONWebKey converts from a X.509 secret into a JWK.
func (i *JWTIssuer) GetJSONWebKey(pem []byte) (*jose.JSONWebKey, *jose.JSONWebKey, error) {
	privateKey, err := parsePrivatekey(pem)
	if err != nil {
		return nil, nil, err
	}

	pkey, ok := privateKey.(PublicKeyer)
	if !ok {
		return nil, nil, fmt.Errorf("%w: failed to cast private key", ErrKeyFormat)
	}

	publicKey := pkey.Public()

	keyID, err := getKeyID(publicKey)
	if err != nil {
		return nil, nil, err
	}

	pub := &jose.JSONWebKey{
		Key:       publicKey,
		KeyID:     keyID,
		Algorithm: "ES512",
		Use:       "sig",
	}

	priv := &jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     keyID,
		Algorithm: "ES512",
		Use:       "sig",
	}

	return pub, priv, nil
}

// GetJSONWebKeySet returns all JSON web keys.
func (i *JWTIssuer) GetJSONWebKeySet(ctx context.Context) (*jose.JSONWebKeySet, *jose.JSONWebKeySet, error) {
	var signingKeys unikornv1.SigningKey

	if err := i.client.Get(ctx, client.ObjectKey{Namespace: i.namespace, Name: SigningKeyName}, &signingKeys); err != nil {
		return nil, nil, err
	}

	pubJWKS := &jose.JSONWebKeySet{}
	privJWKS := &jose.JSONWebKeySet{}

	for _, privateKey := range signingKeys.Spec.PrivateKeys {
		pub, priv, err := i.GetJSONWebKey(privateKey.PEM)
		if err != nil {
			return nil, nil, err
		}

		pubJWKS.Keys = append(pubJWKS.Keys, *pub)
		privJWKS.Keys = append(privJWKS.Keys, *priv)
	}

	return pubJWKS, privJWKS, nil
}

// GetPrimaryKey is the JWK used to sign and encrypt new tokens.
func (i *JWTIssuer) GetPrimaryKey(ctx context.Context) (*jose.JSONWebKey, *jose.JSONWebKey, error) {
	pub, priv, err := i.GetJSONWebKeySet(ctx)
	if err != nil {
		return nil, nil, err
	}

	if len(pub.Keys) == 0 {
		return nil, nil, fmt.Errorf("%w: no signing keys found", ErrMissingKey)
	}

	return &pub.Keys[0], &priv.Keys[0], nil
}

func (i *JWTIssuer) GetKeyByID(ctx context.Context, keyID string) (*jose.JSONWebKey, *jose.JSONWebKey, error) {
	pubJWKS, privJWKS, err := i.GetJSONWebKeySet(ctx)
	if err != nil {
		return nil, nil, err
	}

	pubMatches := pubJWKS.Key(keyID)
	if len(pubMatches) != 1 {
		return nil, nil, fmt.Errorf("%w: jwks key lookup failed", ErrJOSE)
	}

	privMatches := privJWKS.Key(keyID)
	if len(privMatches) != 1 {
		return nil, nil, fmt.Errorf("%w: jwks key lookup failed", ErrJOSE)
	}

	return &pubMatches[0], &privMatches[0], nil
}

func (i *JWTIssuer) EncodeJWT(ctx context.Context, claims any) (string, error) {
	_, priv, err := i.GetPrimaryKey(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get key pair: %w", err)
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.ES512,
		Key:       priv,
	}

	signer, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	return jwt.Signed(signer).Claims(claims).Serialize()
}

func (i *JWTIssuer) DecodeJWT(ctx context.Context, tokenString string, claims any) error {
	token, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.ES512})
	if err != nil {
		return err
	}

	if len(token.Headers) != 1 {
		return fmt.Errorf("%w: jwt doesn't have exactly one header", ErrJOSE)
	}

	keyID := token.Headers[0].KeyID
	if keyID == "" {
		return fmt.Errorf("%w: jwt doesn't have a kid set", ErrJOSE)
	}

	pub, _, err := i.GetKeyByID(ctx, keyID)
	if err != nil {
		return err
	}

	// Annoyingly this cannot extract the public key from the private one...
	if err := token.Claims(pub, claims); err != nil {
		return err
	}

	return nil
}

// TokenType is used to define the specific use of a token.
type TokenType string

const (
	// TokenTypeAccessToken is defined by RFC9068 to prevent reuse in other contexts.
	// This is only valid for access tokens.
	TokenTypeAccessToken TokenType = "at+jwt"

	// TokenTypeAuthorizationCode is defined by us to prevent reuse in other contexts.
	// This is only valid for authorization codes.
	//nolint:gosec
	TokenTypeAuthorizationCode TokenType = "unikorn-cloud.org/authcode+jwt"

	// TokenTypeLoginState is defined by us to prevent reuse in other contexts.
	// This is only valid to preserve state across federated authentication.
	//nolint:gosec
	TokenTypeLoginState TokenType = "unikorn-cloud.org/loginstate+jwt"

	// TokenTypeLoginDialogState is defined by us to prevent reuse in other contexts.
	// This is only valid to preserve state across login dialogs.
	//nolint:gosec
	TokenTypeLoginDialogState TokenType = "unikorn-cloud.org/logindialogstate+jwt"

	// TokenTypeOnboardState is used to authorize an onboarding action.
	//nolint:gosec
	TokenTypeOnboardState TokenType = "unikorn-cloud.org/onboardingstate+jwt"

	// TokenTypeRefreshToken is defined to prevent reuse in other contexts.
	// This is only valid for a refresh token.
	//nolint:gosec
	TokenTypeRefreshToken TokenType = "unikorn-cloud.org/rt+jwt"

	// TokenTypeUserSignupToken is defined to prevent reuse in other contexts.
	// This is only valid for user signup emails.
	//nolint:gosec
	TokenTypeUserSignupToken TokenType = "unikorn-cloud.org/userSignup+jwt"
)

// getSymmetricKey derives a symmetric encryption key (for AES) from whatever
// private signing key is provided.
func getSymmetricKey(key crypto.PrivateKey) ([]byte, error) {
	eckey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported private key type", ErrKeyFormat)
	}

	// Ensure we have enough keying material.
	return hkdf.Expand(sha256.New, eckey.D.Bytes(), "", aes.BlockSize)
}

// EncodeJWEToken encodes, signs and encrypts as set of claims.
// For access tokens this implemenrs https://datatracker.ietf.org/doc/html/rfc9068
func (i *JWTIssuer) EncodeJWEToken(ctx context.Context, claims any, tokenType TokenType) (string, error) {
	// TODO: according to the spec we MUST support RS256, but we do both
	// issue and verification, so not strictly necessary.
	pub, priv, err := i.GetPrimaryKey(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get key pair: %w", err)
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.ES512,
		Key:       priv,
	}

	signer, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	key, err := getSymmetricKey(priv.Key)
	if err != nil {
		return "", err
	}

	recipient := jose.Recipient{
		Algorithm: jose.A256GCMKW,
		Key:       key,
		KeyID:     pub.KeyID,
	}

	encrypterOptions := &jose.EncrypterOptions{}
	encrypterOptions = encrypterOptions.WithType(jose.ContentType(tokenType)).WithContentType("JWT")

	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, encrypterOptions)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	token, err := jwt.SignedAndEncrypted(signer, encrypter).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}

	return token, nil
}

type NestedJSONWebToken struct {
	enc                        *jose.JSONWebEncryption
	Headers                    []jose.Header
	allowedSignatureAlgorithms []jose.SignatureAlgorithm
}

func (t *NestedJSONWebToken) Decrypt(decryptionKey interface{}) (*jwt.JSONWebToken, error) {
	b, err := t.enc.Decrypt(decryptionKey)
	if err != nil {
		return nil, err
	}

	sig, err := jwt.ParseSigned(string(b), t.allowedSignatureAlgorithms)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

//nolint:cyclop
func (i *JWTIssuer) DecodeJWEToken(ctx context.Context, tokenString string, claims any, tokenType TokenType) error {
	// NOTE: we do this to bypass the algorithm checks as ECDH_ES is not permitted usually
	// due to any actor being able to encrypt their own token with the JWKS.  For now it's
	// permitted to allow the transition from the old to the new.  Perfectly safe now as
	// we enforce ES512 signatures.
	enc, err := jose.ParseEncryptedCompact(tokenString, []jose.KeyAlgorithm{jose.A256GCMKW, jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return fmt.Errorf("failed to parse jwe: %w", err)
	}

	nestedToken := &NestedJSONWebToken{
		allowedSignatureAlgorithms: []jose.SignatureAlgorithm{jose.ES512},
		enc:                        enc,
		Headers:                    []jose.Header{enc.Header},
	}

	// nestedToken, err := jwt.ParseSignedAndEncrypted(tokenString, []jose.KeyAlgorithm{jose.A256GCMKW}, []jose.ContentEncryption{jose.A256GCM}, []jose.SignatureAlgorithm{jose.ES512})
	// if err != nil {
	// 	return fmt.Errorf("failed to parse encrypted token: %w", err)
	// }

	if len(nestedToken.Headers) != 1 {
		return fmt.Errorf("%w: expected exactly one header", ErrTokenVerification)
	}

	header := nestedToken.Headers[0]

	t, ok := header.ExtraHeaders["typ"].(string)
	if !ok {
		return fmt.Errorf("%w: typ header not present", ErrTokenVerification)
	}

	if t != string(tokenType) {
		return fmt.Errorf("%w: typ header incorrect", ErrTokenVerification)
	}

	keyID := header.KeyID
	if keyID == "" {
		return fmt.Errorf("%w: jwt doesn't have a kid set", ErrJOSE)
	}

	pub, priv, err := i.GetKeyByID(ctx, keyID)
	if err != nil {
		return err
	}

	// Key depends on the encryption type...
	// TODO: delete ECDH when transitioned when we remove the above workaround.
	var key any

	//nolint:exhaustive
	switch jose.KeyAlgorithm(nestedToken.Headers[0].Algorithm) {
	case jose.A256GCMKW:
		key, err = getSymmetricKey(priv.Key)
		if err != nil {
			return err
		}
	case jose.ECDH_ES:
		key = priv
	default:
		return fmt.Errorf("%w: unusupported key encapsulation", ErrTokenVerification)
	}

	token, err := nestedToken.Decrypt(key)
	if err != nil {
		return fmt.Errorf("failed to decrypt token: %w", err)
	}

	// Annoyingly this cannot extract the public key from the private one...
	if err := token.Claims(pub, claims); err != nil {
		return fmt.Errorf("failed to extract claims: %w", err)
	}

	return nil
}
