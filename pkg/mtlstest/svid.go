/*
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

package mtlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// NewSVID issues an X.509-SVID for the SPIFFE ID id, signed by the CA.  The leaf
// has one URI SAN, the ID, and a common name only when commonName is not empty.
func NewSVID(caCertificate *x509.Certificate, caKey *ecdsa.PrivateKey, id string, commonName string) (*x509svid.SVID, error) {
	spiffeID, err := spiffeid.FromString(id)
	if err != nil {
		return nil, err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		URIs:                  []*url.URL{spiffeID.URL()},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, err
	}

	return &x509svid.SVID{
		ID:           spiffeID,
		Certificates: []*x509.Certificate{certificate},
		PrivateKey:   privateKey,
	}, nil
}
