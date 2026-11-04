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

package mtlstest_test

import (
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/mtlstest"
)

// TestNewSVIDVerifiesAgainstItsCA checks that the SVID passes the SPIFFE
// verification of a peer, which the listener tests depend on.
func TestNewSVIDVerifiesAgainstItsCA(t *testing.T) {
	t.Parallel()

	caCertificate, caKey, _, _, err := mtlstest.GenerateCACerts()
	require.NoError(t, err)

	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("example.org"), []*x509.Certificate{caCertificate})

	svid, err := mtlstest.NewSVID(caCertificate, caKey, "spiffe://example.org/region", "")
	require.NoError(t, err)

	id, _, err := x509svid.Verify(svid.Certificates, bundle)
	require.NoError(t, err)
	require.Equal(t, "spiffe://example.org/region", id.String())
	require.Empty(t, svid.Certificates[0].Subject.CommonName)

	named, err := mtlstest.NewSVID(caCertificate, caKey, "spiffe://example.org/region", "unikorn-region")
	require.NoError(t, err)
	require.Equal(t, "unikorn-region", named.Certificates[0].Subject.CommonName)
}
