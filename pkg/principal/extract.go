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

package principal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"net/http"

	coreclient "github.com/unikorn-cloud/core/pkg/client"
	"github.com/unikorn-cloud/identity/pkg/util"
)

var (
	// ErrHeader signals a missing or malformed principal header.
	ErrHeader = goerrors.New("header error")
)

// ExtractFromRequest decodes the X-Principal header into a Principal and stores
// it in the context. When X-Impersonate: true is also set, the returned context
// additionally carries the impersonation signal so downstream RBAC resolves
// against the propagated user rather than the calling service's system account.
//
// This helper assumes the caller has already established mTLS trust — it must
// only be invoked when the request is authenticated via a client certificate,
// otherwise the headers it parses can be spoofed by an untrusted actor.
func ExtractFromRequest(ctx context.Context, r *http.Request) (context.Context, error) {
	header := r.Header.Get(Header)
	if header == "" {
		return nil, fmt.Errorf("%w: principal header not present", ErrHeader)
	}

	data, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		// TODO: fallback, delete me... I am VERY slow.
		// Use the certificate of the service that actually called us.
		// The one in the context is used to propagate token binding information.
		certRaw, err := util.GetClientCertificateHeader(r.Header)
		if err != nil {
			return nil, err
		}

		certificate, err := util.GetClientCertificate(certRaw)
		if err != nil {
			return nil, err
		}

		p := &Principal{}

		if err := coreclient.VerifyAndDecode(p, header, certificate); err != nil {
			return nil, err
		}

		return NewContext(ctx, p), nil
	}

	p := &Principal{}

	if err := json.Unmarshal(data, p); err != nil {
		return nil, err
	}

	ctx = NewContext(ctx, p)

	if r.Header.Get(ImpersonateHeader) == "true" {
		ctx = NewImpersonateContext(ctx)
	}

	return ctx, nil
}
