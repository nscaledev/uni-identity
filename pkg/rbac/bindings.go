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

package rbac

import (
	goerrors "errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	idconstants "github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

const WildcardSubject = "*"

// Sentinel errors wrapped with the offending flag value by Set/validateBindingIssuer.
// Unexported: no consumer needs errors.Is on these, they exist only so err113
// sees static errors instead of inline construction.
var (
	errMalformedBinding   = goerrors.New("want issuer::subject::role[,role...]")
	errEmptySubject       = goerrors.New("empty subject")
	errBadRoleID          = goerrors.New("role ID is empty or contains whitespace")
	errSentinelWildcard   = goerrors.New("wildcard subject not allowed on the UNI sentinel issuer")
	errIssuerCommaOrSpace = goerrors.New("issuer contains comma or whitespace")
	errIssuerNotURL       = goerrors.New("issuer is neither the UNI sentinel nor an absolute URL")
	errIssuerPathSep      = goerrors.New("issuer URL path contains \"::\"")
)

// GlobalRoleBinding grants the global scopes of RoleIDs to Subject when
// authenticated by Issuer. Wildcard is set only by the flag parser (subject
// "*"): wildcard bindings match any subject and are clamped to read at
// accumulation time. Legacy-translated bindings are always exact.
type GlobalRoleBinding struct {
	Issuer   string
	Subject  string
	RoleIDs  []string
	Wildcard bool
}

// GlobalRoleBindingsValue parses repeated issuer::subject::role[,role...]
// flags, one binding per flag occurrence.
type GlobalRoleBindingsValue []GlobalRoleBinding

var _ pflag.Value = (*GlobalRoleBindingsValue)(nil)

// Set parses right-anchored: subjects and role IDs cannot contain "::", so
// the last two separators are unambiguous even for IPv6 issuer URLs.
func (v *GlobalRoleBindingsValue) Set(value string) error {
	bad := func(err error) error { return fmt.Errorf("invalid global role binding %q: %w", value, err) }

	last := strings.LastIndex(value, "::")
	if last < 0 {
		return bad(errMalformedBinding)
	}

	prev := strings.LastIndex(value[:last], "::")
	if prev < 0 {
		return bad(errMalformedBinding)
	}

	issuer, roleList := value[:prev], value[last+2:]
	subject := strings.TrimSpace(value[prev+2 : last])

	if subject == "" {
		return bad(errEmptySubject)
	}

	if err := validateBindingIssuer(issuer, subject); err != nil {
		return bad(err)
	}

	roleIDs := strings.Split(roleList, ",")
	for _, id := range roleIDs {
		if id == "" || strings.ContainsFunc(id, unicode.IsSpace) {
			return bad(errBadRoleID)
		}
	}

	*v = append(*v, GlobalRoleBinding{Issuer: issuer, Subject: subject, RoleIDs: roleIDs, Wildcard: subject == WildcardSubject})

	return nil
}

// validateBindingIssuer accepts the UNI sentinel (exact subjects only — a
// sentinel wildcard would match every local user) or an absolute URL. Comma
// and whitespace are rejected explicitly: the legacy flag's comma-join idiom
// would otherwise parse into one bogus never-matching binding.
func validateBindingIssuer(issuer, subject string) error {
	if issuer == idconstants.UNISentinel {
		if subject == WildcardSubject {
			return errSentinelWildcard
		}

		return nil
	}

	if strings.ContainsRune(issuer, ',') || strings.ContainsFunc(issuer, unicode.IsSpace) {
		return errIssuerCommaOrSpace
	}

	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errIssuerNotURL
	}

	// A "::" in the path (not the IPv6-host brackets url.Parse already
	// consumed) would let a subject containing "::" parse right-anchored
	// into the issuer instead, silently producing a never-matching binding.
	if strings.Contains(u.Path, "::") {
		return errIssuerPathSep
	}

	return nil
}

func (v *GlobalRoleBindingsValue) String() string {
	parts := make([]string, 0, len(*v))

	for _, b := range *v {
		parts = append(parts, b.Issuer+"::"+b.Subject+"::"+strings.Join(b.RoleIDs, ","))
	}

	return strings.Join(parts, " ")
}

func (*GlobalRoleBindingsValue) Type() string { return "issuer::subject::roles" }

// accumulateGlobalReadPermissions is accumulateGlobalPermissions with the
// wildcard clamp, applied at authorization time because Role CRDs are live
// and can gain write scopes after the chart's render-time guard
// (charts/identity/templates/identity/deployment.yaml) has already run. This
// clamp is the defence-in-depth backstop for that gap and must not be
// removed; see pkg/rbac/README.md#global-role-bindings for the full
// two-layer rationale.
func accumulateGlobalReadPermissions(acl *openapi.Acl, roleIDs []string, roles map[string]*unikornv1.Role) error {
	for _, roleID := range roleIDs {
		role, ok := roles[roleID]
		if !ok {
			return fmt.Errorf("%w: role %s referenced by global role binding", errors.ErrConsistency, roleID)
		}

		// Clamp: project each scope down to its read operation only, dropping
		// scopes that don't grant read at all.
		readScopes := make([]unikornv1.RoleScope, 0, len(role.Spec.Scopes.Global))

		for _, scope := range role.Spec.Scopes.Global {
			if slices.Contains(scope.Operations, unikornv1.Read) {
				readScopes = append(readScopes, unikornv1.RoleScope{Name: scope.Name, Operations: []unikornv1.Operation{unikornv1.Read}})
			}
		}

		acl.Global = addScopesToEndpointList(acl.Global, readScopes)
	}

	return nil
}

// effectiveGlobalRoleBindings translates the legacy admin flags into exact
// bindings (verbatim — Wildcard is never set, so a legacy subject literally
// "*" keeps its historical exact-match semantics) and appends the new list.
func effectiveGlobalRoleBindings(o *Options) []GlobalRoleBinding {
	out := make([]GlobalRoleBinding, 0, len(o.PlatformAdministratorSubjects)+len(o.GlobalRoleBindings))

	for _, s := range o.PlatformAdministratorSubjects {
		out = append(out, GlobalRoleBinding{Issuer: s.Issuer, Subject: s.Subject, RoleIDs: o.PlatformAdministratorRoleIDs})
	}

	return append(out, o.GlobalRoleBindings...)
}

// resolveGlobalRoleBindings returns the bindings matching the authenticated
// (issuer, subject) pair. Wildcards never match the sentinel or an unset
// issuer (impersonated principals, pre-src_iss passports).
func (r *RBAC) resolveGlobalRoleBindings(srcIss, subject string) []GlobalRoleBinding {
	var out []GlobalRoleBinding

	for _, b := range r.bindings {
		if b.Issuer != srcIss {
			continue
		}

		if b.Wildcard {
			if srcIss == "" || srcIss == idconstants.UNISentinel {
				continue
			}

			out = append(out, b)

			continue
		}

		if strings.EqualFold(strings.TrimSpace(b.Subject), strings.TrimSpace(subject)) {
			out = append(out, b)
		}
	}

	return out
}
