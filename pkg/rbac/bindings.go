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

// Sentinel errors for group bindings. The two issuer-slot errors name the
// group-name possibility because right-anchored parsing shifts a "::" inside
// a group name into the issuer slot — the parser cannot attribute it.
var (
	errMalformedGroupBinding = goerrors.New("want issuer::group::role[,role...]")
	errGroupSentinelIssuer   = goerrors.New("group bindings are not valid on the UNI sentinel issuer: UNI-local tokens carry no groups claim")
	errWildcardGroup         = goerrors.New("wildcard group not allowed; use a wildcard subject binding instead")
	errEmptyGroup            = goerrors.New("empty group")
	errGroupIssuerNotURL     = goerrors.New("issuer is not an absolute URL (or the group name contains \"::\", which is not supported)")
	errGroupIssuerPathSep    = goerrors.New("issuer URL path contains \"::\" (or the group name contains \"::\", which is not supported)")
)

// GroupRoleBinding grants the global scopes of RoleIDs to any user-account
// subject whose token from Issuer carries Group in the issuer's configured
// groups claim (BearerTrustSpec.GroupsClaim). Matching is byte-exact: no
// case folding, no trimming inside the name. Unlike wildcard subject
// bindings, group bindings are NOT clamped to read.
type GroupRoleBinding struct {
	Issuer  string
	Group   string
	RoleIDs []string
}

// GlobalGroupRoleBindingsValue parses repeated issuer::group::role[,role...]
// flags, one binding per flag occurrence, right-anchored like its sibling
// GlobalRoleBindingsValue.
type GlobalGroupRoleBindingsValue []GroupRoleBinding

var _ pflag.Value = (*GlobalGroupRoleBindingsValue)(nil)

func (v *GlobalGroupRoleBindingsValue) Set(value string) error {
	bad := func(err error) error { return fmt.Errorf("invalid global group role binding %q: %w", value, err) }

	last := strings.LastIndex(value, "::")
	if last < 0 {
		return bad(errMalformedGroupBinding)
	}

	prev := strings.LastIndex(value[:last], "::")
	if prev < 0 {
		return bad(errMalformedGroupBinding)
	}

	issuer, roleList := value[:prev], value[last+2:]
	group := strings.TrimSpace(value[prev+2 : last])

	if group == "" {
		return bad(errEmptyGroup)
	}

	if group == WildcardSubject {
		return bad(errWildcardGroup)
	}

	if err := validateGroupBindingIssuer(issuer); err != nil {
		return bad(err)
	}

	roleIDs := strings.Split(roleList, ",")
	for _, id := range roleIDs {
		if id == "" || strings.ContainsFunc(id, unicode.IsSpace) {
			return bad(errBadRoleID)
		}
	}

	*v = append(*v, GroupRoleBinding{Issuer: issuer, Group: group, RoleIDs: roleIDs})

	return nil
}

// validateGroupBindingIssuer rejects the UNI sentinel outright (UNI-local
// tokens carry no groups claim, so a sentinel group binding is dead config)
// and otherwise applies the same absolute-URL rules as subject bindings,
// with error messages that also name the group-name-contains-"::" cause.
func validateGroupBindingIssuer(issuer string) error {
	if issuer == idconstants.UNISentinel {
		return errGroupSentinelIssuer
	}

	if strings.ContainsRune(issuer, ',') || strings.ContainsFunc(issuer, unicode.IsSpace) {
		return errIssuerCommaOrSpace
	}

	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errGroupIssuerNotURL
	}

	if strings.Contains(u.Path, "::") {
		return errGroupIssuerPathSep
	}

	return nil
}

func (v *GlobalGroupRoleBindingsValue) String() string {
	parts := make([]string, 0, len(*v))

	for _, b := range *v {
		parts = append(parts, b.Issuer+"::"+b.Group+"::"+strings.Join(b.RoleIDs, ","))
	}

	return strings.Join(parts, " ")
}

func (*GlobalGroupRoleBindingsValue) Type() string { return "issuer::group::roles" }

// accumulateGlobalReadPermissions clamps wildcard bindings at authorization
// time, because live Role CRDs can gain write scopes after the chart's
// render-time guard has run. See pkg/rbac/README.md#global-role-bindings for
// the two-layer rationale.
func accumulateGlobalReadPermissions(acl *openapi.Acl, roleIDs []string, roles map[string]*unikornv1.Role) error {
	for _, roleID := range roleIDs {
		role, ok := roles[roleID]
		if !ok {
			return fmt.Errorf("%w: role %s referenced by global role binding", errors.ErrConsistency, roleID)
		}

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
// issuer (impersonated principals, pre-src_iss passports). A non-wildcard
// subject match is exact (case-sensitive) after trimming surrounding
// whitespace on both sides: the authenticated subject already arrives
// lower-cased and trimmed (pkg/oauth2's Auth0 email normalization), so this
// trim only absorbs whitespace in a configured binding's subject.
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

		if strings.TrimSpace(b.Subject) == strings.TrimSpace(subject) {
			out = append(out, b)
		}
	}

	return out
}

// resolveGroupRoleBindings returns the group bindings matching the
// authenticated issuer whose Group appears byte-exact in the token's groups.
// srcIss can never be the UNI sentinel here in a matching state via
// flag-parsed configuration: sentinel issuers are rejected at flag parse.
// Impersonated principals carry the sentinel plus nil groups, so delegated
// hops fail closed on the nil groups alone even disregarding that gate
// (pinned by TestImpersonatedPrincipalNeverMatchesGroupBindings, which
// constructs a sentinel-issuer binding directly to isolate exactly that).
func (r *RBAC) resolveGroupRoleBindings(srcIss string, groups []string) []GroupRoleBinding {
	var out []GroupRoleBinding

	for _, b := range r.groupBindings {
		if b.Issuer != srcIss {
			continue
		}

		if slices.Contains(groups, b.Group) {
			out = append(out, b)
		}
	}

	return out
}

// describeSubjectBindings renders matched subject bindings for the exercise
// log: the matched subject (or "*") and the roles it granted.
func describeSubjectBindings(bindings []GlobalRoleBinding) []string {
	out := make([]string, 0, len(bindings))

	for _, b := range bindings {
		out = append(out, "subject "+b.Subject+" -> "+strings.Join(b.RoleIDs, ","))
	}

	return out
}

// describeGroupBindings renders matched group bindings for the exercise log.
func describeGroupBindings(bindings []GroupRoleBinding) []string {
	out := make([]string, 0, len(bindings))

	for _, b := range bindings {
		out = append(out, "group "+b.Group+" -> "+strings.Join(b.RoleIDs, ","))
	}

	return out
}
