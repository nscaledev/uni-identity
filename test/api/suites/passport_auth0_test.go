//go:build integration
// +build integration

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

//nolint:revive,testpackage // dot imports and package naming standard for Ginkgo
package suites

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

const skippedEquivalentUNIReason = "skipped: automated fixtures do not yet mint non-interactive UNI human/federated tokens for same-identity parity"

func requireAuth0Fixture(name, value string) {
	if strings.TrimSpace(value) == "" {
		Skip(fmt.Sprintf("%s is required for Auth0 exchange integration testing", name))
	}
}

func sortedStrings(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)

	return out
}

var _ = Describe("Passport Token Exchange Auth0", func() {
	Context("When exchanging an Auth0 JWT subject token", func() {
		Describe("Given a valid Auth0 JWT", func() {
			It("should return a signed passport with expected identity claims", func() {
				requireAuth0Fixture("AUTH0_VALID_JWT_TOKEN", config.Auth0ValidJWTToken)
				requireAuth0Fixture("AUTH0_EXPECTED_SUBJECT", config.Auth0ExpectedSubject)

				result, err := client.ExchangePassportWithSubjectToken(ctx, config.Auth0ValidJWTToken, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty())
				Expect(result.TokenType).To(Equal("Bearer"))
				Expect(result.ExpiresIn).To(Equal(120))
				Expect(result.IssuedTokenType).NotTo(BeNil())
				Expect(*result.IssuedTokenType).To(Equal(passportIssuedTokenType()))

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.Type).To(Equal("passport"))
				Expect(claims.Source).To(Equal("auth0"))
				Expect(claims.Acctype).To(Equal(identityopenapi.User))
				Expect(claims.Subject).To(Equal(config.Auth0ExpectedSubject))
				Expect(claims.Actor).To(Equal(config.Auth0ExpectedSubject))
				Expect(claims.OrgIDs).To(ContainElement(config.OrgID))
				Expect(claims.Expiry).NotTo(BeNil())
				Expect(claims.Expiry.Time()).To(BeTemporally(">", time.Now()))
			})
		})

		Describe("Given a JWT with wrong audience", func() {
			It("should reject exchange with OAuth2 access_denied", func() {
				requireAuth0Fixture("AUTH0_WRONG_AUDIENCE_JWT_TOKEN", config.Auth0WrongAudienceJWTToken)

				response, responseBody, err := client.ExchangePassportRawWithSubjectToken(
					ctx,
					config.Auth0WrongAudienceJWTToken,
					0,
					nil,
				)

				Expect(err).NotTo(HaveOccurred())
				Expect(response).NotTo(BeNil())
				Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))

				oauthError := decodeExchangeOAuth2Error(responseBody)
				Expect(oauthError.Error).To(Equal(identityopenapi.AccessDenied))
				Expect(oauthError.ErrorDescription).To(ContainSubstring("token validation failed"))
			})
		})

		Describe("Given an expired JWT", func() {
			It("should reject exchange with OAuth2 access_denied", func() {
				requireAuth0Fixture("AUTH0_EXPIRED_JWT_TOKEN", config.Auth0ExpiredJWTToken)

				response, responseBody, err := client.ExchangePassportRawWithSubjectToken(
					ctx,
					config.Auth0ExpiredJWTToken,
					0,
					nil,
				)

				Expect(err).NotTo(HaveOccurred())
				Expect(response).NotTo(BeNil())
				Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))

				oauthError := decodeExchangeOAuth2Error(responseBody)
				Expect(oauthError.Error).To(Equal(identityopenapi.AccessDenied))
				Expect(oauthError.ErrorDescription).To(ContainSubstring("token validation failed"))
			})
		})

		Describe("Given a JWT from the wrong issuer", func() {
			It("should reject exchange with OAuth2 access_denied", func() {
				requireAuth0Fixture("AUTH0_WRONG_ISSUER_JWT_TOKEN", config.Auth0WrongIssuerJWTToken)

				response, responseBody, err := client.ExchangePassportRawWithSubjectToken(
					ctx,
					config.Auth0WrongIssuerJWTToken,
					0,
					nil,
				)

				Expect(err).NotTo(HaveOccurred())
				Expect(response).NotTo(BeNil())
				Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))

				oauthError := decodeExchangeOAuth2Error(responseBody)
				Expect(oauthError.Error).To(Equal(identityopenapi.AccessDenied))
				Expect(oauthError.ErrorDescription).To(ContainSubstring("token validation failed"))
			})
		})
	})

	Context("When Auth0 token resolves no active user mapping", func() {
		Describe("Given a valid Auth0 JWT for an inactive identity", func() {
			It("should reject exchange with an OAuth2 access_denied response", func() {
				requireAuth0Fixture("AUTH0_INACTIVE_USER_JWT_TOKEN", config.Auth0InactiveUserJWTToken)

				response, responseBody, err := client.ExchangePassportRawWithSubjectToken(
					ctx,
					config.Auth0InactiveUserJWTToken,
					0,
					nil,
				)

				Expect(err).NotTo(HaveOccurred())
				Expect(response).NotTo(BeNil())
				Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))

				oauthError := decodeExchangeOAuth2Error(responseBody)
				Expect(oauthError.Error).To(Equal(identityopenapi.AccessDenied))
				Expect(oauthError.ErrorDescription).To(ContainSubstring("user identity not found or inactive"))
			})
		})
	})

	Context("When Auth0 opaque fallback is enabled", func() {
		Describe("Given an opaque Auth0 token", func() {
			It("should return a signed passport via fallback with expected identity claims", func() {
				requireAuth0Fixture("AUTH0_OPAQUE_TOKEN", config.Auth0OpaqueToken)
				requireAuth0Fixture("AUTH0_EXPECTED_SUBJECT", config.Auth0ExpectedSubject)

				result, err := client.ExchangePassportWithSubjectToken(ctx, config.Auth0OpaqueToken, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty())
				Expect(result.TokenType).To(Equal("Bearer"))
				Expect(result.ExpiresIn).To(Equal(120))

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.Type).To(Equal("passport"))
				Expect(claims.Source).To(Equal("auth0"))
				Expect(claims.Acctype).To(Equal(identityopenapi.User))
				Expect(claims.Subject).To(Equal(config.Auth0ExpectedSubject))
				Expect(claims.Actor).To(Equal(config.Auth0ExpectedSubject))
				Expect(claims.OrgIDs).To(ContainElement(config.OrgID))
				Expect(claims.Expiry).NotTo(BeNil())
				Expect(claims.Expiry.Time()).To(BeTemporally(">", time.Now()))
			})
		})
	})

	Context("When exchanging equivalent UNI and Auth0 identities", func() {
		Describe("Given UNI and Auth0 tokens for the same human identity", func() {
			It("should mint passports with equivalent identity claim values", func() {
				Skip(skippedEquivalentUNIReason)

				requireAuth0Fixture("AUTH0_VALID_JWT_TOKEN", config.Auth0ValidJWTToken)
				requireAuth0Fixture("AUTH0_EQUIVALENT_UNI_TOKEN", config.Auth0EquivalentUNIToken)

				auth0Passport, err := client.ExchangePassportWithSubjectToken(ctx, config.Auth0ValidJWTToken, nil)
				Expect(err).NotTo(HaveOccurred())

				uniPassport, err := client.ExchangePassportWithSubjectToken(ctx, config.Auth0EquivalentUNIToken, nil)
				Expect(err).NotTo(HaveOccurred())

				auth0Claims := decodePassportClaims(auth0Passport.AccessToken)
				uniClaims := decodePassportClaims(uniPassport.AccessToken)

				Expect(auth0Claims.Source).To(Equal("auth0"))
				Expect(uniClaims.Source).To(Equal("uni"))
				Expect(auth0Claims.Subject).To(Equal(uniClaims.Subject))
				Expect(auth0Claims.Actor).To(Equal(uniClaims.Actor))
				Expect(auth0Claims.Acctype).To(Equal(uniClaims.Acctype))
				Expect(sortedStrings(auth0Claims.OrgIDs)).To(Equal(sortedStrings(uniClaims.OrgIDs)))
			})
		})
	})

	Context("When comparing exchange with current userinfo path", func() {
		Describe("Given a UNI token for the same identity", func() {
			It("should preserve subject and organization context parity", func() {
				Skip(skippedEquivalentUNIReason)

				requireAuth0Fixture("AUTH0_VALID_JWT_TOKEN", config.Auth0ValidJWTToken)
				requireAuth0Fixture("AUTH0_EQUIVALENT_UNI_TOKEN", config.Auth0EquivalentUNIToken)

				auth0Passport, err := client.ExchangePassportWithSubjectToken(ctx, config.Auth0ValidJWTToken, nil)
				Expect(err).NotTo(HaveOccurred())

				userinfo, err := client.GetUserinfoWithAccessToken(ctx, config.Auth0EquivalentUNIToken)
				Expect(err).NotTo(HaveOccurred())
				Expect(userinfo).NotTo(BeNil())
				Expect(userinfo.HttpsunikornCloudOrgauthz).NotTo(BeNil())

				auth0Claims := decodePassportClaims(auth0Passport.AccessToken)

				Expect(auth0Claims.Subject).To(Equal(userinfo.Sub))
				Expect(auth0Claims.Actor).To(Equal(userinfo.Sub))
				Expect(auth0Claims.Acctype).To(Equal(userinfo.HttpsunikornCloudOrgauthz.Acctype))
				Expect(sortedStrings(auth0Claims.OrgIDs)).To(Equal(sortedStrings(userinfo.HttpsunikornCloudOrgauthz.OrgIds)))
			})
		})
	})
})
