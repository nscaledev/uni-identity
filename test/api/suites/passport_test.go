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
	"encoding/json"
	"net/http"
	"net/url"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

type actorClaim struct {
	Subject string      `json:"sub"`
	Act     *actorClaim `json:"act,omitempty"`
}

type passportClaims struct {
	jwt.Claims `json:",inline"`

	Type      string                            `json:"typ"`
	Acctype   identityopenapi.AuthClaimsAcctype `json:"acctype"`
	Source    string                            `json:"source"`
	Email     string                            `json:"email,omitempty"`
	OrgIDs    []string                          `json:"org_ids"`
	OrgID     string                            `json:"org_id,omitempty"`
	ProjectID string                            `json:"project_id,omitempty"`
	Actor     *actorClaim                       `json:"act,omitempty"`
}

func passportIssuedTokenType() string {
	return "urn:nscale:params:oauth:token-type:passport"
}

func tokenExchangeGrantType() string {
	return "urn:ietf:params:oauth:grant-type:token-exchange"
}

func accessTokenSubjectTokenType() string {
	return "urn:ietf:params:oauth:token-type:access_token"
}

func decodePassportClaims(passport string) passportClaims {
	parsed, err := jwt.ParseSigned(passport, []gojose.SignatureAlgorithm{gojose.ES512})
	Expect(err).NotTo(HaveOccurred(), "Passport should be a valid ES512 JWS")
	Expect(parsed.Headers).To(HaveLen(1))
	Expect(parsed.Headers[0].Algorithm).To(Equal(string(gojose.ES512)))

	var claims passportClaims

	Expect(parsed.UnsafeClaimsWithoutVerification(&claims)).To(Succeed())

	return claims
}

func decodePassportClaimMap(passport string) map[string]any {
	parsed, err := jwt.ParseSigned(passport, []gojose.SignatureAlgorithm{gojose.ES512})
	Expect(err).NotTo(HaveOccurred(), "Passport should be a valid ES512 JWS")

	var claims map[string]any

	Expect(parsed.UnsafeClaimsWithoutVerification(&claims)).To(Succeed())

	return claims
}

func passportTTLSeconds(claims passportClaims) int64 {
	Expect(claims.IssuedAt).NotTo(BeNil(), "Passport iat claim should be present")
	Expect(claims.Expiry).NotTo(BeNil(), "Passport exp claim should be present")

	return int64(*claims.Expiry) - int64(*claims.IssuedAt)
}

func keySetFromJWKS(jwks *identityopenapi.JwksResponse) *gojose.JSONWebKeySet {
	Expect(jwks).NotTo(BeNil())

	encoded, err := json.Marshal(jwks)
	Expect(err).NotTo(HaveOccurred(), "JWKS should marshal from the OpenAPI response")

	var keySet gojose.JSONWebKeySet

	Expect(json.Unmarshal(encoded, &keySet)).To(Succeed(), "JWKS should decode as a JOSE key set")

	return &keySet
}

func verifyPassportClaims(passport string, jwks *identityopenapi.JwksResponse) passportClaims {
	parsed, err := jwt.ParseSigned(passport, []gojose.SignatureAlgorithm{gojose.ES512})
	Expect(err).NotTo(HaveOccurred(), "Passport should be a valid ES512 JWS")
	Expect(parsed.Headers).To(HaveLen(1))
	Expect(parsed.Headers[0].Algorithm).To(Equal(string(gojose.ES512)))
	Expect(parsed.Headers[0].KeyID).NotTo(BeEmpty(), "Passport header should carry a kid")

	keySet := keySetFromJWKS(jwks)
	Expect(keySet.Key(parsed.Headers[0].KeyID)).NotTo(BeEmpty(), "JWKS should contain the passport signing key")

	var claims passportClaims

	Expect(parsed.Claims(keySet, &claims)).To(Succeed(), "Passport signature should verify against JWKS")

	return claims
}

func decodeExchangeOAuth2Error(respBody []byte) identityopenapi.Oauth2Error {
	var oauthErr identityopenapi.Oauth2Error

	Expect(json.Unmarshal(respBody, &oauthErr)).To(Succeed())

	return oauthErr
}

func expectExchangeOAuth2Error(respBody []byte, expected identityopenapi.Oauth2ErrorError, descriptionSubstring string) {
	oauthErr := decodeExchangeOAuth2Error(respBody)
	Expect(oauthErr.Error).To(Equal(expected))
	if descriptionSubstring != "" {
		Expect(oauthErr.ErrorDescription).To(ContainSubstring(descriptionSubstring))
	}
	Expect(string(respBody)).NotTo(ContainSubstring("access_token"))
}

var _ = Describe("Passport Token Exchange", func() {
	Context("When exchanging an access token for a passport", func() {
		Describe("Given valid authentication without scope", func() {
			It("should return a signed passport with correct metadata", func() {
				result, err := client.ExchangePassport(ctx, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty(), "Passport JWT should not be empty")
				Expect(result.ExpiresIn).To(Equal(60), "Passport TTL should be 60 seconds")
				Expect(result.TokenType).To(Equal("Bearer"))
				Expect(result.IssuedTokenType).NotTo(BeNil())
				Expect(*result.IssuedTokenType).To(Equal(passportIssuedTokenType()))

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.Type).To(Equal("passport"))
				Expect(claims.Issuer).To(Equal("uni-identity"))
				Expect(claims.Source).To(Equal("uni"))
				Expect(claims.Subject).NotTo(BeEmpty())
				Expect(claims.ID).NotTo(BeEmpty())
				_, err = uuid.Parse(claims.ID)
				Expect(err).NotTo(HaveOccurred(), "Passport jti should be a UUID")
				Expect(passportTTLSeconds(claims)).To(Equal(int64(60)))
				Expect(claims.OrgIDs).To(ContainElement(config.OrgID))
				Expect(claims.Actor).To(BeNil(), "act claim must be omitted when subject is the acting party")
				Expect(decodePassportClaimMap(result.AccessToken)).NotTo(HaveKey("acl"),
					"Passport must not embed ACLs; authorization stays on the remote authorizer path")

				GinkgoWriter.Printf("Passport exchanged successfully, expires_in: %d\n", result.ExpiresIn)
			})
		})

		Describe("Given valid authentication with response inspection", func() {
			It("should return a JSON token response", func() {
				resp, respBody, err := client.ExchangePassportRaw(ctx, http.StatusOK, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.Header.Get("Content-Type")).To(ContainSubstring("application/json"))

				var result identityopenapi.Token

				Expect(json.Unmarshal(respBody, &result)).To(Succeed())
				Expect(result.AccessToken).NotTo(BeEmpty())
				Expect(result.ExpiresIn).To(Equal(60))
				Expect(result.TokenType).To(Equal("Bearer"))
				Expect(result.IssuedTokenType).NotTo(BeNil())
				Expect(*result.IssuedTokenType).To(Equal(passportIssuedTokenType()))
			})
		})

		Describe("Given repeated valid authentication", func() {
			It("should mint a unique passport for each exchange", func() {
				first, err := client.ExchangePassport(ctx, nil)
				Expect(err).NotTo(HaveOccurred())

				second, err := client.ExchangePassport(ctx, nil)
				Expect(err).NotTo(HaveOccurred())

				Expect(first.AccessToken).NotTo(Equal(second.AccessToken))

				firstClaims := decodePassportClaims(first.AccessToken)
				secondClaims := decodePassportClaims(second.AccessToken)

				Expect(firstClaims.ID).NotTo(BeEmpty())
				Expect(secondClaims.ID).NotTo(BeEmpty())
				Expect(firstClaims.ID).NotTo(Equal(secondClaims.ID))
			})
		})

		Describe("Given valid authentication with organization scope", func() {
			It("should return a passport scoped to the organization", func() {
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
				}

				result, err := client.ExchangePassport(ctx, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty(), "Passport JWT should not be empty")
				Expect(result.ExpiresIn).To(Equal(60), "Passport TTL should be 60 seconds")

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.OrgID).To(Equal(config.OrgID))
				Expect(claims.ProjectID).To(BeEmpty())

				GinkgoWriter.Printf("Org-scoped passport exchanged for org %s\n", config.OrgID)
			})
		})

		Describe("Given valid authentication with organization and project scope", func() {
			It("should return a passport scoped to the organization and project", func() {
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
					XProjectId:      &config.ProjectID,
				}

				result, err := client.ExchangePassport(ctx, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty(), "Passport JWT should not be empty")
				Expect(result.ExpiresIn).To(Equal(60), "Passport TTL should be 60 seconds")

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.OrgID).To(Equal(config.OrgID))
				Expect(claims.ProjectID).To(Equal(config.ProjectID))

				GinkgoWriter.Printf("Org+project-scoped passport exchanged for org %s, project %s\n",
					config.OrgID, config.ProjectID)
			})
		})

		Describe("Given valid authentication with audience and resource hints", func() {
			It("should include the requested audience values in the passport", func() {
				audience := "uni-region"
				resource := "https://region.identity.test/"
				options := &identityopenapi.TokenRequestOptions{
					Audience: &audience,
					Resource: &resource,
				}

				result, err := client.ExchangePassport(ctx, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())

				claims := decodePassportClaims(result.AccessToken)
				Expect([]string(claims.Audience)).To(ConsistOf(resource, audience))
			})
		})

		Describe("Given project-scoped fixture user authentication", func() {
			BeforeEach(func() {
				Expect(userClient).NotTo(BeNil(), "USER_AUTH_TOKEN must be set by integration fixtures")
			})

			It("should return a user passport scoped to the fixture project", func() {
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
					XProjectId:      &config.ProjectID,
				}

				result, err := userClient.ExchangePassport(ctx, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty())

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.Acctype).To(Equal(identityopenapi.User))
				Expect(claims.OrgIDs).To(ContainElement(config.OrgID))
				Expect(claims.OrgID).To(Equal(config.OrgID))
				Expect(claims.ProjectID).To(Equal(config.ProjectID))
			})
		})

		Describe("Given an out-of-scope organization", func() {
			It("should reject the exchange with an OAuth2 invalid_scope response", func() {
				invalidOrgID := "00000000-0000-0000-0000-000000000000"
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &invalidOrgID,
				}

				resp, respBody, err := client.ExchangePassportRaw(ctx, 0, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				oauthErr := decodeExchangeOAuth2Error(respBody)
				Expect(oauthErr.Error).To(Equal(identityopenapi.InvalidScope))
				Expect(oauthErr.ErrorDescription).To(ContainSubstring("organization not in scope"))
			})
		})

		Describe("Given an invalid project scope", func() {
			It("should reject the exchange with an OAuth2 invalid_scope response", func() {
				invalidProjectID := "00000000-0000-0000-0000-000000000000"
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
					XProjectId:      &invalidProjectID,
				}

				resp, respBody, err := client.ExchangePassportRaw(ctx, 0, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				oauthErr := decodeExchangeOAuth2Error(respBody)
				Expect(oauthErr.Error).To(Equal(identityopenapi.InvalidScope))
				Expect(oauthErr.ErrorDescription).To(ContainSubstring("project not in scope"))
			})
		})

		Describe("Given fixture user authentication for an unauthorized organization", func() {
			BeforeEach(func() {
				if userClient == nil {
					Skip("USER_AUTH_TOKEN is required for user permission passport testing")
				}
				if config.UnauthorisedOrgID == "" {
					Skip("UNAUTHORISED_ORG_ID is required for user permission passport testing")
				}
			})

			It("should reject the exchange with an OAuth2 access_denied response", func() {
				options := &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.UnauthorisedOrgID,
				}

				resp, respBody, err := userClient.ExchangePassportRaw(ctx, 0, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
				expectExchangeOAuth2Error(respBody, identityopenapi.AccessDenied, "organization not in scope")
			})
		})

		Describe("Given project scope without organization scope", func() {
			It("should reject the exchange with an OAuth2 invalid_request response", func() {
				options := &identityopenapi.TokenRequestOptions{
					XProjectId: &config.ProjectID,
				}

				resp, respBody, err := client.ExchangePassportRaw(ctx, 0, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "x_organization_id must be specified")
			})
		})

		Describe("Given an invalid resource URI", func() {
			It("should reject the exchange with an OAuth2 invalid_request response", func() {
				resource := "not-a-uri"
				options := &identityopenapi.TokenRequestOptions{
					Resource: &resource,
				}

				resp, respBody, err := client.ExchangePassportRaw(ctx, 0, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "resource must be an absolute URI")
			})
		})

		Describe("Given an unsupported requested token type", func() {
			It("should reject the exchange with an OAuth2 invalid_request response", func() {
				requestedTokenType := "urn:ietf:params:oauth:token-type:id_token"
				options := &identityopenapi.TokenRequestOptions{
					RequestedTokenType: &requestedTokenType,
				}

				resp, respBody, err := client.ExchangePassportRaw(ctx, 0, options)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "requested_token_type is not supported")
			})
		})

		Describe("Given an invalid source token", func() {
			It("should return unauthorized access_denied without minting a passport", func() {
				form := url.Values{
					"grant_type":           {tokenExchangeGrantType()},
					"subject_token":        {"not-a-valid-token"},
					"subject_token_type":   {accessTokenSubjectTokenType()},
					"requested_token_type": {passportIssuedTokenType()},
				}

				resp, respBody, err := client.ExchangePassportRawForm(ctx, http.StatusUnauthorized, form)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
				expectExchangeOAuth2Error(respBody, identityopenapi.AccessDenied, "token validation failed")
			})
		})

		Describe("Given a passport is presented as the source token", func() {
			It("should reject the exchange with an OAuth2 access_denied response", func() {
				result, err := client.ExchangePassport(ctx, nil)
				Expect(err).NotTo(HaveOccurred())

				passportConfig := *config
				passportConfig.AuthToken = result.AccessToken
				passportClient := api.NewAPIClientWithConfig(&passportConfig)

				resp, respBody, err := passportClient.ExchangePassportRaw(ctx, 0, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))

				expectExchangeOAuth2Error(respBody, identityopenapi.AccessDenied, "")
			})
		})

		Describe("Given no authentication", func() {
			It("should reject the exchange request", func() {
				unauthConfig := *config
				unauthConfig.AuthToken = ""
				unauthClient := api.NewAPIClientWithConfig(&unauthConfig)

				resp, respBody, err := unauthClient.ExchangePassportRaw(ctx, http.StatusBadRequest, nil)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "subject_token must be specified")

				GinkgoWriter.Printf("Expected error for missing authentication: %v\n", err)
			})
		})

		Describe("Given a missing subject token type", func() {
			It("should reject the request with an OAuth2 invalid_request response", func() {
				form := url.Values{
					"grant_type":           {tokenExchangeGrantType()},
					"subject_token":        {config.AuthToken},
					"requested_token_type": {passportIssuedTokenType()},
				}

				resp, respBody, err := client.ExchangePassportRawForm(ctx, http.StatusBadRequest, form)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "subject_token_type must be specified")
			})
		})

		Describe("Given an unsupported subject token type", func() {
			It("should reject the request with an OAuth2 invalid_request response", func() {
				form := url.Values{
					"grant_type":           {tokenExchangeGrantType()},
					"subject_token":        {config.AuthToken},
					"subject_token_type":   {"urn:ietf:params:oauth:token-type:id_token"},
					"requested_token_type": {passportIssuedTokenType()},
				}

				resp, respBody, err := client.ExchangePassportRawForm(ctx, http.StatusBadRequest, form)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "subject_token_type is not supported")
			})
		})

		Describe("Given token exchange parameters in the URL query", func() {
			It("should reject the request with an OAuth2 invalid_request response", func() {
				form := url.Values{
					"grant_type":         {tokenExchangeGrantType()},
					"subject_token":      {config.AuthToken},
					"subject_token_type": {accessTokenSubjectTokenType()},
				}
				query := url.Values{
					"subject_token": {"query-token-value"},
				}

				resp, respBody, err := client.ExchangePassportRawPathForm(ctx, http.StatusBadRequest,
					client.GetEndpoints().Token()+"?"+query.Encode(), form)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "subject_token must be supplied in the form body")
			})
		})

		Describe("Given actor token delegation parameters", func() {
			It("should reject the request with an OAuth2 invalid_request response", func() {
				form := url.Values{
					"grant_type":           {tokenExchangeGrantType()},
					"subject_token":        {config.AuthToken},
					"subject_token_type":   {accessTokenSubjectTokenType()},
					"requested_token_type": {passportIssuedTokenType()},
					"actor_token":          {"actor-token"},
					"actor_token_type":     {accessTokenSubjectTokenType()},
				}

				resp, respBody, err := client.ExchangePassportRawForm(ctx, http.StatusBadRequest, form)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))
				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "actor_token is not supported")
			})
		})

		Describe("Given a missing token-exchange grant type", func() {
			It("should reject the request without minting a passport", func() {
				form := url.Values{
					"subject_token":        {config.AuthToken},
					"subject_token_type":   {accessTokenSubjectTokenType()},
					"requested_token_type": {passportIssuedTokenType()},
				}

				resp, respBody, err := client.ExchangePassportRawForm(ctx, http.StatusBadRequest, form)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "token grant type is not supported")
			})
		})

		Describe("Given a wrong grant type with exchange parameters", func() {
			It("should not apply token-exchange semantics or mint a passport", func() {
				form := url.Values{
					"grant_type":           {"client_credentials"},
					"subject_token":        {config.AuthToken},
					"subject_token_type":   {accessTokenSubjectTokenType()},
					"requested_token_type": {passportIssuedTokenType()},
				}

				resp, respBody, err := client.ExchangePassportRawForm(ctx, http.StatusBadRequest, form)

				Expect(err).NotTo(HaveOccurred())
				Expect(resp).NotTo(BeNil())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				expectExchangeOAuth2Error(respBody, identityopenapi.InvalidRequest, "mTLS client verification failed")
			})
		})
	})

	Context("When verifying a passport with the published JWKS", func() {
		Describe("Given a valid passport", func() {
			It("should verify the signature using the key identified by kid", func() {
				result, err := client.ExchangePassport(ctx, &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty())

				jwks, err := client.GetJWKS(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(jwks.Keys).NotTo(BeNil(), "JWKS keys should be present")
				Expect(*jwks.Keys).NotTo(BeEmpty(), "JWKS should expose at least one signing key")

				claims := verifyPassportClaims(result.AccessToken, jwks)
				Expect(claims.Type).To(Equal("passport"))
				Expect(claims.Issuer).To(Equal("uni-identity"))
				Expect(claims.OrgID).To(Equal(config.OrgID))
			})
		})
	})

	Context("When exchanging a service account access token for a passport", func() {
		Describe("Given a service account in the organization", func() {
			It("should return a signed service passport with the expected claims", func() {
				created, _ := api.CreateServiceAccountWithCleanup(client, ctx, config,
					api.NewServiceAccountPayload().Build())

				Expect(created.Status.AccessToken).NotTo(BeNil(), "Service account create should return a token")

				serviceConfig := *config
				serviceConfig.AuthToken = *created.Status.AccessToken
				serviceClient := api.NewAPIClientWithConfig(&serviceConfig)

				result, err := serviceClient.ExchangePassport(ctx, &identityopenapi.TokenRequestOptions{
					XOrganizationId: &config.OrgID,
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())
				Expect(result.AccessToken).NotTo(BeEmpty())
				Expect(result.ExpiresIn).To(Equal(60))
				Expect(result.TokenType).To(Equal("Bearer"))
				Expect(result.IssuedTokenType).NotTo(BeNil())
				Expect(*result.IssuedTokenType).To(Equal(passportIssuedTokenType()))

				claims := decodePassportClaims(result.AccessToken)
				Expect(claims.Type).To(Equal("passport"))
				Expect(claims.Acctype).To(Equal(identityopenapi.Service))
				Expect(claims.Source).To(Equal("uni"))
				Expect(claims.Subject).NotTo(BeEmpty())
				Expect(claims.Actor).To(BeNil(), "act claim must be omitted when subject is the acting party")
				Expect(claims.OrgIDs).To(ContainElement(config.OrgID))
				Expect(claims.OrgID).To(Equal(config.OrgID))
				Expect(claims.ProjectID).To(BeEmpty())
			})
		})
	})
})
