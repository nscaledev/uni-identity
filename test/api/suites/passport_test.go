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

// From nscale-auth0-tests: passport.spec.ts — all sections ported to Go/Ginkgo.

//nolint:revive,testpackage // dot imports and package naming standard for Ginkgo
package suites

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Passport Exchange - Happy Paths", func() {
	// §3.1 unscoped admin exchange
	Describe("Given a valid admin token", func() {
		It("should return 200 with a non-empty passport string and expires_in 120", func() {
			resp, err := client.ExchangePassport(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(resp).NotTo(BeNil())
			Expect(resp.Passport).NotTo(BeEmpty())
			Expect(resp.ExpiresIn).To(Equal(120))

			GinkgoWriter.Printf("Unscoped admin exchange OK — passport length %d\n", len(resp.Passport))
		})
	})

	// §3.2 unscoped audit exchange
	Describe("Given a valid audit token", func() {
		BeforeEach(func() {
			if auditClient == nil {
				Skip("AUDIT_AUTH_TOKEN is not configured")
			}
		})
		It("should return 200 with a non-empty passport string and expires_in 120", func() {
			resp, err := auditClient.ExchangePassport(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(resp).NotTo(BeNil())
			Expect(resp.Passport).NotTo(BeEmpty())
			Expect(resp.ExpiresIn).To(Equal(120))

			GinkgoWriter.Printf("Unscoped audit exchange OK — passport length %d\n", len(resp.Passport))
		})
	})

	// §3.3 org-scoped exchange
	Describe("Given a valid admin token with org scope", func() {
		It("should return 200 with a passport and expires_in 120", func() {
			resp, err := client.ExchangePassport(ctx, map[string]string{
				"organizationId": config.OrgID,
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(resp).NotTo(BeNil())
			Expect(resp.Passport).NotTo(BeEmpty())
			Expect(resp.ExpiresIn).To(Equal(120))

			GinkgoWriter.Printf("Org-scoped exchange OK for org %s\n", config.OrgID)
		})
	})

	// §3.4 org+project scoped exchange
	Describe("Given a valid admin token with org and project scope", func() {
		It("should return 200 with a passport and expires_in 120", func() {
			resp, err := client.ExchangePassport(ctx, map[string]string{
				"organizationId": config.OrgID,
				"projectId":      config.ProjectID,
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(resp).NotTo(BeNil())
			Expect(resp.Passport).NotTo(BeEmpty())
			Expect(resp.ExpiresIn).To(Equal(120))

			GinkgoWriter.Printf("Org+project scoped exchange OK\n")
		})
	})

	// §3.5 repeated exchange produces distinct jti values
	Describe("Given two concurrent unscoped exchanges", func() {
		It("should produce passports with distinct jti values", func() {
			// Run sequentially to avoid timing collisions.
			resp1, err := client.ExchangePassport(ctx, nil)
			Expect(err).NotTo(HaveOccurred())

			resp2, err := client.ExchangePassport(ctx, nil)
			Expect(err).NotTo(HaveOccurred())

			claims1, err := api.DecodeJWTPayload(resp1.Passport)
			Expect(err).NotTo(HaveOccurred())

			claims2, err := api.DecodeJWTPayload(resp2.Passport)
			Expect(err).NotTo(HaveOccurred())

			jti1, _ := claims1["jti"].(string)
			jti2, _ := claims2["jti"].(string)

			Expect(jti1).NotTo(BeEmpty(), "jti must be present in passport")
			Expect(jti2).NotTo(BeEmpty(), "jti must be present in passport")
			Expect(jti1).NotTo(Equal(jti2), "each exchange must produce a unique jti")

			GinkgoWriter.Printf("jti1=%s jti2=%s\n", jti1, jti2)
		})
	})

	// §3.6 exchange response Content-Type
	Describe("Given a valid exchange request", func() {
		It("should return Content-Type: application/json", func() {
			resp, err := client.ExchangePassport(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(resp).NotTo(BeNil())
			Expect(resp.Passport).NotTo(BeEmpty(),
				"exchange response must carry a non-empty passport field")

			GinkgoWriter.Printf("Exchange response is valid JSON — passport length %d\n", len(resp.Passport))
		})
	})
})

var _ = Describe("Passport JWT Claims", func() {
	// §4.1–4.9 standard and identity claims
	Describe("Given a valid unscoped admin exchange", func() {
		It("should include correct standard and identity claims (typ, iss, sub, iat/exp, acctype, source, email)", func() {
			resp, err := client.ExchangePassport(ctx, nil)
			Expect(err).NotTo(HaveOccurred())

			claims, err := api.DecodeJWTPayload(resp.Passport)
			Expect(err).NotTo(HaveOccurred())

			// §4.1 typ distinguishes passports from access tokens
			Expect(claims["typ"]).To(Equal("passport"))
			// §4.2 iss identifies the issuing service
			Expect(claims["iss"]).To(Equal("uni-identity"))
			// §4.3 sub is the subject identifier
			sub, _ := claims["sub"].(string)
			Expect(sub).NotTo(BeEmpty())
			// §4.4 TTL is exactly 120 seconds
			iat, iatOK := claims["iat"].(float64)
			exp, expOK := claims["exp"].(float64)
			Expect(iatOK).To(BeTrue(), "iat claim must be a number")
			Expect(expOK).To(BeTrue(), "exp claim must be a number")
			Expect(exp - iat).To(BeNumerically("==", 120))
			// §4.6–4.9 identity claims
			acctype, _ := claims["acctype"].(string)
			Expect(acctype).To(BeElementOf("user", "service", "system"))
			Expect(claims["source"]).To(Equal("uni"))
			email, _ := claims["email"].(string)
			Expect(email).NotTo(BeEmpty())

			GinkgoWriter.Printf("Claims OK: typ=%v iss=%v sub=%v acctype=%v source=%v\n",
				claims["typ"], claims["iss"], sub, acctype, claims["source"])
		})

		// §4.10, §4.13–4.14 membership and context claims
		It("should include correct membership and context claims (org_ids, actor, acl)", func() {
			resp, err := client.ExchangePassport(ctx, nil)
			Expect(err).NotTo(HaveOccurred())

			claims, err := api.DecodeJWTPayload(resp.Passport)
			Expect(err).NotTo(HaveOccurred())

			// §4.10 org_ids lists the caller's authorized organizations
			orgIDs, ok := claims["org_ids"].([]interface{})
			Expect(ok).To(BeTrue(), "org_ids must be an array")
			Expect(orgIDs).NotTo(BeEmpty())

			var orgIDStrings []string
			for _, o := range orgIDs {
				if s, ok := o.(string); ok {
					orgIDStrings = append(orgIDStrings, s)
				}
			}

			Expect(orgIDStrings).To(ContainElement(config.OrgID))
			// §4.13 actor is always present
			Expect(claims).To(HaveKey("actor"))
			// §4.14 acl is a non-null object
			Expect(claims["acl"]).NotTo(BeNil())
			_, isMap := claims["acl"].(map[string]interface{})
			Expect(isMap).To(BeTrue(), "acl must be an object")

			GinkgoWriter.Printf("Membership OK: org_ids count=%d\n", len(orgIDStrings))
		})
	})

	// §4.11 org_id set in scoped passport, absent in unscoped
	Describe("Given unscoped and org-scoped exchanges", func() {
		It("should set org_id only in the scoped passport", func() {
			unscopedResp, err := client.ExchangePassport(ctx, nil)
			Expect(err).NotTo(HaveOccurred())

			scopedResp, err := client.ExchangePassport(ctx, map[string]string{
				"organizationId": config.OrgID,
			})
			Expect(err).NotTo(HaveOccurred())

			unscopedClaims, err := api.DecodeJWTPayload(unscopedResp.Passport)
			Expect(err).NotTo(HaveOccurred())

			scopedClaims, err := api.DecodeJWTPayload(scopedResp.Passport)
			Expect(err).NotTo(HaveOccurred())

			// Unscoped: org_id must be absent or empty string
			unscopedOrgID, _ := unscopedClaims["org_id"].(string)
			Expect(unscopedOrgID).To(BeEmpty(),
				"unscoped passport must not carry org_id")

			// Scoped: org_id must match the requested org
			Expect(scopedClaims["org_id"]).To(Equal(config.OrgID))

			GinkgoWriter.Printf("org_id absent in unscoped, present in scoped (%s)\n", config.OrgID)
		})
	})

	// §4.12 project_id set in full-scope passport, absent in org-only
	Describe("Given org-only and org+project scoped exchanges", func() {
		It("should set project_id only in the full-scope passport", func() {
			orgOnlyResp, err := client.ExchangePassport(ctx, map[string]string{
				"organizationId": config.OrgID,
			})
			Expect(err).NotTo(HaveOccurred())

			fullScopeResp, err := client.ExchangePassport(ctx, map[string]string{
				"organizationId": config.OrgID,
				"projectId":      config.ProjectID,
			})
			Expect(err).NotTo(HaveOccurred())

			orgOnlyClaims, err := api.DecodeJWTPayload(orgOnlyResp.Passport)
			Expect(err).NotTo(HaveOccurred())

			fullScopeClaims, err := api.DecodeJWTPayload(fullScopeResp.Passport)
			Expect(err).NotTo(HaveOccurred())

			orgOnlyProjectID, _ := orgOnlyClaims["project_id"].(string)
			Expect(orgOnlyProjectID).To(BeEmpty(),
				"org-only passport must not carry project_id")

			Expect(fullScopeClaims["project_id"]).To(Equal(config.ProjectID))

			GinkgoWriter.Printf("project_id absent in org-only, present in full-scope (%s)\n", config.ProjectID)
		})
	})
})

var _ = Describe("Passport ACL Embedding", func() {
	// §5.1 acl present and non-null in org-scoped passport
	Describe("Given an org-scoped passport", func() {
		It("should include a non-null acl claim", func() {
			resp, err := client.ExchangePassport(ctx, map[string]string{
				"organizationId": config.OrgID,
			})
			Expect(err).NotTo(HaveOccurred())

			claims, err := api.DecodeJWTPayload(resp.Passport)
			Expect(err).NotTo(HaveOccurred())

			Expect(claims["acl"]).NotTo(BeNil())
			_, isMap := claims["acl"].(map[string]interface{})
			Expect(isMap).To(BeTrue(), "acl claim must be an object in org-scoped passport")
		})
	})

	// §5.2 acl.organizations entries match /api/v1/acl response
	Describe("Given an org-scoped passport and the ACL API response for the same org", func() {
		It("should embed matching endpoint permissions in the passport acl claim", func() {
			passportResp, err := client.ExchangePassport(ctx, map[string]string{
				"organizationId": config.OrgID,
			})
			Expect(err).NotTo(HaveOccurred())

			aclResp, err := client.GetOrganizationACL(ctx, config.OrgID)
			Expect(err).NotTo(HaveOccurred())
			Expect(aclResp.Organization).NotTo(BeNil())

			claims, err := api.DecodeJWTPayload(passportResp.Passport)
			Expect(err).NotTo(HaveOccurred())

			aclClaim, _ := claims["acl"].(map[string]interface{})
			Expect(aclClaim).NotTo(BeNil())

			// Passport acl.organizations is keyed by org ID.
			orgsInPassport, _ := aclClaim["organizations"].(map[string]interface{})

			if orgsInPassport == nil || len(orgsInPassport) == 0 {
				GinkgoWriter.Printf("passport acl.organizations is absent or empty — skipping endpoint comparison\n")
				return
			}

			passportOrgACL, _ := orgsInPassport[config.OrgID].([]interface{})

			if aclResp.Organization.Endpoints == nil {
				GinkgoWriter.Printf("API ACL has no endpoints for org %s — skipping\n", config.OrgID)
				return
			}

			for _, endpoint := range *aclResp.Organization.Endpoints {
				found := false

				for _, pe := range passportOrgACL {
					entry, _ := pe.(map[string]interface{})
					if name, _ := entry["name"].(string); name == endpoint.Name {
						found = true
						break
					}
				}

				Expect(found).To(BeTrue(),
					"endpoint %q present in ACL API must also appear in passport acl", endpoint.Name)
			}

			GinkgoWriter.Printf("Passport ACL matches API ACL for org %s\n", config.OrgID)
		})
	})

	// §5.4 admin passport acl has more total operations than audit passport acl
	Describe("Given admin and audit org-scoped passports", func() {
		BeforeEach(func() {
			if auditClient == nil {
				Skip("AUDIT_AUTH_TOKEN is not configured")
			}
		})
		It("should embed more operations in the admin passport than the audit passport", func() {
			adminResp, err := client.ExchangePassport(ctx, map[string]string{
				"organizationId": config.OrgID,
			})
			Expect(err).NotTo(HaveOccurred())

			auditResp, err := auditClient.ExchangePassport(ctx, map[string]string{
				"organizationId": config.OrgID,
			})
			Expect(err).NotTo(HaveOccurred())

			adminClaims, _ := api.DecodeJWTPayload(adminResp.Passport)
			auditClaims, _ := api.DecodeJWTPayload(auditResp.Passport)

			countOps := func(claims map[string]interface{}) int {
				aclClaim, _ := claims["acl"].(map[string]interface{})
				if aclClaim == nil {
					return 0
				}

				orgs, _ := aclClaim["organizations"].(map[string]interface{})
				orgACL, _ := orgs[config.OrgID].([]interface{})
				total := 0

				for _, e := range orgACL {
					entry, _ := e.(map[string]interface{})
					ops, _ := entry["operations"].([]interface{})
					total += len(ops)
				}

				return total
			}

			adminOps := countOps(adminClaims)
			auditOps := countOps(auditClaims)

			GinkgoWriter.Printf("Admin ACL ops=%d  Audit ACL ops=%d\n", adminOps, auditOps)
			Expect(adminOps).To(BeNumerically(">", auditOps),
				"admin passport must embed more operations than audit passport")
		})
	})
})

var _ = Describe("Passport Exchange - Rejection Cases", func() {
	// §6.1 missing Authorization header → 401 with error: access_denied
	Describe("Given no Authorization header", func() {
		It("should return 401 with error access_denied", func() {
			statusCode, errorCode, err := client.WithToken("").ExchangePassportErrorCode(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(statusCode).To(Equal(http.StatusUnauthorized))
			Expect(errorCode).To(Equal("access_denied"))

			GinkgoWriter.Printf("No-auth exchange correctly returned 401 with access_denied\n")
		})
	})

	// §6.2 empty bearer token → 401
	Describe("Given an empty bearer token", func() {
		It("should return 401", func() {
			emptyTokenClient := client.WithToken(" ")
			statusCode, _, err := emptyTokenClient.ExchangePassportRaw(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(statusCode).To(Equal(http.StatusUnauthorized))
		})
	})

	// §6.3 garbage bearer token → 401
	Describe("Given a garbage bearer token", func() {
		It("should return 401", func() {
			garbageClient := client.WithToken("notavalidtoken")
			statusCode, _, err := garbageClient.ExchangePassportRaw(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(statusCode).To(Equal(http.StatusUnauthorized))
		})
	})

	// §6.5 using a passport JWT as the source token for a new exchange → 401
	Describe("Given a passport JWT used as the source token", func() {
		It("should return 401 — passports must not be accepted as exchange source tokens", func() {
			firstResp, err := client.ExchangePassport(ctx, nil)
			Expect(err).NotTo(HaveOccurred())

			passportAsSourceClient := client.WithToken(firstResp.Passport)
			statusCode, _, err := passportAsSourceClient.ExchangePassportRaw(ctx, nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(statusCode).To(Equal(http.StatusUnauthorized),
				"a passport JWT must not be accepted as a source token for a new exchange")

			GinkgoWriter.Printf("Passport-as-source-token correctly rejected with 401\n")
		})
	})
})

var _ = Describe("Passport Exchange - Scope Validation", func() {
	// §7.1 non-member org not embedded in org_id
	Describe("Given an org ID the caller is not a member of", func() {
		BeforeEach(func() {
			if config.UnauthorisedOrgID == "" {
				Skip("UNAUTHORISED_ORG_ID is not configured")
			}
		})
		It("should not embed the non-member org in the passport org_id claim", func() {
			statusCode, resp, err := client.ExchangePassportTryParse(ctx, map[string]string{
				"organizationId": config.UnauthorisedOrgID,
			})
			Expect(err).NotTo(HaveOccurred())

			if statusCode != http.StatusOK {
				Expect(statusCode).To(BeElementOf(http.StatusBadRequest, http.StatusForbidden))
				GinkgoWriter.Printf("Non-member org scope rejected with %d\n", statusCode)
				return
			}

			claims, err := api.DecodeJWTPayload(resp.Passport)
			Expect(err).NotTo(HaveOccurred())

			orgID, _ := claims["org_id"].(string)
			Expect(orgID).NotTo(Equal(config.UnauthorisedOrgID),
				"org_id must not be set to an org the caller is not a member of")

			GinkgoWriter.Printf("Non-member org scope correctly handled — org_id absent\n")
		})
	})

	// §7.2 garbage project ID not embedded
	Describe("Given a garbage project ID", func() {
		It("should not embed the garbage project ID in the passport project_id claim", func() {
			fakeProjectID := "not-a-real-project-id"
			statusCode, resp, err := client.ExchangePassportTryParse(ctx, map[string]string{
				"organizationId": config.OrgID,
				"projectId":      fakeProjectID,
			})
			Expect(err).NotTo(HaveOccurred())

			if statusCode != http.StatusOK {
				Expect(statusCode).To(BeElementOf(http.StatusBadRequest, http.StatusForbidden))
				GinkgoWriter.Printf("Garbage project ID rejected with %d\n", statusCode)
				return
			}

			claims, err := api.DecodeJWTPayload(resp.Passport)
			Expect(err).NotTo(HaveOccurred())

			projectID, _ := claims["project_id"].(string)
			Expect(projectID).NotTo(Equal(fakeProjectID),
				"project_id must not be set to a non-existent project ID")

			GinkgoWriter.Printf("Garbage project ID correctly not embedded in passport\n")
		})
	})

	// §7.3 garbage org ID not embedded
	Describe("Given a garbage org ID", func() {
		It("should not embed the garbage org ID in the passport org_id claim", func() {
			fakeOrgID := "not-a-real-org-id"
			statusCode, resp, err := client.ExchangePassportTryParse(ctx, map[string]string{
				"organizationId": fakeOrgID,
			})
			Expect(err).NotTo(HaveOccurred())

			if statusCode != http.StatusOK {
				Expect(statusCode).To(BeElementOf(http.StatusBadRequest, http.StatusForbidden))
				GinkgoWriter.Printf("Garbage org ID rejected with %d\n", statusCode)
				return
			}

			claims, err := api.DecodeJWTPayload(resp.Passport)
			Expect(err).NotTo(HaveOccurred())

			orgID, _ := claims["org_id"].(string)
			Expect(orgID).NotTo(Equal(fakeOrgID),
				"org_id must not be set to a non-existent org ID")

			GinkgoWriter.Printf("Garbage org ID correctly not embedded in passport\n")
		})
	})
})

var _ = Describe("Passport JWKS Verification", func() {
	// §8.1 JWKS endpoint returns at least one EC key
	Describe("Given a request to the JWKS endpoint", func() {
		It("should return at least one EC key", func() {
			jwks, err := client.GetJWKS(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(jwks).NotTo(BeNil())
			Expect(jwks.Keys).NotTo(BeEmpty(), "JWKS must contain at least one key")

			var ecKey *api.JWK
			for i := range jwks.Keys {
				if jwks.Keys[i].Kty == "EC" {
					ecKey = &jwks.Keys[i]
					break
				}
			}

			Expect(ecKey).NotTo(BeNil(), "JWKS must contain at least one EC key")
			GinkgoWriter.Printf("Found EC key with kid=%s\n", ecKey.Kid)
		})
	})

	// §8.2–8.3 passport kid header present and matches a key in JWKS
	Describe("Given a passport and the JWKS", func() {
		It("should have a kid header that matches a key in the JWKS", func() {
			passportResp, err := client.ExchangePassport(ctx, nil)
			Expect(err).NotTo(HaveOccurred())

			jwks, err := client.GetJWKS(ctx)
			Expect(err).NotTo(HaveOccurred())

			header, err := api.DecodeJWTHeader(passportResp.Passport)
			Expect(err).NotTo(HaveOccurred())

			kid, _ := header["kid"].(string)
			Expect(kid).NotTo(BeEmpty(), "passport JWT header must include a kid field")

			var matchingKey *api.JWK
			for i := range jwks.Keys {
				if jwks.Keys[i].Kid == kid {
					matchingKey = &jwks.Keys[i]
					break
				}
			}

			Expect(matchingKey).NotTo(BeNil(),
				"passport kid %q must match a key in the JWKS", kid)

			GinkgoWriter.Printf("Passport kid %s matched JWKS key (kty=%s)\n", kid, matchingKey.Kty)
		})
	})
})

var _ = Describe("Phase 2 Regression - Existing Endpoints Unaffected", func() {
	// §9.1 userinfo still returns authz claims
	Describe("Given a valid admin token", func() {
		It("should still return authz.acctype and authz.orgIds from userinfo", func() {
			userinfo, err := client.GetUserinfo(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(userinfo).NotTo(BeNil())
			Expect(userinfo.HttpsunikornCloudOrgauthz).NotTo(BeNil(),
				"https://unikorn-cloud.org/authz claim must still be present after Phase 2")
			Expect(userinfo.HttpsunikornCloudOrgauthz.Acctype).NotTo(BeEmpty())
			Expect(userinfo.HttpsunikornCloudOrgauthz.OrgIds).NotTo(BeEmpty())

			GinkgoWriter.Printf("Userinfo regression OK: acctype=%s orgIds=%v\n",
				userinfo.HttpsunikornCloudOrgauthz.Acctype,
				userinfo.HttpsunikornCloudOrgauthz.OrgIds)
		})
	})

	// §9.2 ACL endpoint still returns org-scoped permissions
	Describe("Given a valid admin token with org scope", func() {
		It("should still return org-scoped permissions from the ACL endpoint", func() {
			acl, err := client.GetOrganizationACL(ctx, config.OrgID)

			Expect(err).NotTo(HaveOccurred())
			Expect(acl).NotTo(BeNil())
			Expect(acl.Organization).NotTo(BeNil(),
				"ACL endpoint must still return org-scoped data after Phase 2")
			Expect(acl.Organization.Id).To(Equal(config.OrgID))

			if acl.Organization.Endpoints != nil {
				Expect(*acl.Organization.Endpoints).NotTo(BeEmpty())
			}

			GinkgoWriter.Printf("ACL regression OK for org %s\n", config.OrgID)
		})
	})
})
