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
	"errors"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	coreclient "github.com/unikorn-cloud/core/pkg/testing/client"
	identityopenapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/test/api"
)

var _ = Describe("Userinfo", func() {
	Context("When calling the userinfo endpoint", func() {
		Describe("Given valid authentication", func() {
			It("should return claims including a non-empty sub", func() {
				userinfo, err := client.GetUserinfo(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(userinfo).NotTo(BeNil())
				Expect(userinfo.Sub).NotTo(BeEmpty(), "sub claim must be present in userinfo response")

				GinkgoWriter.Printf("Userinfo sub: %s\n", userinfo.Sub)
			})

			It("should return consistent sub across repeated calls", func() {
				first, err := client.GetUserinfo(ctx)
				Expect(err).NotTo(HaveOccurred())

				second, err := client.GetUserinfo(ctx)
				Expect(err).NotTo(HaveOccurred())

				Expect(first.Sub).To(Equal(second.Sub),
					"sub claim must be stable for the same token")
			})

			It("should include the custom authz claims with a valid acctype", func() {
				userinfo, err := client.GetUserinfo(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(userinfo).NotTo(BeNil())
				Expect(userinfo.HttpsunikornCloudOrgauthz).NotTo(BeNil(),
					"https://unikorn-cloud.org/authz claim must be present")

				authz := userinfo.HttpsunikornCloudOrgauthz
				Expect(authz.Acctype).To(BeElementOf(
					identityopenapi.Service,
					identityopenapi.System,
					identityopenapi.User,
				), "acctype must be one of: service, system, user")

				GinkgoWriter.Printf("acctype: %s\n", authz.Acctype)
			})

			It("should include a non-empty orgIds list in the custom authz claims", func() {
				userinfo, err := client.GetUserinfo(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(userinfo.HttpsunikornCloudOrgauthz).NotTo(BeNil())
				Expect(userinfo.HttpsunikornCloudOrgauthz.OrgIds).NotTo(BeEmpty(),
					"orgIds must contain at least one organisation ID")

				GinkgoWriter.Printf("orgIds count: %d\n",
					len(userinfo.HttpsunikornCloudOrgauthz.OrgIds))
			})

			It("should return orgIds that are consistent with the organizations list", func() {
				userinfo, err := client.GetUserinfo(ctx)

				Expect(err).NotTo(HaveOccurred())
				Expect(userinfo.HttpsunikornCloudOrgauthz).NotTo(BeNil())

				orgs, err := client.ListOrganizations(ctx)
				Expect(err).NotTo(HaveOccurred())

				var orgIDs []string
				for _, org := range orgs {
					orgIDs = append(orgIDs, org.Metadata.Id)
				}

				expectedOrgIDs := make([]interface{}, 0, len(orgIDs))
				for _, orgID := range orgIDs {
					expectedOrgIDs = append(expectedOrgIDs, orgID)
				}

				Expect(userinfo.HttpsunikornCloudOrgauthz.OrgIds).To(ConsistOf(expectedOrgIDs...),
					"orgIds in authz claims must exactly match the organizations list")

				GinkgoWriter.Printf("orgIds from claims: %v match organizations list\n",
					userinfo.HttpsunikornCloudOrgauthz.OrgIds)
			})
		})

		Describe("Given no authentication", func() {
			It("should reject the request", func() {
				unauthClient := coreclient.NewAPIClient(config.BaseURL, "", config.RequestTimeout, &api.GinkgoLogger{})
				_, _, err := unauthClient.DoRequest(ctx, http.MethodGet, api.NewEndpoints().GetUserinfo(), nil, http.StatusOK)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, coreclient.ErrUnexpectedStatusCode)).To(BeTrue(),
					"Unauthenticated userinfo request must be rejected")

				GinkgoWriter.Printf("Unauthenticated userinfo rejected: %v\n", err)
			})
		})

		Context("When authenticated as a user", func() {
			BeforeEach(func() {
				Expect(userClient).NotTo(BeNil(), "USER_AUTH_TOKEN must be set by integration fixtures")
				Expect(config.UserSubjectEmail).NotTo(BeEmpty(),
					"TEST_USER_SUBJECT_EMAIL must be set by integration fixtures")
				Expect(config.UnauthorisedOrgID).NotTo(BeEmpty(),
					"UNAUTHORISED_ORG_ID must be set by integration fixtures")
			})

			It("should report acctype 'user' in the authz claims", func() {
				userinfo, err := userClient.GetUserinfo(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(userinfo.HttpsunikornCloudOrgauthz).NotTo(BeNil())
				Expect(userinfo.HttpsunikornCloudOrgauthz.Acctype).To(Equal(identityopenapi.User))
				Expect(userinfo.HttpsunikornCloudOrgauthz.OrgIds).To(ContainElement(config.OrgID))

				Expect(userinfo.HttpsunikornCloudOrgauthz.OrgIds).NotTo(ContainElement(config.UnauthorisedOrgID),
					"user authz claims must not include organizations the user is not a member of")
				Expect(userinfo.Sub).To(Equal(config.UserSubjectEmail))
				Expect(userinfo.Email).NotTo(BeNil())
				Expect(*userinfo.Email).To(Equal(config.UserSubjectEmail))

				GinkgoWriter.Printf("User acctype: %s\n", userinfo.HttpsunikornCloudOrgauthz.Acctype)
			})
		})

		Context("When authenticated as a service account", func() {
			BeforeEach(func() {
				Expect(serviceAccountClient).NotTo(BeNil(),
					"SERVICE_ACCOUNT_TOKEN must be set by integration fixtures")
			})
			It("should report acctype 'service' in the authz claims", func() {
				userinfo, err := serviceAccountClient.GetUserinfo(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(userinfo.HttpsunikornCloudOrgauthz).NotTo(BeNil())
				Expect(userinfo.HttpsunikornCloudOrgauthz.Acctype).To(Equal(identityopenapi.Service))
				GinkgoWriter.Printf("Service account acctype: %s\n", userinfo.HttpsunikornCloudOrgauthz.Acctype)
			})
		})
	})
})
