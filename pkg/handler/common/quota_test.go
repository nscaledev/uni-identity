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

//nolint:revive,paralleltest // Dot imports and serial suite entry points are standard for Ginkgo.
package common_test

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/ids"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"
)

const (
	quotaChartValuesPath    = "../../../charts/identity/values.yaml"
	quotaTestOrganizationID = "00000000-0000-4000-8000-000000000001"
)

type chartQuota struct {
	Default any    `json:"default"`
	Kind    string `json:"kind"`
}

type quotaChartValues struct {
	Quotas map[string]chartQuota `json:"quotas"`
}

func TestQuotaMetadata(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Quota Metadata Suite")
}

func newQuotaMetadata(name, displayName, description string, defaultQuantity int64) *unikornv1.QuotaMetadata {
	return &unikornv1.QuotaMetadata{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "identity",
		},
		Spec: unikornv1.QuotaMetadataSpec{
			DisplayName: displayName,
			Description: description,
			Default:     resource.NewQuantity(defaultQuantity, resource.DecimalSI),
		},
	}
}

func newQuotaMetadataClient(metadata ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	Expect(unikornv1.AddToScheme(scheme)).To(Succeed())

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(metadata...).
		Build()
}

func loadQuotaChartValues() quotaChartValues {
	raw, err := os.ReadFile(filepath.Clean(quotaChartValuesPath))
	Expect(err).NotTo(HaveOccurred())

	var values quotaChartValues

	Expect(yaml.Unmarshal(raw, &values)).To(Succeed())
	Expect(values.Quotas).NotTo(BeEmpty())

	return values
}

var _ = Describe("Quota metadata", func() {
	Context("When resolving the default organization quota", func() {
		Describe("Given the compact lowercase block storage kind", func() {
			It("uses the public kind in the quota contract", func(ctx SpecContext) {
				metadata := newQuotaMetadata(
					"volumegib",
					"Volume Capacity",
					"Total requested block storage capacity in GiB.",
					0,
				)
				metadata.Annotations = map[string]string{
					"identity.unikorn-cloud.org/quota-kind": "volumeGiB",
				}
				client := newQuotaMetadataClient(metadata)

				quota, virtual, err := common.New(client).GetQuota(ctx, ids.MustParseOrganizationID(quotaTestOrganizationID))

				Expect(err).NotTo(HaveOccurred())
				Expect(virtual).To(BeTrue())
				Expect(quota.Spec.Quotas).To(HaveLen(1))
				Expect(quota.Spec.Quotas[0].Kind).To(Equal("volumeGiB"))
				Expect(quota.Spec.Quotas[0].Quantity.Value()).To(BeZero())
			})
		})

		Describe("Given an existing custom volume-gib quota kind", func() {
			It("preserves the existing quota contract", func(ctx SpecContext) {
				metadata := newQuotaMetadata("volume-gib", "Custom Volume Capacity", "Custom quota.", 500)
				client := newQuotaMetadataClient(metadata)

				quota, virtual, err := common.New(client).GetQuota(ctx, ids.MustParseOrganizationID(quotaTestOrganizationID))

				Expect(err).NotTo(HaveOccurred())
				Expect(virtual).To(BeTrue())
				Expect(quota.Spec.Quotas).To(HaveLen(1))
				Expect(quota.Spec.Quotas[0].Kind).To(Equal("volume-gib"))
				Expect(quota.Spec.Quotas[0].Quantity.Value()).To(Equal(int64(500)))
			})
		})

		Describe("Given an existing custom volumegib quota kind", func() {
			It("preserves the existing quota contract", func(ctx SpecContext) {
				metadata := newQuotaMetadata("volumegib", "Custom Volume Capacity", "Custom quota.", 500)
				client := newQuotaMetadataClient(metadata)

				quota, virtual, err := common.New(client).GetQuota(ctx, ids.MustParseOrganizationID(quotaTestOrganizationID))

				Expect(err).NotTo(HaveOccurred())
				Expect(virtual).To(BeTrue())
				Expect(quota.Spec.Quotas).To(HaveLen(1))
				Expect(quota.Spec.Quotas[0].Kind).To(Equal("volumegib"))
				Expect(quota.Spec.Quotas[0].Quantity.Value()).To(Equal(int64(500)))
			})
		})

		Describe("Given stored custom volumegib quota state when the built-in marker appears", func() {
			It("fails closed instead of replacing the existing limit", func(ctx SpecContext) {
				metadata := newQuotaMetadata("volumegib", "Volume Capacity", "Block storage capacity.", 0)
				metadata.Annotations = map[string]string{
					"identity.unikorn-cloud.org/quota-kind": "volumeGiB",
				}
				stored := &unikornv1.Quota{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "organization-quota",
						Namespace: "organization",
						Labels: map[string]string{
							constants.OrganizationLabel: quotaTestOrganizationID,
						},
					},
					Spec: unikornv1.QuotaSpec{
						Quotas: []unikornv1.ResourceQuota{
							{
								Kind:     "volumegib",
								Quantity: resource.NewQuantity(500, resource.DecimalSI),
							},
						},
					},
				}
				client := newQuotaMetadataClient(metadata, stored)

				quota, virtual, err := common.New(client).GetQuota(ctx, ids.MustParseOrganizationID(quotaTestOrganizationID))

				Expect(err).To(MatchError(ContainSubstring(`existing quota kind "volumegib" conflicts with built-in "volumeGiB"`)))
				Expect(quota).To(BeNil())
				Expect(virtual).To(BeFalse())
			})
		})

		Describe("Given legacy allocation state without a matching capacity", func() {
			It("fails closed instead of ignoring the allocation", func(ctx SpecContext) {
				metadata := newQuotaMetadata("volumegib", "Volume Capacity", "Block storage capacity.", 0)
				metadata.Annotations = map[string]string{
					"identity.unikorn-cloud.org/quota-kind": "volumeGiB",
				}
				allocation := &unikornv1.Allocation{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "legacy-volume",
						Namespace: "organization",
						Labels: map[string]string{
							constants.OrganizationLabel: quotaTestOrganizationID,
						},
					},
					Spec: unikornv1.AllocationSpec{
						Allocations: []unikornv1.ResourceAllocation{
							{
								Kind:      "volumegib",
								Committed: resource.NewQuantity(1, resource.DecimalSI),
								Reserved:  resource.NewQuantity(0, resource.DecimalSI),
							},
						},
					},
				}
				client := newQuotaMetadataClient(metadata, allocation)

				err := common.New(client).CheckQuotaConsistency(
					ctx,
					ids.MustParseOrganizationID(quotaTestOrganizationID),
					nil,
					nil,
				)

				Expect(err).To(MatchError(ContainSubstring(`allocation kind "volumegib" has no matching quota`)))
			})
		})

		Describe("Given an unrelated retired custom allocation kind", func() {
			It("preserves the existing quota consistency behavior", func(ctx SpecContext) {
				metadata := newQuotaMetadata("volumegib", "Volume Capacity", "Block storage capacity.", 0)
				metadata.Annotations = map[string]string{
					"identity.unikorn-cloud.org/quota-kind": "volumeGiB",
				}
				allocation := &unikornv1.Allocation{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "retired-custom-resource",
						Namespace: "organization",
						Labels: map[string]string{
							constants.OrganizationLabel: quotaTestOrganizationID,
						},
					},
					Spec: unikornv1.AllocationSpec{
						Allocations: []unikornv1.ResourceAllocation{
							{
								Kind:      "retired-custom",
								Committed: resource.NewQuantity(1, resource.DecimalSI),
								Reserved:  resource.NewQuantity(0, resource.DecimalSI),
							},
						},
					},
				}
				client := newQuotaMetadataClient(metadata, allocation)

				err := common.New(client).CheckQuotaConsistency(
					ctx,
					ids.MustParseOrganizationID(quotaTestOrganizationID),
					nil,
					nil,
				)

				Expect(err).NotTo(HaveOccurred())
			})
		})

	})

	Context("When loading the built-in quota catalogue", func() {
		Describe("Given block storage quota defaults", func() {
			It("registers only capacity with a zero default", func() {
				values := loadQuotaChartValues()
				capacity, ok := values.Quotas["volumegib"]

				Expect(ok).To(BeTrue())
				Expect(capacity.Default).To(BeNumerically("==", 0))
				Expect(capacity.Kind).To(Equal("volumeGiB"))
				Expect(values.Quotas).NotTo(HaveKey("volumes"))
			})
		})
	})
})
