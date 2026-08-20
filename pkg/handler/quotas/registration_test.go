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

//nolint:revive // dot imports are the standard Ginkgo DSL
package quotas_test

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"sigs.k8s.io/yaml"
)

const chartValuesPath = "../../../charts/identity/values.yaml"

type chartValues struct {
	Quotas map[string]unikornv1.QuotaMetadataSpec `json:"quotas"`
}

func TestQuotaRegistration(t *testing.T) {
	t.Parallel()

	RegisterFailHandler(Fail)
	RunSpecs(t, "Quota Registration Suite")
}

var _ = Describe("Built-in quota registration", func() {
	Context("When loading the Identity chart defaults", func() {
		Describe("Given block storage Volume capacity", func() {
			It("registers the volume quota with a zero default and binary format", func() {
				raw, err := os.ReadFile(filepath.Clean(chartValuesPath))
				Expect(err).NotTo(HaveOccurred())

				var values chartValues
				Expect(yaml.Unmarshal(raw, &values)).To(Succeed())

				metadata, ok := values.Quotas["volume"]
				Expect(ok).To(BeTrue())
				Expect(metadata.DisplayName).NotTo(BeEmpty())
				Expect(metadata.Description).To(ContainSubstring("GiB"))
				Expect(metadata.Default).NotTo(BeNil())
				Expect(metadata.Default.Value()).To(BeZero())
				Expect(metadata.Format).To(Equal(unikornv1.Binary))
			})
		})
	})
})
