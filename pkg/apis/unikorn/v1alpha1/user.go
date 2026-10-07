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

package v1alpha1

import (
	"github.com/google/uuid"

	"github.com/unikorn-cloud/core/pkg/util"
)

const (
	globalUserIDNamespace = "b11bc9c8-5ac7-4554-9911-99725c71e24c"
	UserSubjectIDLabel    = "unikorn-cloud.org/user-subject-id"
)

// GlobalUserNamespace identifies deterministic global User names.
func GlobalUserNamespace() uuid.UUID {
	return uuid.MustParse(globalUserIDNamespace)
}

// GlobalUserName returns the stored name for a user subject.
func GlobalUserName(subject string) string {
	return util.GenerateDeterministicResourceID(GlobalUserNamespace(), subject)
}
