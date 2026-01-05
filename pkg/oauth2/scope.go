/*
Copyright 2024-2025 the Unikorn Authors.
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

package oauth2

import (
	"encoding/json"
	"strings"
)

// Scope defines a list of scopes.
type Scope []string

// Ensure the correct interfaces are implemented.
var _ json.Marshaler = &Scope{}
var _ json.Unmarshaler = &Scope{}

// NewScope creates a new scopes object.
func NewScope(s string) Scope {
	return strings.Split(s, " ")
}

// MarshalJSON implements json.Marshaller.
func (l *Scope) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(strings.Join(*l, " "))
	if err != nil {
		return nil, err
	}

	return data, nil
}

// UnmarshalJSON implments json.Unmarshaller.
func (l *Scope) UnmarshalJSON(value []byte) error {
	var list string

	if err := json.Unmarshal(value, &list); err != nil {
		return err
	}

	*l = strings.Split(list, " ")

	return nil
}
