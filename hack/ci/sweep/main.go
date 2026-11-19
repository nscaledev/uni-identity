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

// sweep deletes the test objects that earlier API test runs left in the test organization of a
// deployed environment. It reads the same configuration as the suite.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/unikorn-cloud/identity/test/api"
)

func main() {
	config, err := api.LoadTestConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := api.Sweep(context.Background(), api.NewAPIClientWithConfig(config), config, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
