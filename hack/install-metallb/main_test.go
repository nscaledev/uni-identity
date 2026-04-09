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

package main

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr %q: %v", cidr, err)
	}

	return network
}

func TestGetVIPRangeLargeSubnet(t *testing.T) {
	t.Parallel()

	start, end := getVIPRange(mustCIDR(t, "172.18.0.0/16"), 200, 250)

	if got, want := start.String(), "172.18.255.200"; got != want {
		t.Fatalf("start = %s, want %s", got, want)
	}

	if got, want := end.String(), "172.18.255.250"; got != want {
		t.Fatalf("end = %s, want %s", got, want)
	}
}

func TestGetVIPRangeSmallSubnetFallsBackInsideSubnet(t *testing.T) {
	t.Parallel()

	start, end := getVIPRange(mustCIDR(t, "172.18.0.0/25"), 200, 250)

	if got, want := start.String(), "172.18.0.76"; got != want {
		t.Fatalf("start = %s, want %s", got, want)
	}

	if got, want := end.String(), "172.18.0.126"; got != want {
		t.Fatalf("end = %s, want %s", got, want)
	}
}

func TestGetVIPRangePanicsWhenSubnetTooSmall(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for undersized subnet")
		}
	}()

	getVIPRange(mustCIDR(t, "172.18.0.0/30"), 200, 250)
}
