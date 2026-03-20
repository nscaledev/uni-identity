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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"text/template"
	"time"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/util/retry"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// metalLBVersion is the version of the load balancer controller to install.
	metalLBVersion = "v0.13.5"

	// metalLBManifest describes where to get the installer manifest from.
	metalLBManifest = "https://raw.githubusercontent.com/metallb/metallb/" + metalLBVersion + "/config/manifests/metallb-native.yaml"

	metalLBNamespace = "metallb-system"

	metalLBAddressPoolTemplate = `apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: example
  namespace: metallb-system
spec:
  addresses:
  - {{.start}}-{{.end}}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
`
)

var (
	ErrConditionFormat  = errors.New("status condition incorrectly formatted")
	ErrConditionMissing = errors.New("status condition not found")
	ErrConditionStatus  = errors.New("status condition incorrect status")
	ErrDaemonSetUnready = errors.New("daemonset readiness doesn't match desired")
)

func waitCondition(ctx context.Context, client dynamic.Interface, group, version, resource, namespace, name, conditionType string) {
	gvr := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}

	callback := func() error {
		object, err := client.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		conditions, _, err := unstructured.NestedSlice(object.Object, "status", "conditions")
		if err != nil {
			return fmt.Errorf("%w: conditions lookup error: %s", ErrConditionFormat, err.Error())
		}

		for i := range conditions {
			condition, ok := conditions[i].(map[string]any)
			if !ok {
				return fmt.Errorf("%w: condition type assertion error", ErrConditionFormat)
			}

			t, _, err := unstructured.NestedString(condition, "type")
			if err != nil {
				return fmt.Errorf("%w: condition type error: %s", ErrConditionFormat, err.Error())
			}

			if t != conditionType {
				continue
			}

			s, _, err := unstructured.NestedString(condition, "status")
			if err != nil {
				return fmt.Errorf("%w: condition status error: %s", ErrConditionFormat, err.Error())
			}

			if s != "True" {
				return ErrConditionStatus
			}

			return nil
		}

		return ErrConditionMissing
	}

	if err := retry.Forever().DoWithContext(ctx, callback); err != nil {
		panic(err)
	}
}

func waitDaemonSetReady(ctx context.Context, client kubernetes.Interface, namespace, name string) {
	callback := func() error {
		daemonset, err := client.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("daemonset get error: %w", err)
		}

		if daemonset.Status.NumberReady != daemonset.Status.DesiredNumberScheduled {
			return fmt.Errorf("%w: status mismatch", ErrDaemonSetUnready)
		}

		return nil
	}

	if err := retry.Forever().DoWithContext(ctx, callback); err != nil {
		panic(err)
	}
}

func kubectlApply(kubeConfigPath, contextName, path string) error {
	args := []string{}

	if kubeConfigPath != "" {
		args = append(args, "--kubeconfig", kubeConfigPath)
	}

	if contextName != "" {
		args = append(args, "--context", contextName)
	}

	args = append(args, "apply", "-f", path)

	cmd := exec.Command("kubectl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

func applyManifest(kubeConfigPath, contextName, path string) {
	if err := kubectlApply(kubeConfigPath, contextName, path); err != nil {
		panic(err)
	}
}

func getKindNetworkName(clusterName string) string {
	controlPlane := fmt.Sprintf("%s-control-plane", clusterName)

	out, err := exec.Command("docker", "inspect", controlPlane).Output()
	if err != nil {
		panic(err)
	}

	var containers []struct {
		NetworkSettings struct {
			Networks map[string]any
		}
	}

	if err := json.Unmarshal(out, &containers); err != nil { //nolint:musttag
		panic(err)
	}

	if len(containers) != 1 {
		panic("wrong container inspect length")
	}

	networks := containers[0].NetworkSettings.Networks
	if len(networks) == 0 {
		panic("kind control-plane container has no attached networks")
	}

	if _, ok := networks["kind"]; ok {
		return "kind"
	}

	if len(networks) == 1 {
		for name := range networks {
			return name
		}
	}

	panic("unable to determine kind network name")
}

func getDockerNetwork(clusterName string) *net.IPNet {
	networkName := getKindNetworkName(clusterName)

	out, err := exec.Command("docker", "network", "inspect", networkName).Output()
	if err != nil {
		panic(err)
	}

	var dockerNetConfigs []map[string]any
	if err := json.Unmarshal(out, &dockerNetConfigs); err != nil {
		panic(err)
	}

	if len(dockerNetConfigs) != 1 {
		panic("wrong net config length")
	}

	ipamConfigs, _, err := unstructured.NestedSlice(dockerNetConfigs[0], "IPAM", "Config")
	if err != nil {
		panic(err)
	}

	for i := range ipamConfigs {
		ipamConfig, ok := ipamConfigs[i].(map[string]any)
		if !ok {
			panic("config format fail")
		}

		prefix, _, err := unstructured.NestedString(ipamConfig, "Subnet")
		if err != nil {
			panic("subnet fail")
		}

		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			panic(err)
		}

		if network.IP.To4() != nil {
			return network
		}
	}

	panic("no IPv4 subnet found")
}

func ipv4ToUint(ip net.IP) uint {
	v4 := ip.To4()
	return uint(v4[0])<<24 | uint(v4[1])<<16 | uint(v4[2])<<8 | uint(v4[3])
}

func uintToIPv4(ip uint) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func getVIPRange(network *net.IPNet, rangeStart, rangeEnd uint) (net.IP, net.IP) { //nolint:unparam
	if rangeEnd < rangeStart {
		panic("invalid range: end before start")
	}

	base := ipv4ToUint(network.IP)
	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	count := rangeEnd - rangeStart + 1

	if hostBits >= 8 {
		offset := ((1 << hostBits) - 1) & ^uint(0xff)
		prefix := base + offset
		start := prefix + rangeStart
		end := prefix + rangeEnd

		if network.Contains(uintToIPv4(start)) && network.Contains(uintToIPv4(end)) {
			return uintToIPv4(start), uintToIPv4(end)
		}
	}

	if hostBits < 2 {
		panic("subnet too small for any usable VIPs")
	}

	usableStart := base + 1
	usableEnd := base + (1 << hostBits) - 2

	if usableEnd < usableStart {
		panic("subnet has no usable VIPs")
	}

	usableCount := usableEnd - usableStart + 1
	if usableCount < count {
		panic("subnet too small for requested VIP range")
	}

	start := usableEnd - count + 1

	return uintToIPv4(start), uintToIPv4(usableEnd)
}

func applyMetalLBAddressPools(kubeConfigPath, contextName string, start, end net.IP) {
	tmpl := template.New("metallb")
	if _, err := tmpl.Parse(metalLBAddressPoolTemplate); err != nil {
		panic(err)
	}

	tf, err := os.CreateTemp("", "metallb-*.yaml")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tf.Name())

	ctx := map[string]string{
		"start": start.String(),
		"end":   end.String(),
	}

	if err := tmpl.Execute(tf, ctx); err != nil {
		panic(err)
	}

	if err := tf.Close(); err != nil {
		panic(err)
	}

	applyManifest(kubeConfigPath, contextName, tf.Name())
}

func main() {
	var clusterName string

	var kubeConfigPath string

	var contextName string

	var timeout time.Duration

	pflag.StringVar(&clusterName, "cluster-name", "kind", "Kind cluster name to probe.")
	pflag.StringVar(&kubeConfigPath, "kubeconfig", "", "Path to the kubeconfig file.")
	pflag.StringVar(&contextName, "context", "", "Kubernetes context to use.")
	pflag.DurationVar(&timeout, "timeout", 5*time.Minute, "Global timeout to complete installation.")
	pflag.Parse()

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeConfigPath != "" {
		loadingRules.ExplicitPath = kubeConfigPath
	}

	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, overrides)

	config, err := clientConfig.ClientConfig()
	if err != nil {
		panic(err)
	}

	kubernetesClient := kubernetes.NewForConfigOrDie(config)
	dynamicClient := dynamic.NewForConfigOrDie(config)

	c, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	fmt.Println("==> Applying MetalLB manifest...")
	applyManifest(kubeConfigPath, contextName, metalLBManifest)

	fmt.Println("==> Waiting for MetalLB controller to be ready...")
	waitCondition(c, dynamicClient, "apps", "v1", "deployments", metalLBNamespace, "controller", "Available")

	fmt.Println("==> Waiting for MetalLB daemonset to be ready...")
	waitDaemonSetReady(c, kubernetesClient, metalLBNamespace, "speaker")

	network := getDockerNetwork(clusterName)
	fmt.Println("==> Using routable prefix", network)

	start, end := getVIPRange(network, 200, 250)
	fmt.Println("==> Using address range", start, "-", end)

	fmt.Println("==> Applying MetalLB network configuration...")
	applyMetalLBAddressPools(kubeConfigPath, contextName, start, end)
}
