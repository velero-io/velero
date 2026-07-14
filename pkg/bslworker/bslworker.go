/*
Copyright the Velero contributors.

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

// Package bslworker implements per-BackupStorageLocation object-store worker pods.
//
// When a BackupStorageLocation sets Spec.Worker, Velero runs that location's
// object-store plugin in a dedicated worker pod under a distinct identity (for
// example, an Azure AD Workload Identity, AWS IRSA role, or GCP Workload Identity
// bound to a tenant ServiceAccount) instead of in the central Velero server
// process. The central Velero controllers reach that plugin through a network mTLS
// gRPC connection, reusing the existing ObjectStore plugin protocol, so every
// higher-level BackupStore operation transparently runs under the worker's identity.
package bslworker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

const (
	// WorkerObjectStorePluginName is the transport-level multiplexing key shared by
	// the central client and the worker server for the ObjectStore gRPC service. The
	// worker serves exactly one object store (the BSL's provider) registered under
	// this name, and the central client sends it as the plugin key on every request.
	WorkerObjectStorePluginName = "velero.io/bsl-worker"

	// WorkerGRPCPort is the TCP port the worker's ObjectStore gRPC server listens on
	// and that the central client and worker Service target.
	WorkerGRPCPort = 9443

	// WorkerContainerName is the name of the object-store server container in the
	// worker pod.
	WorkerContainerName = "object-store-server"

	// WorkerTLSMountPath is where the worker's TLS Secret (CA + server cert/key) is
	// mounted inside the worker pod.
	WorkerTLSMountPath = "/etc/velero/bsl-worker-tls"

	// WorkerSelectorLabel identifies the pods/Service belonging to a BSL worker; its
	// value is the worker resource name.
	WorkerSelectorLabel = "velero.io/bsl-worker"

	// resourceNamePrefix prefixes all Kubernetes resources created for a worker.
	resourceNamePrefix = "velero-bsl-worker-"

	// dns1123LabelMaxLength is the maximum length of a DNS-1123 label, which bounds
	// Service names (and, to stay safe for generated pod names, other resources too).
	dns1123LabelMaxLength = 63
)

// workerName builds a deterministic, DNS-1123-label-safe (<=63 char) name for a
// worker resource derived from the BSL name plus an optional suffix. Because BSL
// names are DNS-1123 *subdomains* (which may contain dots and uppercase) while
// Service/Deployment names must be DNS-1123 *labels*, the BSL name is sanitized to
// the label alphabet. Whenever sanitization changes the name (or the name is too
// long) a short hash of the original BSL name is appended so distinct BSLs that
// sanitize/truncate to the same base still get distinct, collision-resistant names.
func workerName(bslName, suffix string) string {
	sanitized, changed := sanitizeDNS1123Label(bslName)
	name := resourceNamePrefix + sanitized + suffix
	if !changed && len(name) <= dns1123LabelMaxLength {
		return name
	}

	h := sha256.Sum256([]byte(bslName))
	hash := hex.EncodeToString(h[:])[:8]

	keep := dns1123LabelMaxLength - len(resourceNamePrefix) - len(suffix) - 1 - len(hash)
	if keep < 0 {
		keep = 0
	}
	if keep > len(sanitized) {
		keep = len(sanitized)
	}
	base := strings.TrimRight(sanitized[:keep], "-")
	if base == "" {
		// resourceNamePrefix already ends in '-', so the hash follows directly.
		return resourceNamePrefix + hash + suffix
	}
	return resourceNamePrefix + base + "-" + hash + suffix
}

// sanitizeDNS1123Label lowercases the input and replaces every character outside the
// DNS-1123 label alphabet ([a-z0-9-]) with '-', then trims leading/trailing '-'. It
// reports whether the result differs from the input, which callers use to decide
// whether hash disambiguation is required.
func sanitizeDNS1123Label(in string) (string, bool) {
	var b strings.Builder
	b.Grow(len(in))
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r - 'A' + 'a')
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	return out, out != in
}

// WorkerDeploymentName returns the name of the Deployment running the worker for the
// given BackupStorageLocation.
func WorkerDeploymentName(bslName string) string {
	return workerName(bslName, "")
}

// WorkerServiceName returns the name of the Service fronting the worker for the given
// BackupStorageLocation. It is also the DNS name embedded in the worker's server
// certificate SAN.
func WorkerServiceName(bslName string) string {
	return workerName(bslName, "")
}

// WorkerTLSSecretName returns the name of the Secret holding the worker's TLS
// materials (CA, server cert/key, client cert/key) for the given BSL.
func WorkerTLSSecretName(bslName string) string {
	return workerName(bslName, "-tls")
}

// WorkerServiceDNS returns the in-cluster DNS name of the worker Service. This is the
// name the worker's server certificate must be issued for (SAN).
func WorkerServiceDNS(bslName, namespace string) string {
	return fmt.Sprintf("%s.%s.svc", WorkerServiceName(bslName), namespace)
}

// WorkerEndpoint returns the host:port the central client dials to reach the worker.
func WorkerEndpoint(bslName, namespace string) string {
	return fmt.Sprintf("%s:%d", WorkerServiceDNS(bslName, namespace), WorkerGRPCPort)
}

// WorkerSelectorLabels returns the labels identifying a worker's pods and Service.
func WorkerSelectorLabels(bslName string) map[string]string {
	return map[string]string{WorkerSelectorLabel: WorkerServiceName(bslName)}
}

// WorkerNamespace resolves the namespace a worker runs in: the BSL's requested worker
// namespace, or veleroNamespace when unset.
func WorkerNamespace(worker *velerov1api.BackupStorageLocationWorker, veleroNamespace string) string {
	if worker != nil && worker.Namespace != "" {
		return worker.Namespace
	}
	return veleroNamespace
}
