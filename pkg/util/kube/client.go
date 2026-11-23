/*
Copyright The Velero Contributors.

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

package kube

import (
	"context"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	veleroPkgClient "github.com/velero-io/velero/pkg/client"
)

func PatchResource(original, updated client.Object, kbClient client.Client) error {
	err := kbClient.Patch(context.Background(), updated, client.MergeFrom(original))

	return err
}

// PatchResourceWithRetries patches the original resource with the updated resource, retrying when the provided retriable function returns true.
func PatchResourceWithRetries(maxDuration time.Duration, original, updated client.Object, kbClient client.Client, retriable func(error) bool) error {
	return veleroPkgClient.RetryOnRetriableMaxBackOff(maxDuration, func() error { return PatchResource(original, updated, kbClient) }, retriable)
}

// PatchResourceWithRetriesOnErrors patches the original resource with the updated resource, retrying when the operation returns an error.
func PatchResourceWithRetriesOnErrors(maxDuration time.Duration, original, updated client.Object, kbClient client.Client) error {
	return PatchResourceWithRetries(maxDuration, original, updated, kbClient, func(err error) bool {
		// retry using DefaultBackoff to resolve connection refused error that may occur when the server is under heavy load
		// TODO: consider using a more specific error type to retry, for now, we retry on all errors
		// specific errors:
		// - connection refused: https://pkg.go.dev/syscall#:~:text=Errno(0x67)-,ECONNREFUSED,-%3D%20Errno(0x6f
		return err != nil
	})
}
