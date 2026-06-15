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

package restore

import (
	"encoding/json"

	"github.com/cockroachdb/errors"
	jsonpatch "github.com/evanphx/json-patch/v5"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// mergeServiceAccount takes a backed up serviceaccount and merges attributes into the current in-cluster service account.
// Labels and Annotations on the backed up version but not on the in-cluster version will be merged. If a key is specified in both, the in-cluster version is retained.
func mergeServiceAccounts(fromCluster, fromBackup *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	desired := new(corev1api.ServiceAccount)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(fromCluster.UnstructuredContent(), desired); err != nil {
		return nil, errors.Wrap(err, "unable to convert from-cluster service account from unstructured to serviceaccount")
	}

	backupSA := new(corev1api.ServiceAccount)
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(fromBackup.UnstructuredContent(), backupSA); err != nil {
		return nil, errors.Wrap(err, "unable to convert from backed up service account unstructured to serviceaccount")
	}

	desired.Secrets = mergeObjectReferenceSlices(desired.Secrets, backupSA.Secrets)

	desired.ImagePullSecrets = mergeLocalObjectReferenceSlices(desired.ImagePullSecrets, backupSA.ImagePullSecrets)

	desired.Labels = mergeMaps(desired.Labels, backupSA.Labels)

	desired.Annotations = mergeMaps(desired.Annotations, backupSA.Annotations)

	desiredUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(desired)
	if err != nil {
		return nil, errors.Wrap(err, "unable to convert desired service account to unstructured")
	}
	// The DefaultUnstructuredConverter.ToUnstructured function will populate the creation timestamp with the nil value
	// However, we remove this on both the backup and cluster objects before comparison, and we don't want it in any patches.
	delete(desiredUnstructured["metadata"].(map[string]any), "creationTimestamp")

	return &unstructured.Unstructured{Object: desiredUnstructured}, nil
}

func mergeObjectReferenceSlices(first, second []corev1api.ObjectReference) []corev1api.ObjectReference {
	for _, s := range second {
		var exists bool
		for _, f := range first {
			if s.Name == f.Name {
				exists = true
				break
			}
		}
		if !exists {
			first = append(first, s)
		}
	}

	return first
}

func mergeLocalObjectReferenceSlices(first, second []corev1api.LocalObjectReference) []corev1api.LocalObjectReference {
	for _, s := range second {
		var exists bool
		for _, f := range first {
			if s.Name == f.Name {
				exists = true
				break
			}
		}
		if !exists {
			first = append(first, s)
		}
	}

	return first
}

// mergeMaps takes two map[string]string and merges missing keys from the second into the first.
// If a key already exists, its value is not overwritten.
func mergeMaps(first, second map[string]string) map[string]string {
	// If the first map passed in is empty, just use all of the second map's data
	if first == nil {
		first = map[string]string{}
	}

	for k, v := range second {
		_, ok := first[k]
		if !ok {
			first[k] = v
		}
	}

	return first
}

// generatePatch will calculate a JSON merge patch for an object's desired state.
// If the passed in objects are already equal, nil is returned.
func generatePatch(fromCluster, desired *unstructured.Unstructured) ([]byte, error) {
	// If the objects are already equal, there's no need to generate a patch.
	if equality.Semantic.DeepEqual(fromCluster, desired) {
		return nil, nil
	}

	desiredBytes, err := json.Marshal(desired.Object)
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal desired object")
	}

	fromClusterBytes, err := json.Marshal(fromCluster.Object)
	if err != nil {
		return nil, errors.Wrap(err, "unable to marshal in-cluster object")
	}

	patchBytes, err := jsonpatch.CreateMergePatch(fromClusterBytes, desiredBytes)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create merge patch")
	}

	return patchBytes, nil
}
