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

package k8s

import (
	"context"
	"fmt"

	"github.com/cockroachdb/errors"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

func CreatePersistentVolume(client TestClient, name string) (*corev1api.PersistentVolume, error) {
	p := &corev1api.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: corev1api.PersistentVolumeSpec{
			StorageClassName: "manual",
			AccessModes:      []corev1api.PersistentVolumeAccessMode{corev1api.ReadWriteOnce},
			Capacity:         corev1api.ResourceList{corev1api.ResourceStorage: resource.MustParse("2Gi")},

			PersistentVolumeSource: corev1api.PersistentVolumeSource{
				HostPath: &corev1api.HostPathVolumeSource{
					Path: "/demo",
				},
			},
		},
	}

	return client.ClientGo.CoreV1().PersistentVolumes().Create(context.TODO(), p, metav1.CreateOptions{})
}

func GetPersistentVolume(ctx context.Context, client TestClient, namespace string, persistentVolume string) (*corev1api.PersistentVolume, error) {
	return client.ClientGo.CoreV1().PersistentVolumes().Get(ctx, persistentVolume, metav1.GetOptions{})
}

func AddAnnotationToPersistentVolume(ctx context.Context, client TestClient, namespace string, persistentVolume, key string) (*corev1api.PersistentVolume, error) {
	newPV, err := GetPersistentVolume(ctx, client, "", persistentVolume)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Fail to ge PV %s", persistentVolume))
	}
	ann := newPV.ObjectMeta.Annotations
	ann[key] = persistentVolume
	newPV.Annotations = ann

	return client.ClientGo.CoreV1().PersistentVolumes().Update(ctx, newPV, metav1.UpdateOptions{})
}

func ClearClaimRefForFailedPVs(ctx context.Context, client TestClient) error {
	pvList, err := client.ClientGo.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list PVs: %v", err)
	}

	for _, pv := range pvList.Items {
		pvName := pv.Name

		if pv.Status.Phase != corev1api.VolumeAvailable {
			retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				pv, getErr := client.ClientGo.CoreV1().PersistentVolumes().Get(ctx, pvName, metav1.GetOptions{})
				if getErr != nil {
					return fmt.Errorf("failed to get PV %s: %v", pvName, getErr)
				}
				pv.Spec.ClaimRef = nil
				_, updateErr := client.ClientGo.CoreV1().PersistentVolumes().Update(ctx, pv, metav1.UpdateOptions{})
				return updateErr
			})
			if retryErr != nil {
				return fmt.Errorf("failed to clear claimRef for PV %s: %v", pvName, retryErr)
			}
		}
	}

	return nil
}

func GetAllPVNames(ctx context.Context, client TestClient) ([]string, error) {
	var pvNameList []string
	pvList, err := client.ClientGo.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to List PV")
	}

	for _, pvName := range pvList.Items {
		pvNameList = append(pvNameList, pvName.Name)
	}
	return pvNameList, nil
}
