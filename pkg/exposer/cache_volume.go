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

package exposer

import (
	"context"

	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/velero-io/velero/pkg/util/boolptr"
	"github.com/velero-io/velero/pkg/util/kube"
)

type CacheConfigs struct {
	Limit             int64
	StorageClass      string
	ResidentThreshold int64
}

const (
	cacheVolumeName      = "cachedir"
	cacheVolumeDirSuffix = "-cache"
)

func createCachePVC(ctx context.Context, pvcClient corev1client.CoreV1Interface, ownerObject corev1api.ObjectReference, sc string, size int64, selectedNode string) (*corev1api.PersistentVolumeClaim, error) {
	cachePVCName := getCachePVCName(ownerObject)

	volumeMode := corev1api.PersistentVolumeFilesystem

	pvcObj := &corev1api.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ownerObject.Namespace,
			Name:      cachePVCName,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: ownerObject.APIVersion,
					Kind:       ownerObject.Kind,
					Name:       ownerObject.Name,
					UID:        ownerObject.UID,
					Controller: boolptr.True(),
				},
			},
		},
		Spec: corev1api.PersistentVolumeClaimSpec{
			AccessModes:      []corev1api.PersistentVolumeAccessMode{corev1api.ReadWriteOnce},
			StorageClassName: &sc,
			VolumeMode:       &volumeMode,
			Resources: corev1api.VolumeResourceRequirements{
				Requests: corev1api.ResourceList{
					corev1api.ResourceStorage: *resource.NewQuantity(size, resource.BinarySI),
				},
			},
		},
	}

	if selectedNode != "" {
		pvcObj.Annotations = map[string]string{
			kube.KubeAnnSelectedNode: selectedNode,
		}
	}

	return pvcClient.PersistentVolumeClaims(pvcObj.Namespace).Create(ctx, pvcObj, metav1.CreateOptions{})
}

func getCachePVCName(ownerObject corev1api.ObjectReference) string {
	return ownerObject.Name + cacheVolumeDirSuffix
}

func getCacheVolumeSize(dataSize int64, info *CacheConfigs) int64 {
	if info == nil {
		return 0
	}

	if dataSize != 0 && dataSize < info.ResidentThreshold {
		return 0
	}

	// 20% inflate and round up to GB
	volumeSize := (info.Limit*12/10 + (1 << 30) - 1) / (1 << 30) * (1 << 30)

	return volumeSize
}
