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

package kube

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	velerov1 "github.com/velero-io/velero/pkg/apis/velero/v1"
)

func TestSpecChangePredicate(t *testing.T) {
	cases := []struct {
		name    string
		oldObj  client.Object
		newObj  client.Object
		changed bool
	}{
		{
			name: "Contains no spec field",
			oldObj: &velerov1.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bsl01",
				},
			},
			newObj: &velerov1.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bsl01",
				},
			},
			changed: false,
		},
		{
			name: "ObjectMetas are different, Specs are same",
			oldObj: &velerov1.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "bsl01",
					Annotations: map[string]string{"key1": "value1"},
				},
				Spec: velerov1.BackupStorageLocationSpec{
					Provider: "azure",
				},
			},
			newObj: &velerov1.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "bsl01",
					Annotations: map[string]string{"key2": "value2"},
				},
				Spec: velerov1.BackupStorageLocationSpec{
					Provider: "azure",
				},
			},
			changed: false,
		},
		{
			name: "Statuses are different, Specs are same",
			oldObj: &velerov1.BackupStorageLocation{
				Spec: velerov1.BackupStorageLocationSpec{
					Provider: "azure",
				},
				Status: velerov1.BackupStorageLocationStatus{
					Phase: velerov1.BackupStorageLocationPhaseAvailable,
				},
			},
			newObj: &velerov1.BackupStorageLocation{
				Spec: velerov1.BackupStorageLocationSpec{
					Provider: "azure",
				},
				Status: velerov1.BackupStorageLocationStatus{
					Phase: velerov1.BackupStorageLocationPhaseUnavailable,
				},
			},
			changed: false,
		},
		{
			name: "Specs are different",
			oldObj: &velerov1.BackupStorageLocation{
				Spec: velerov1.BackupStorageLocationSpec{
					Provider: "azure",
				},
			},
			newObj: &velerov1.BackupStorageLocation{
				Spec: velerov1.BackupStorageLocationSpec{
					Provider: "aws",
				},
			},
			changed: true,
		},
		{
			name: "Specs are same",
			oldObj: &velerov1.BackupStorageLocation{
				Spec: velerov1.BackupStorageLocationSpec{
					Provider: "azure",
					Config:   map[string]string{"key": "value"},
					Credential: &corev1api.SecretKeySelector{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "secret",
						},
						Key: "credential",
					},
					StorageType: velerov1.StorageType{
						ObjectStorage: &velerov1.ObjectStorageLocation{
							Bucket: "bucket1",
							Prefix: "prefix",
							CACert: []byte{'a'},
						},
					},
					Default:    true,
					AccessMode: velerov1.BackupStorageLocationAccessModeReadWrite,
					BackupSyncPeriod: &metav1.Duration{
						Duration: 1 * time.Minute,
					},
					ValidationFrequency: &metav1.Duration{
						Duration: 1 * time.Minute,
					},
				},
			},
			newObj: &velerov1.BackupStorageLocation{
				Spec: velerov1.BackupStorageLocationSpec{
					Provider: "azure",
					Config:   map[string]string{"key": "value"},
					Credential: &corev1api.SecretKeySelector{
						LocalObjectReference: corev1api.LocalObjectReference{
							Name: "secret",
						},
						Key: "credential",
					},
					StorageType: velerov1.StorageType{
						ObjectStorage: &velerov1.ObjectStorageLocation{
							Bucket: "bucket1",
							Prefix: "prefix",
							CACert: []byte{'a'},
						},
					},
					Default:    true,
					AccessMode: velerov1.BackupStorageLocationAccessModeReadWrite,
					BackupSyncPeriod: &metav1.Duration{
						Duration: 1 * time.Minute,
					},
					ValidationFrequency: &metav1.Duration{
						Duration: 1 * time.Minute,
					},
				},
			},
			changed: false,
		},
	}

	predicate := SpecChangePredicate{}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			changed := predicate.Update(event.UpdateEvent{
				ObjectOld: c.oldObj,
				ObjectNew: c.newObj,
			})
			assert.Equal(t, c.changed, changed)
		})
	}
}

func TestNewAllEventPredicate(t *testing.T) {
	predicate := NewAllEventPredicate(func(object client.Object) bool {
		return false
	})

	assert.False(t, predicate.Create(event.CreateEvent{}))
	assert.False(t, predicate.Update(event.UpdateEvent{}))
	assert.False(t, predicate.Delete(event.DeleteEvent{}))
	assert.False(t, predicate.Generic(event.GenericEvent{}))
}

func TestNewGenericEventPredicate(t *testing.T) {
	predicate := NewGenericEventPredicate(func(object client.Object) bool {
		return false
	})

	assert.False(t, predicate.Generic(event.GenericEvent{}))
	assert.True(t, predicate.Update(event.UpdateEvent{}))
	assert.True(t, predicate.Create(event.CreateEvent{}))
	assert.True(t, predicate.Delete(event.DeleteEvent{}))
}

func TestNewUpdateEventPredicate(t *testing.T) {
	predicate := NewUpdateEventPredicate(
		func(client.Object, client.Object) bool {
			return false
		},
	)

	assert.False(t, predicate.Update(event.UpdateEvent{}))
	assert.True(t, predicate.Create(event.CreateEvent{}))
	assert.True(t, predicate.Delete(event.DeleteEvent{}))
	assert.True(t, predicate.Generic(event.GenericEvent{}))
}

func TestNewCreateEventPredicate(t *testing.T) {
	predicate := NewCreateEventPredicate(
		func(client.Object) bool {
			return false
		},
	)

	assert.False(t, predicate.Create(event.CreateEvent{}))
	assert.True(t, predicate.Update(event.UpdateEvent{}))
	assert.True(t, predicate.Generic(event.GenericEvent{}))
	assert.True(t, predicate.Delete(event.DeleteEvent{}))
}
