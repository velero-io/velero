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
	"sort"
	"testing"
	"time"

	"context"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/workqueue"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/vmware-tanzu/velero/internal/storage"
	velerov1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestStart(t *testing.T) {
	require.NoError(t, velerov1.AddToScheme(scheme.Scheme))

	ctx, cancelFunc := context.WithCancel(t.Context())
	client := (&fake.ClientBuilder{}).Build()
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedItemBasedRateLimiter[reconcile.Request]())
	source := NewPeriodicalEnqueueSource(logrus.WithContext(ctx).WithField("controller", "PES_TEST"), client, &velerov1.ScheduleList{}, 1*time.Second, PeriodicalEnqueueSourceOption{})

	require.NoError(t, source.Start(ctx, queue))

	// no resources
	time.Sleep(1 * time.Second)
	require.Equal(t, 0, queue.Len())

	// contain one resource
	require.NoError(t, client.Create(ctx, &velerov1.Schedule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "schedule",
		},
	}))
	time.Sleep(2 * time.Second)
	require.Equal(t, 1, queue.Len())

	// context canceled, the enqueue source shouldn't run anymore
	item, _ := queue.Get()
	queue.Forget(item)
	require.Equal(t, 0, queue.Len())
	cancelFunc()
	time.Sleep(2 * time.Second)
	require.Equal(t, 0, queue.Len())
}

func TestPredicate(t *testing.T) {
	require.NoError(t, velerov1.AddToScheme(scheme.Scheme))

	ctx, cancelFunc := context.WithCancel(t.Context())
	client := (&fake.ClientBuilder{}).Build()
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedItemBasedRateLimiter[reconcile.Request]())

	pred := NewGenericEventPredicate(func(object crclient.Object) bool {
		location := object.(*velerov1.BackupStorageLocation)
		return storage.IsReadyToValidate(location.Spec.ValidationFrequency, location.Status.LastValidationTime, 1*time.Minute, logrus.WithContext(ctx).WithField("BackupStorageLocation", location.Name))
	})
	source := NewPeriodicalEnqueueSource(
		logrus.WithContext(ctx).WithField("controller", "PES_TEST"),
		client,
		&velerov1.BackupStorageLocationList{},
		1*time.Second,
		PeriodicalEnqueueSourceOption{
			Predicates: []predicate.Predicate{pred},
		},
	)

	// Should not patch a backup storage location object status phase
	// if the location's validation frequency is specifically set to zero
	require.NoError(t, client.Create(ctx, &velerov1.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "location1",
			Namespace: "default",
		},
		Spec: velerov1.BackupStorageLocationSpec{
			ValidationFrequency: &metav1.Duration{Duration: 0},
		},
		Status: velerov1.BackupStorageLocationStatus{
			LastValidationTime: &metav1.Time{Time: time.Now()},
		},
	}))

	require.NoError(t, source.Start(ctx, queue))
	time.Sleep(2 * time.Second)

	require.Equal(t, 0, queue.Len())

	cancelFunc()
}

func TestOrder(t *testing.T) {
	require.NoError(t, velerov1.AddToScheme(scheme.Scheme))

	ctx, cancelFunc := context.WithCancel(t.Context())
	client := (&fake.ClientBuilder{}).Build()
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedItemBasedRateLimiter[reconcile.Request]())
	source := NewPeriodicalEnqueueSource(
		logrus.WithContext(ctx).WithField("controller", "PES_TEST"),
		client,
		&velerov1.BackupStorageLocationList{},
		1*time.Second,
		PeriodicalEnqueueSourceOption{
			OrderFunc: func(objList crclient.ObjectList) crclient.ObjectList {
				locationList, ok := objList.(*velerov1.BackupStorageLocationList)
				if !ok {
					return objList
				}

				sort.SliceStable(locationList.Items, func(i, j int) bool {
					return locationList.Items[i].Spec.Default && !locationList.Items[j].Spec.Default
				})

				return locationList
			},
		},
	)

	// Should not patch a backup storage location object status phase
	// if the location's validation frequency is specifically set to zero
	require.NoError(t, client.Create(ctx, &velerov1.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "location1",
			Namespace: "default",
		},
		Spec: velerov1.BackupStorageLocationSpec{
			ValidationFrequency: &metav1.Duration{Duration: 0},
		},
		Status: velerov1.BackupStorageLocationStatus{
			LastValidationTime: &metav1.Time{Time: time.Now()},
		},
	}))
	require.NoError(t, client.Create(ctx, &velerov1.BackupStorageLocation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "location2",
			Namespace: "default",
		},
		Spec: velerov1.BackupStorageLocationSpec{
			ValidationFrequency: &metav1.Duration{Duration: 0},
			Default:             true,
		},
		Status: velerov1.BackupStorageLocationStatus{
			LastValidationTime: &metav1.Time{Time: time.Now()},
		},
	}))

	require.NoError(t, source.Start(ctx, queue))
	time.Sleep(2 * time.Second)

	first, _ := queue.Get()
	bsl := &velerov1.BackupStorageLocation{}
	require.Equal(t, "location2", first.Name)
	require.NoError(t, client.Get(ctx, first.NamespacedName, bsl))
	require.True(t, bsl.Spec.Default)

	cancelFunc()
}
