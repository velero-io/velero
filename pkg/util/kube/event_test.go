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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	corev1api "k8s.io/api/core/v1"

	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestEvent(t *testing.T) {
	type testEvent struct {
		warning bool
		reason  string
		message string
		ending  bool
	}

	cases := []struct {
		name           string
		events         []testEvent
		generateDiff   int
		generateSame   int
		generateEnding bool
		expected       int
	}{
		{
			name: "update events, different message",
			events: []testEvent{
				{
					warning: false,
					reason:  "Progress",
					message: "progress-1",
				},
				{
					warning: false,
					reason:  "Progress",
					message: "progress-2",
					ending:  true,
				},
			},
			expected: 1,
		},
		{
			name: "create events, different reason",
			events: []testEvent{
				{
					warning: false,
					reason:  "action-1-1",
					message: "fake-message",
				},
				{
					warning: false,
					reason:  "action-1-2",
					message: "fake-message",
					ending:  true,
				},
			},
			expected: 2,
		},
		{
			name: "create events, different warning",
			events: []testEvent{
				{
					warning: false,
					reason:  "action-2-1",
					message: "fake-message",
				},
				{
					warning: true,
					reason:  "action-2-1",
					message: "fake-message",
					ending:  true,
				},
			},
			expected: 2,
		},
		{
			name: "endingEvent, double entrance",
			events: []testEvent{
				{
					warning: false,
					reason:  "action-2-1",
					message: "fake-message",
					ending:  true,
				},
				{
					warning: true,
					reason:  "action-2-1",
					message: "fake-message",
					ending:  true,
				},
			},
			expected: -1,
		},
		{
			name:           "auto generate 200",
			generateDiff:   200,
			generateEnding: true,
			expected:       201,
		},
		{
			name:           "auto generate 200, update",
			generateSame:   200,
			generateEnding: true,
			expected:       2,
		},
	}

	shutdownTimeout = time.Second * 5

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			scheme := runtime.NewScheme()
			err := corev1api.AddToScheme(scheme)
			require.NoError(t, err)

			recorder := NewEventRecorder(client, scheme, "source-1", "fake-node", velerotest.NewLogger())

			pod := &corev1api.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fake-ns",
					Name:      "fake-pod",
					UID:       types.UID("fake-uid"),
				},
				Spec: corev1api.PodSpec{
					NodeName: "fake-node",
				},
			}

			_, err = client.CoreV1().Pods("fake-ns").Create(t.Context(), pod, metav1.CreateOptions{})
			require.NoError(t, err)

			for i := 0; i < tc.generateDiff; i++ {
				tc.events = append(tc.events, testEvent{
					reason:  fmt.Sprintf("fake-reason-%v", i),
					message: fmt.Sprintf("fake-message-%v", i),
				})
			}

			for i := 0; i < tc.generateSame; i++ {
				tc.events = append(tc.events, testEvent{
					reason:  "fake-reason",
					message: fmt.Sprintf("fake-message-%v", i),
				})
			}

			if tc.generateEnding {
				tc.events = append(tc.events, testEvent{
					reason:  "fake-ending-reason",
					message: "fake-ending-message",
					ending:  true,
				})
			}

			for _, e := range tc.events {
				if e.ending {
					recorder.EndingEvent(pod, e.warning, e.reason, e.message)
				} else {
					recorder.Event(pod, e.warning, e.reason, e.message)
				}
			}

			recorder.Shutdown()

			items, err := client.CoreV1().Events("fake-ns").List(t.Context(), metav1.ListOptions{})
			require.NoError(t, err)

			if tc.expected != len(items.Items) {
				for _, i := range items.Items {
					fmt.Printf("event (%s, %s, %s)\n", i.Type, i.Message, i.Reason)
				}
			}

			if tc.expected >= 0 {
				assert.Len(t, items.Items, tc.expected)
			}
		})
	}
}
