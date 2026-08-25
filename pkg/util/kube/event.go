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
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
)

type EventRecorder interface {
	Event(object runtime.Object, warning bool, reason string, message string, a ...any)
	EndingEvent(object runtime.Object, warning bool, reason string, message string, a ...any)
	Shutdown()
}

type eventRecorder struct {
	broadcaster    record.EventBroadcaster
	recorder       record.EventRecorder
	lock           sync.Mutex
	endingSentinel *eventElement
	log            logrus.FieldLogger
}

type eventElement struct {
	t      string
	r      string
	m      string
	sinked chan struct{}
}

type eventSink struct {
	recorder *eventRecorder
	sink     typedcorev1.EventInterface
}

func NewEventRecorder(kubeClient kubernetes.Interface, scheme *runtime.Scheme, eventSource string, eventNode string, log logrus.FieldLogger) EventRecorder {
	res := eventRecorder{
		log: log,
	}

	res.broadcaster = record.NewBroadcasterWithCorrelatorOptions(record.CorrelatorOptions{
		// Bypass the built-in EventCorrelator's rate filtering, otherwise, the event will be abandoned if the rate exceeds.
		// The callers (i.e., data mover pods) have controlled the rate and total number outside. E.g., the progress is designed to be updated every 10 seconds and is changeable.
		BurstSize: math.MaxInt32,
		MaxEvents: 1,
		MessageFunc: func(event *corev1api.Event) string {
			return event.Message
		},
	})

	res.broadcaster.StartRecordingToSink(&eventSink{
		recorder: &res,
		sink:     kubeClient.CoreV1().Events(""),
	})

	res.recorder = res.broadcaster.NewRecorder(scheme, corev1api.EventSource{
		Component: eventSource,
		Host:      eventNode,
	})

	return &res
}

func (er *eventRecorder) Event(object runtime.Object, warning bool, reason string, message string, a ...any) {
	if er.broadcaster == nil {
		return
	}

	eventType := corev1api.EventTypeNormal
	if warning {
		eventType = corev1api.EventTypeWarning
	}

	if len(a) > 0 {
		er.recorder.Eventf(object, eventType, reason, message, a...)
	} else {
		er.recorder.Event(object, eventType, reason, message)
	}
}

func (er *eventRecorder) EndingEvent(object runtime.Object, warning bool, reason string, message string, a ...any) {
	if er.broadcaster == nil {
		return
	}

	er.Event(object, warning, reason, message, a...)

	var sentinelEvent string

	er.lock.Lock()
	if er.endingSentinel == nil {
		sentinelEvent = uuid.NewString()
		er.endingSentinel = &eventElement{
			t:      corev1api.EventTypeNormal,
			r:      sentinelEvent,
			m:      sentinelEvent,
			sinked: make(chan struct{}),
		}
	}
	er.lock.Unlock()

	if sentinelEvent != "" {
		er.Event(object, false, sentinelEvent, sentinelEvent)
	} else {
		er.log.Warn("More than one ending events, ignore")
	}
}

var shutdownTimeout = time.Minute

func (er *eventRecorder) Shutdown() {
	var wait chan struct{}
	er.lock.Lock()
	if er.endingSentinel != nil {
		wait = er.endingSentinel.sinked
	}
	er.lock.Unlock()

	if wait != nil {
		er.log.Info("Waiting sentinel before shutdown")

	waitloop:
		for {
			select {
			case <-wait:
				break waitloop
			case <-time.After(shutdownTimeout):
				er.log.Warn("Timeout waiting for assured events processed")
				break waitloop
			}
		}
	}

	er.broadcaster.Shutdown()
	er.broadcaster = nil

	er.lock.Lock()
	er.endingSentinel = nil
	er.lock.Unlock()
}

func (er *eventRecorder) sentinelWatch(event *corev1api.Event) bool {
	er.lock.Lock()
	defer er.lock.Unlock()

	if er.endingSentinel == nil {
		return false
	}

	if er.endingSentinel.m == event.Message && er.endingSentinel.r == event.Reason && er.endingSentinel.t == event.Type {
		close(er.endingSentinel.sinked)
		return true
	}

	return false
}

func (es *eventSink) Create(event *corev1api.Event) (*corev1api.Event, error) {
	if es.recorder.sentinelWatch(event) {
		return event, nil
	}

	return es.sink.CreateWithEventNamespaceWithContext(context.Background(), event)
}

func (es *eventSink) Update(event *corev1api.Event) (*corev1api.Event, error) {
	return es.sink.UpdateWithEventNamespaceWithContext(context.Background(), event)
}

func (es *eventSink) Patch(event *corev1api.Event, data []byte) (*corev1api.Event, error) {
	return es.sink.PatchWithEventNamespaceWithContext(context.Background(), event, data)
}
