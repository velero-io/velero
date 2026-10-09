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
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// SpecChangePredicate implements a default update predicate function on Spec change
// As Velero doesn't enable subresource in CRDs, we cannot use the object's metadata.generation field to check the spec change
// More details about the generation field refer to https://github.com/kubernetes-sigs/controller-runtime/blob/v0.12.2/pkg/predicate/predicate.go#L156
type SpecChangePredicate struct {
	predicate.Funcs
}

func (SpecChangePredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil {
		return false
	}
	if e.ObjectNew == nil {
		return false
	}
	oldSpec := reflect.ValueOf(e.ObjectOld).Elem().FieldByName("Spec")
	// contains no field named "Spec", return false directly
	if oldSpec.IsZero() {
		return false
	}
	newSpec := reflect.ValueOf(e.ObjectNew).Elem().FieldByName("Spec")
	return !reflect.DeepEqual(oldSpec.Interface(), newSpec.Interface())
}

// NewAllEventPredicate creates a new Predicate that checks all the events with the provided func
func NewAllEventPredicate(f func(object client.Object) bool) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event event.CreateEvent) bool {
			return f(event.Object)
		},
		DeleteFunc: func(event event.DeleteEvent) bool {
			return f(event.Object)
		},
		UpdateFunc: func(event event.UpdateEvent) bool {
			return f(event.ObjectNew)
		},
		GenericFunc: func(event event.GenericEvent) bool {
			return f(event.Object)
		},
	}
}

// FalsePredicate always returns false for all kinds of events
type FalsePredicate struct{}

// Create always returns false
func (f FalsePredicate) Create(event.CreateEvent) bool {
	return false
}

// Delete always returns false
func (f FalsePredicate) Delete(event.DeleteEvent) bool {
	return false
}

// Update always returns false
func (f FalsePredicate) Update(event.UpdateEvent) bool {
	return false
}

// Generic always returns false
func (f FalsePredicate) Generic(event.GenericEvent) bool {
	return false
}

// NewGenericEventPredicate creates a new Predicate that checks the Generic event with the provided func
func NewGenericEventPredicate(f func(object client.Object) bool) predicate.Predicate {
	return predicate.Funcs{
		GenericFunc: func(event event.GenericEvent) bool {
			return f(event.Object)
		},
	}
}

// NewUpdateEventPredicate creates a new Predicate that checks the Update event with the provided func
func NewUpdateEventPredicate(
	f func(objectOld client.Object, objectNew client.Object) bool,
) predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(event event.UpdateEvent) bool {
			return f(event.ObjectOld, event.ObjectNew)
		},
	}
}

func NewCreateEventPredicate(
	f func(object client.Object) bool,
) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event event.CreateEvent) bool {
			return f(event.Object)
		},
	}
}

// NewDeleteEventPredicate creates a new Predicate that checks the Delete event with the provided func
func NewDeleteEventPredicate(
	f func(object client.Object) bool,
) predicate.Predicate {
	return predicate.Funcs{
		DeleteFunc: func(event event.DeleteEvent) bool {
			return f(event.Object)
		},
	}
}
