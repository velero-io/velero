/*
Copyright 2017 the Velero contributors.

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

package test

import (
	"github.com/cockroachdb/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type FakeMapper struct {
	meta.RESTMapper
	AutoReturnResource   bool
	Resources            map[schema.GroupVersionResource]schema.GroupVersionResource
	KindToPluralResource map[schema.GroupVersionKind]schema.GroupVersionResource
}

func (m *FakeMapper) ResourceFor(input schema.GroupVersionResource) (schema.GroupVersionResource, error) {
	if m.AutoReturnResource {
		return schema.GroupVersionResource{
			Group:    input.Group,
			Version:  input.Version,
			Resource: input.Resource,
		}, nil
	}
	if m.Resources == nil {
		return schema.GroupVersionResource{}, errors.Errorf("invalid resource %q", input.String())
	}

	if gr, found := m.Resources[input]; found {
		return gr, nil
	}
	if input.Version == "" {
		input.Version = "v1"
		if gr, found := m.Resources[input]; found {
			return gr, nil
		}
		input.Version = "v1beta1"
		if gr, found := m.Resources[input]; found {
			return gr, nil
		}
	}

	return schema.GroupVersionResource{}, errors.Errorf("invalid resource %q", input.String())
}

func (m *FakeMapper) RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error) {
	potentialGVK := make([]schema.GroupVersionKind, 0)
	// Pick an appropriate version
	for _, version := range versions {
		if len(version) == 0 || version == runtime.APIVersionInternal {
			continue
		}
		currGVK := gk.WithVersion(version)
		if _, ok := m.KindToPluralResource[currGVK]; ok {
			potentialGVK = append(potentialGVK, currGVK)
			break
		}
	}
	if len(potentialGVK) == 0 {
		return nil, &meta.NoKindMatchError{GroupKind: gk, SearchedVersions: versions}
	}

	for _, gvk := range potentialGVK {
		//Ensure we have a REST mapping
		res, ok := m.KindToPluralResource[gvk]
		if !ok {
			continue
		}

		return &meta.RESTMapping{
			Resource:         res,
			GroupVersionKind: gvk,
			Scope:            meta.RESTScopeNamespace,
		}, nil
	}
	return nil, &meta.NoResourceMatchError{PartialResource: schema.GroupVersionResource{Group: gk.Group, Resource: gk.Kind}}
}
