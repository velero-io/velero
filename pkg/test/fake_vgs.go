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

package test

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const vgsGroup = "groupsnapshot.storage.k8s.io"

// VGSTestRESTMapper returns a RESTMapper that serves the VolumeGroupSnapshot
// kinds at the given versions. The vanilla fake controller-runtime client has no
// RESTMapper, so this is needed for code that resolves the served VGS version via
// client.RESTMapper() and for unstructured VGS I/O. Pass no versions for a mapper
// that serves no VGS API (to exercise the "not available" path).
func VGSTestRESTMapper(versions ...string) meta.RESTMapper {
	gvs := make([]schema.GroupVersion, 0, len(versions))
	for _, v := range versions {
		gvs = append(gvs, schema.GroupVersion{Group: vgsGroup, Version: v})
	}
	m := meta.NewDefaultRESTMapper(gvs)
	for _, v := range versions {
		gv := schema.GroupVersion{Group: vgsGroup, Version: v}
		m.Add(gv.WithKind("VolumeGroupSnapshot"), meta.RESTScopeNamespace)
		m.Add(gv.WithKind("VolumeGroupSnapshotClass"), meta.RESTScopeRoot)
		m.Add(gv.WithKind("VolumeGroupSnapshotContent"), meta.RESTScopeRoot)
	}
	return m
}

// NewFakeControllerRuntimeClientWithVGS returns a fake controller-runtime client
// with a RESTMapper serving the VolumeGroupSnapshot v1 API, seeded with objs. Use
// this for tests that exercise the csi VGS helpers (which route unstructured VGS
// I/O through the client's RESTMapper).
func NewFakeControllerRuntimeClientWithVGS(t *testing.T, objs ...runtime.Object) client.Client {
	t.Helper()
	return NewFakeControllerRuntimeClientBuilder(t).
		WithRESTMapper(VGSTestRESTMapper("v1")).
		WithRuntimeObjects(objs...).
		Build()
}
