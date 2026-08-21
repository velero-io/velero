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

// Package crds embeds the controller-tools generated CRD manifests from
// ./bases into the binary via go:embed.
package crds

import (
	"embed"

	apiextinstall "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/install"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

//go:embed bases/*.yaml
var basesFS embed.FS

var CRDs = crds()

func crds() []*apiextv1.CustomResourceDefinition {
	apiextinstall.Install(scheme.Scheme)
	decode := scheme.Codecs.UniversalDeserializer().Decode

	entries, err := basesFS.ReadDir("bases")
	if err != nil {
		panic(err)
	}

	objs := make([]*apiextv1.CustomResourceDefinition, 0, len(entries))
	for _, entry := range entries {
		data, err := basesFS.ReadFile("bases/" + entry.Name())
		if err != nil {
			panic(err)
		}

		obj, _, err := decode(data, nil, nil)
		if err != nil {
			panic(err)
		}
		objs = append(objs, obj.(*apiextv1.CustomResourceDefinition))
	}

	return objs
}
