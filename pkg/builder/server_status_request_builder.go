/*
Copyright 2018 the Velero contributors.

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

package builder

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
)

// ServerStatusRequestBuilder builds ServerStatusRequest objects.
type ServerStatusRequestBuilder struct {
	object *velerov1api.ServerStatusRequest
}

// ForServerStatusRequest is the constructor for a ServerStatusRequestBuilder.
func ForServerStatusRequest(ns, name, resourceVersion string) *ServerStatusRequestBuilder {
	return &ServerStatusRequestBuilder{
		object: &velerov1api.ServerStatusRequest{
			TypeMeta: metav1.TypeMeta{
				APIVersion: velerov1api.SchemeGroupVersion.String(),
				Kind:       "ServerStatusRequest",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace:       ns,
				Name:            name,
				ResourceVersion: resourceVersion,
			},
		},
	}
}

// Result returns the built ServerStatusRequest.
func (b *ServerStatusRequestBuilder) Result() *velerov1api.ServerStatusRequest {
	return b.object
}

// ObjectMeta applies functional options to the ServerStatusRequest's ObjectMeta.
func (b *ServerStatusRequestBuilder) ObjectMeta(opts ...ObjectMetaOpt) *ServerStatusRequestBuilder {
	for _, opt := range opts {
		opt(b.object)
	}

	return b
}

// Phase sets the ServerStatusRequest's phase.
func (b *ServerStatusRequestBuilder) Phase(phase velerov1api.ServerStatusRequestPhase) *ServerStatusRequestBuilder {
	b.object.Status.Phase = phase
	return b
}

// ProcessedTimestamp sets the ServerStatusRequest's processed timestamp.
func (b *ServerStatusRequestBuilder) ProcessedTimestamp(time time.Time) *ServerStatusRequestBuilder {
	b.object.Status.ProcessedTimestamp = &metav1.Time{Time: time}
	return b
}

// ServerVersion sets the ServerStatusRequest's server version.
func (b *ServerStatusRequestBuilder) ServerVersion(version string) *ServerStatusRequestBuilder {
	b.object.Status.ServerVersion = version
	return b
}

// Plugins sets the ServerStatusRequest's plugins.
func (b *ServerStatusRequestBuilder) Plugins(plugins []velerov1api.PluginInfo) *ServerStatusRequestBuilder {
	b.object.Status.Plugins = plugins
	return b
}
