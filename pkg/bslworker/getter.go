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

package bslworker

import (
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/persistence"
)

// WorkerGetterFactory implements persistence.WorkerObjectStoreGetterFactory.
var _ persistence.WorkerObjectStoreGetterFactory = (*WorkerGetterFactory)(nil)

// WorkerGetterFactory implements persistence.WorkerObjectStoreGetterFactory. For a
// worker-backed BackupStorageLocation it returns a RemoteObjectStoreGetter that dials
// the location's worker Service over mutual TLS, using the central Velero client
// certificate. Getters (and their connections) are cached per worker endpoint.
type WorkerGetterFactory struct {
	logger logrus.FieldLogger
	// defaultNamespace is where a worker runs when the BSL does not specify one
	// (the Velero server namespace).
	defaultNamespace string
	// Central client mutual-TLS materials, mounted from the worker TLS Secret.
	clientCertFile string
	clientKeyFile  string
	caFile         string

	mu      sync.Mutex
	getters map[string]*RemoteObjectStoreGetter
}

// NewWorkerGetterFactory returns a factory that dials workers using the given central
// client certificate/key and CA, defaulting workers to defaultNamespace.
func NewWorkerGetterFactory(logger logrus.FieldLogger, defaultNamespace, clientCertFile, clientKeyFile, caFile string) *WorkerGetterFactory {
	return &WorkerGetterFactory{
		logger:           logger,
		defaultNamespace: defaultNamespace,
		clientCertFile:   clientCertFile,
		clientKeyFile:    clientKeyFile,
		caFile:           caFile,
		getters:          make(map[string]*RemoteObjectStoreGetter),
	}
}

// GetterFor returns an ObjectStoreGetter that proxies to the worker serving location.
func (f *WorkerGetterFactory) GetterFor(location *velerov1api.BackupStorageLocation, logger logrus.FieldLogger) (persistence.ObjectStoreGetter, error) {
	if location.Spec.Worker == nil {
		return nil, errors.Errorf("backup storage location %q has no worker configuration", location.Name)
	}

	namespace := location.Spec.Worker.Namespace
	if namespace == "" {
		namespace = f.defaultNamespace
	}

	endpoint := WorkerEndpoint(location.Name, namespace)
	serverName := WorkerServiceDNS(location.Name, namespace)

	f.mu.Lock()
	defer f.mu.Unlock()

	if g, ok := f.getters[endpoint]; ok {
		return g, nil
	}

	tlsConfig, err := LoadClientTLSConfig(f.clientCertFile, f.clientKeyFile, f.caFile, serverName)
	if err != nil {
		return nil, errors.Wrapf(err, "loading client TLS config for worker %q", endpoint)
	}

	getterLogger := logger
	if getterLogger == nil {
		getterLogger = f.logger
	}

	g := NewRemoteObjectStoreGetter(getterLogger, endpoint, tlsConfig)
	f.getters[endpoint] = g
	return g, nil
}

// Forget drops and closes the cached getter for the worker serving the named BSL in
// the given namespace (the Velero namespace if empty). It is called when a worker is
// torn down or its connection should be re-established.
func (f *WorkerGetterFactory) Forget(bslName, namespace string) {
	if namespace == "" {
		namespace = f.defaultNamespace
	}
	endpoint := WorkerEndpoint(bslName, namespace)

	f.mu.Lock()
	defer f.mu.Unlock()

	if g, ok := f.getters[endpoint]; ok {
		_ = g.Close()
		delete(f.getters, endpoint)
	}
}

// Close closes all cached getter connections.
func (f *WorkerGetterFactory) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()

	for endpoint, g := range f.getters {
		_ = g.Close()
		delete(f.getters, endpoint)
	}
}
