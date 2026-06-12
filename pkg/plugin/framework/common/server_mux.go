/*
Copyright 2018, 2019 the Velero contributors.

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

package common

import (
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
)

// HandlerInitializer is a function that initializes and returns a new instance of one of Velero's plugin interfaces
// (ObjectStore, VolumeSnapshotter, BackupItemAction, RestoreItemAction).
type HandlerInitializer func(logger logrus.FieldLogger) (any, error)

// ServerMux manages multiple implementations of a single plugin kind, such as pod and pvc BackupItemActions.
type ServerMux struct {
	kind         PluginKind
	initializers map[string]HandlerInitializer
	Handlers     map[string]any
	ServerLog    logrus.FieldLogger
}

// NewServerMux returns a new ServerMux.
func NewServerMux(logger logrus.FieldLogger) *ServerMux {
	return &ServerMux{
		initializers: make(map[string]HandlerInitializer),
		Handlers:     make(map[string]any),
		ServerLog:    logger,
	}
}

// register validates the plugin name and registers the
// initializer for the given name.
func (m *ServerMux) Register(name string, f HandlerInitializer) {
	if err := ValidatePluginName(name, m.Names()); err != nil {
		m.ServerLog.Errorf("invalid plugin name %q: %s", name, err)
		return
	}
	m.initializers[name] = f
}

// names returns a list of all registered implementations.
func (m *ServerMux) Names() []string {
	return sets.StringKeySet(m.initializers).List()
}

// GetHandler returns the instance for a plugin with the given name. If an instance has already been initialized,
// that is returned. Otherwise, the instance is initialized by calling its initialization function.
func (m *ServerMux) GetHandler(name string) (any, error) {
	if instance, found := m.Handlers[name]; found {
		return instance, nil
	}

	initializer, found := m.initializers[name]
	if !found {
		return nil, errors.Errorf("%v plugin: %s was not found or has an invalid name format", m.kind, name)
	}

	instance, err := initializer(m.ServerLog)
	if err != nil {
		return nil, err
	}

	m.Handlers[name] = instance

	return m.Handlers[name], nil
}

// ValidatePluginName checks if the given name:
// - the plugin name has two parts separated by '/'
// - non of the above parts is empty
// - the prefix is a valid DNS subdomain name
// - a plugin with the same name does not already exist (if list of existing names is passed in)
func ValidatePluginName(name string, existingNames []string) error {
	// validate there is one "/" and two parts
	parts := strings.Split(name, "/")
	if len(parts) != 2 {
		return errors.Errorf("plugin name must have exactly two parts separated by a `/`. Accepted format: <DNS subdomain>/<non-empty name>. %s is invalid", name)
	}

	// validate both prefix and name are non-empty
	if parts[0] == "" || parts[1] == "" {
		return errors.Errorf("both parts of the plugin name must be non-empty. Accepted format: <DNS subdomain>/<non-empty name>. %s is invalid", name)
	}

	// validate that the prefix is a DNS subdomain
	if errs := validation.IsDNS1123Subdomain(parts[0]); len(errs) != 0 {
		return errors.Errorf("first part of the plugin name must be a valid DNS subdomain. Accepted format: <DNS subdomain>/<non-empty name>. first part %q is invalid: %s", parts[0], strings.Join(errs, "; "))
	}

	for _, existingName := range existingNames {
		if strings.Compare(name, existingName) == 0 {
			return errors.New("plugin name " + existingName + " already exists")
		}
	}

	return nil
}
