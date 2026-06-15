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

package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/util/filesystem"
)

// Registry manages information about available plugins.
type Registry interface {
	// DiscoverPlugins discovers all available plugins.
	DiscoverPlugins() error
	// List returns all PluginIdentifiers for kind.
	List(kind common.PluginKind) []framework.PluginIdentifier
	// Get returns the PluginIdentifier for kind and name.
	Get(kind common.PluginKind, name string) (framework.PluginIdentifier, error)
}

// KindAndName is a convenience struct that combines a PluginKind and a name.
type KindAndName struct {
	Kind common.PluginKind
	Name string
}

// registry implements Registry.
type registry struct {
	// dir is the directory to search for plugins.
	dir      string
	logger   logrus.FieldLogger
	logLevel logrus.Level

	processFactory Factory
	fs             filesystem.Interface
	pluginsByID    map[KindAndName]framework.PluginIdentifier
	pluginsByKind  map[common.PluginKind][]framework.PluginIdentifier
}

// NewRegistry returns a new registry.
func NewRegistry(dir string, logger logrus.FieldLogger, logLevel logrus.Level) Registry {
	return &registry{
		dir:      dir,
		logger:   logger,
		logLevel: logLevel,

		processFactory: newProcessFactory(),
		fs:             filesystem.NewFileSystem(),
		pluginsByID:    make(map[KindAndName]framework.PluginIdentifier),
		pluginsByKind:  make(map[common.PluginKind][]framework.PluginIdentifier),
	}
}

func (r *registry) DiscoverPlugins() error {
	plugins, err := r.readPluginsDir(r.dir)
	if err != nil {
		return err
	}

	// Start by adding velero's internal plugins
	commands := []string{os.Args[0]}
	// Then add the discovered plugin executables
	commands = append(commands, plugins...)

	return r.discoverPlugins(commands)
}

func (r *registry) discoverPlugins(commands []string) error {
	for _, command := range commands {
		plugins, err := r.listPlugins(command)
		if err != nil {
			return err
		}

		for _, plugin := range plugins {
			r.logger.WithFields(logrus.Fields{
				"kind":    plugin.Kind,
				"name":    plugin.Name,
				"command": command,
			}).Info("registering plugin")

			if err := r.register(plugin); err != nil {
				return err
			}
		}
	}

	return nil
}

// List returns info about all plugin binaries that implement the given
// PluginKind.
func (r *registry) List(kind common.PluginKind) []framework.PluginIdentifier {
	return r.pluginsByKind[kind]
}

// Get returns info about a plugin with the given name and kind, or an
// error if one cannot be found.
func (r *registry) Get(kind common.PluginKind, name string) (framework.PluginIdentifier, error) {
	p, found := r.pluginsByID[KindAndName{Kind: kind, Name: name}]
	if !found {
		return framework.PluginIdentifier{}, newPluginNotFoundError(kind, name)
	}
	return p, nil
}

// readPluginsDir recursively reads dir looking for plugins.
func (r *registry) readPluginsDir(dir string) ([]string, error) {
	if _, err := r.fs.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, errors.WithStack(err)
	}

	files, err := r.fs.ReadDir(dir)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	fullPaths := make([]string, 0, len(files))
	for _, file := range files {
		fullPath := filepath.Join(dir, file.Name())

		if file.IsDir() {
			subDirPaths, err := r.readPluginsDir(fullPath)
			if err != nil {
				return nil, err
			}
			fullPaths = append(fullPaths, subDirPaths...)
			continue
		}

		if !executable(file) {
			r.logger.Warnf("Searching plugin skip file %s, not executable, mode %v, ext %s", file.Name(), file.Mode(), strings.ToLower(filepath.Ext(file.Name())))
			continue
		}

		fullPaths = append(fullPaths, fullPath)
	}
	return fullPaths, nil
}

// executable determines if a file is executable.
func executable(info os.FileInfo) bool {
	return executableLinux(info) || executableWindows(info)
}

func executableWindows(info os.FileInfo) bool {
	ext := strings.ToLower(filepath.Ext(info.Name()))
	return (ext == ".exe")
}

func executableLinux(info os.FileInfo) bool {
	/*
		When we AND the mode with 0111:

		- 0100 (user executable)
		- 0010 (group executable)
		- 0001 (other executable)

		the result will be 0 if and only if none of the executable bits is set.
	*/
	return (info.Mode() & 0111) != 0
}

// listPlugins executes command, queries it for registered plugins, and returns the list of PluginIdentifiers.
func (r *registry) listPlugins(command string) ([]framework.PluginIdentifier, error) {
	process, err := r.processFactory.newProcess(command, r.logger, r.logLevel)
	if err != nil {
		return nil, err
	}
	defer process.kill()

	plugin, err := process.dispense(KindAndName{Kind: common.PluginKindPluginLister})
	if err != nil {
		return nil, err
	}

	lister, ok := plugin.(framework.PluginLister)
	if !ok {
		return nil, errors.Errorf("%T is not a PluginLister", plugin)
	}

	return lister.ListPlugins()
}

// register registers a PluginIdentifier with the registry.
func (r *registry) register(id framework.PluginIdentifier) error {
	key := KindAndName{Kind: id.Kind, Name: id.Name}
	if existing, found := r.pluginsByID[key]; found {
		return newDuplicatePluginRegistrationError(existing, id)
	}

	// no need to pass list of existing plugins since the check if this exists was done above
	if err := common.ValidatePluginName(id.Name, nil); err != nil {
		return errors.Errorf("invalid plugin name %q: %s", id.Name, err)
	}

	r.pluginsByID[key] = id
	r.pluginsByKind[id.Kind] = append(r.pluginsByKind[id.Kind], id)

	// if id.Kind is adaptable to newer plugin versions, list it under the other versions as well
	// If BackupItemAction is adaptable to BackupItemActionV2, then it would be listed under both
	// kinds
	if kinds, ok := common.PluginKindsAdaptableTo[id.Kind]; ok {
		for _, kind := range kinds {
			r.pluginsByKind[kind] = append(r.pluginsByKind[kind], id)
		}
	}

	return nil
}

// pluginNotFoundError indicates a plugin could not be located for kind and name.
type PluginNotFoundError struct {
	kind common.PluginKind
	name string
}

// newPluginNotFoundError returns a new pluginNotFoundError for kind and name.
func newPluginNotFoundError(kind common.PluginKind, name string) *PluginNotFoundError {
	return &PluginNotFoundError{
		kind: kind,
		name: name,
	}
}

func (e *PluginNotFoundError) Error() string {
	return fmt.Sprintf("unable to locate %v plugin named %s", e.kind, e.name)
}

type duplicatePluginRegistrationError struct {
	existing  framework.PluginIdentifier
	duplicate framework.PluginIdentifier
}

func newDuplicatePluginRegistrationError(existing, duplicate framework.PluginIdentifier) *duplicatePluginRegistrationError {
	return &duplicatePluginRegistrationError{
		existing:  existing,
		duplicate: duplicate,
	}
}

func (e *duplicatePluginRegistrationError) Error() string {
	return fmt.Sprintf(
		"unable to register plugin (kind=%s, name=%s, command=%s) because another plugin is already registered for this kind and name (command=%s)",
		string(e.duplicate.Kind),
		e.duplicate.Name,
		e.duplicate.Command,
		e.existing.Command,
	)
}
