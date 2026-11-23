/*
Copyright 2020 the Velero contributors.

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

package velero

import (
	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/plugin/framework"
	"github.com/velero-io/velero/pkg/plugin/framework/common"
)

type PluginLister interface {
	// List returns all PluginIdentifiers for kind.
	List(kind common.PluginKind) []framework.PluginIdentifier
}

// GetInstalledPluginInfo returns a list of installed plugins
func GetInstalledPluginInfo(pluginLister PluginLister) []velerov1api.PluginInfo {
	var plugins []velerov1api.PluginInfo
	for _, v := range common.AllPluginKinds() {
		list := pluginLister.List(v)
		for _, plugin := range list {
			pluginInfo := velerov1api.PluginInfo{
				Name: plugin.Name,
				Kind: plugin.Kind.String(),
			}
			plugins = append(plugins, pluginInfo)
		}
	}
	return plugins
}
