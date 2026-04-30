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

package framework

import (
	"context"

	plugin "github.com/hashicorp/go-plugin"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
)

// PluginIdentifier uniquely identifies a plugin by command, kind, and name.
type PluginIdentifier struct {
	Command string
	Kind    common.PluginKind
	Name    string
}

// PluginLister lists plugins.
type PluginLister interface {
	ListPlugins() ([]PluginIdentifier, error)
}

// pluginLister implements PluginLister.
type pluginLister struct {
	plugins []PluginIdentifier
}

// NewPluginLister returns a new PluginLister for plugins.
func NewPluginLister(plugins ...PluginIdentifier) PluginLister {
	return &pluginLister{plugins: plugins}
}

// ListPlugins returns the pluginLister's plugins.
func (pl *pluginLister) ListPlugins() ([]PluginIdentifier, error) {
	return pl.plugins, nil
}

// PluginListerPlugin is a go-plugin Plugin for a PluginLister.
type PluginListerPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	impl PluginLister
}

// NewPluginListerPlugin creates a new PluginListerPlugin with impl as the server-side implementation.
func NewPluginListerPlugin(impl PluginLister) *PluginListerPlugin {
	return &PluginListerPlugin{impl: impl}
}

//////////////////////////////////////////////////////////////////////////////
// client code
//////////////////////////////////////////////////////////////////////////////

// GRPCClient returns a PluginLister gRPC client.
func (p *PluginListerPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, clientConn *grpc.ClientConn) (interface{}, error) {
	return &PluginListerGRPCClient{grpcClient: proto.NewPluginListerClient(clientConn)}, nil
}

// PluginListerGRPCClient implements PluginLister and uses a gRPC client to make calls to the plugin server.
type PluginListerGRPCClient struct {
	grpcClient proto.PluginListerClient
}

// ListPlugins uses the gRPC client to request the list of plugins from the server. It translates the protobuf response
// to []PluginIdentifier.
func (c *PluginListerGRPCClient) ListPlugins() ([]PluginIdentifier, error) {
	resp, err := c.grpcClient.ListPlugins(context.Background(), &proto.Empty{})
	if err != nil {
		return nil, err
	}

	ret := make([]PluginIdentifier, len(resp.Plugins))
	for i, id := range resp.Plugins {
		if _, ok := common.AllPluginKinds()[id.Kind]; !ok {
			return nil, errors.Errorf("invalid plugin kind: %s", id.Kind)
		}

		ret[i] = PluginIdentifier{
			Command: id.Command,
			Kind:    common.PluginKind(id.Kind),
			Name:    id.Name,
		}
	}

	return ret, nil
}

//////////////////////////////////////////////////////////////////////////////
// server code
//////////////////////////////////////////////////////////////////////////////

// GRPCServer registers a PluginLister gRPC server.
func (p *PluginListerPlugin) GRPCServer(_ *plugin.GRPCBroker, server *grpc.Server) error {
	proto.RegisterPluginListerServer(server, &PluginListerGRPCServer{impl: p.impl})
	return nil
}

// PluginListerGRPCServer implements the proto-generated PluginLister gRPC service interface. It accepts gRPC calls,
// forwards them to impl, and translates the responses to protobuf.
type PluginListerGRPCServer struct {
	impl PluginLister
}

// ListPlugins returns a list of registered plugins, delegating to s.impl to perform the listing.
func (s *PluginListerGRPCServer) ListPlugins(ctx context.Context, req *proto.Empty) (*proto.ListPluginsResponse, error) {
	list, err := s.impl.ListPlugins()
	if err != nil {
		return nil, err
	}

	plugins := make([]*proto.PluginIdentifier, len(list))
	for i, id := range list {
		if _, ok := common.AllPluginKinds()[id.Kind.String()]; !ok {
			return nil, errors.Errorf("invalid plugin kind: %s", id.Kind)
		}

		plugins[i] = &proto.PluginIdentifier{
			Command: id.Command,
			Kind:    id.Kind.String(),
			Name:    id.Name,
		}
	}
	ret := &proto.ListPluginsResponse{
		Plugins: plugins,
	}
	return ret, nil
}
