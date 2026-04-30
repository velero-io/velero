/*
Copyright 2019 the Velero contributors.

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
	"google.golang.org/grpc"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
)

// VolumeSnapshotterPlugin is an implementation of go-plugin's Plugin
// interface with support for gRPC for the cloudprovider/VolumeSnapshotter
// interface.
type VolumeSnapshotterPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	*common.PluginBase
}

// GRPCClient returns a VolumeSnapshotter gRPC client.
func (p *VolumeSnapshotterPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, clientConn *grpc.ClientConn) (interface{}, error) {
	return common.NewClientDispenser(p.ClientLogger, clientConn, newVolumeSnapshotterGRPCClient), nil
}

// GRPCServer registers a VolumeSnapshotter gRPC server.
func (p *VolumeSnapshotterPlugin) GRPCServer(_ *plugin.GRPCBroker, server *grpc.Server) error {
	proto.RegisterVolumeSnapshotterServer(server, &VolumeSnapshotterGRPCServer{mux: p.ServerMux})
	return nil
}
