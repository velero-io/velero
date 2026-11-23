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

package v1

import (
	"context"

	plugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/velero-io/velero/pkg/plugin/framework/common"
	protoibav1 "github.com/velero-io/velero/pkg/plugin/generated/itemblockaction/v1"
)

// ItemBlockActionPlugin is an implementation of go-plugin's Plugin
// interface with support for gRPC for the backup/ItemAction
// interface.
type ItemBlockActionPlugin struct {
	plugin.NetRPCUnsupportedPlugin
	*common.PluginBase
}

// GRPCClient returns a clientDispenser for ItemBlockAction gRPC clients.
func (p *ItemBlockActionPlugin) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, clientConn *grpc.ClientConn) (any, error) {
	return common.NewClientDispenser(p.ClientLogger, clientConn, newItemBlockActionGRPCClient), nil
}

// GRPCServer registers a ItemBlockAction gRPC server.
func (p *ItemBlockActionPlugin) GRPCServer(_ *plugin.GRPCBroker, server *grpc.Server) error {
	protoibav1.RegisterItemBlockActionServer(server, &ItemBlockActionGRPCServer{mux: p.ServerMux})
	return nil
}
