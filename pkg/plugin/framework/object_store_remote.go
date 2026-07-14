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

package framework

import (
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// NewObjectStoreGRPCServer returns a proto.ObjectStoreServer backed by the given
// ServerMux. It exposes the existing ObjectStore gRPC service implementation so it
// can be served over a network transport (for example, a per-BackupStorageLocation
// worker pod) instead of, or in addition to, go-plugin's local transport.
func NewObjectStoreGRPCServer(mux *common.ServerMux) proto.ObjectStoreServer {
	return &ObjectStoreGRPCServer{mux: mux}
}

// NewObjectStoreGRPCClientForConn returns a velero.ObjectStore backed by a gRPC client
// on the provided connection. pluginName is sent as the multiplexing key on every
// request, so it must match the name the server's ServerMux was registered with.
func NewObjectStoreGRPCClientForConn(logger logrus.FieldLogger, pluginName string, clientConn *grpc.ClientConn) velero.ObjectStore {
	base := &common.ClientBase{
		Plugin: pluginName,
		Logger: logger,
	}
	return newObjectStoreGRPCClient(base, clientConn).(velero.ObjectStore)
}
