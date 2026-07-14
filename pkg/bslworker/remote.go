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
	"crypto/tls"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// maxGRPCMessageSize bounds unary responses (e.g. large object listings). Streaming
// object data is chunked well below this by the ObjectStore gRPC implementation.
const maxGRPCMessageSize = 64 << 20 // 64 MiB

// RemoteObjectStoreGetter implements persistence.ObjectStoreGetter by proxying object
// store operations to a per-BackupStorageLocation worker pod over a network mTLS gRPC
// connection. The returned velero.ObjectStore reuses the standard ObjectStore plugin
// protocol, so all higher-level BackupStore operations run under the worker's identity.
//
// A getter targets a single worker endpoint and lazily maintains one shared
// connection; it is safe for concurrent use.
type RemoteObjectStoreGetter struct {
	logger    logrus.FieldLogger
	endpoint  string
	tlsConfig *tls.Config

	mu   sync.Mutex
	conn *grpc.ClientConn
}

// NewRemoteObjectStoreGetter returns a getter that dials the worker at endpoint
// (host:port) using the supplied mutual-TLS configuration.
func NewRemoteObjectStoreGetter(logger logrus.FieldLogger, endpoint string, tlsConfig *tls.Config) *RemoteObjectStoreGetter {
	return &RemoteObjectStoreGetter{
		logger:    logger,
		endpoint:  endpoint,
		tlsConfig: tlsConfig,
	}
}

// GetObjectStore returns a velero.ObjectStore backed by the worker. The provider name
// is ignored: a worker serves exactly one object store (selected when the worker was
// started) registered under WorkerObjectStorePluginName.
func (g *RemoteObjectStoreGetter) GetObjectStore(provider string) (velero.ObjectStore, error) {
	conn, err := g.dial()
	if err != nil {
		return nil, err
	}
	return framework.NewObjectStoreGRPCClientForConn(g.logger, WorkerObjectStorePluginName, conn), nil
}

// dial returns a healthy shared client connection to the worker, creating one if
// necessary.
func (g *RemoteObjectStoreGetter) dial() (*grpc.ClientConn, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.conn != nil && g.conn.GetState() != connectivity.Shutdown {
		return g.conn, nil
	}

	conn, err := grpc.NewClient(
		g.endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(g.tlsConfig)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxGRPCMessageSize),
			grpc.MaxCallSendMsgSize(maxGRPCMessageSize),
		),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "creating gRPC client for worker %q", g.endpoint)
	}

	g.conn = conn
	return conn, nil
}

// Close closes the shared connection to the worker, if any.
func (g *RemoteObjectStoreGetter) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.conn == nil {
		return nil
	}
	err := g.conn.Close()
	g.conn = nil
	return err
}
