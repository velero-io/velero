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
	"context"
	"crypto/tls"
	"net"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// Server serves a single local velero.ObjectStore over a network mTLS gRPC endpoint
// using the standard ObjectStore plugin protocol. It runs inside the per-BSL worker
// pod; the central Velero process connects to it via a RemoteObjectStoreGetter.
type Server struct {
	objectStore velero.ObjectStore
	tlsConfig   *tls.Config
	logger      logrus.FieldLogger
}

// NewServer returns a Server that exposes objectStore, securing the connection with
// the given mutual-TLS server configuration.
func NewServer(logger logrus.FieldLogger, objectStore velero.ObjectStore, tlsConfig *tls.Config) *Server {
	return &Server{
		objectStore: objectStore,
		tlsConfig:   tlsConfig,
		logger:      logger,
	}
}

// Serve listens on listenAddr and serves the ObjectStore gRPC service until ctx is
// canceled, at which point it gracefully stops. It blocks until the server stops.
func (s *Server) Serve(ctx context.Context, listenAddr string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return errors.Wrapf(err, "listening on %q", listenAddr)
	}
	return s.ServeListener(ctx, listener)
}

// ServeListener serves the ObjectStore gRPC service on the provided listener until
// ctx is canceled, at which point it gracefully stops. It blocks until the server
// stops. It is primarily useful for tests that need to bind an ephemeral port.
func (s *Server) ServeListener(ctx context.Context, listener net.Listener) error {
	// Register the local object store in a ServerMux under the shared transport name
	// so the reused ObjectStore gRPC server can look it up for every request.
	mux := common.NewServerMux(s.logger)
	mux.Register(WorkerObjectStorePluginName, func(logrus.FieldLogger) (any, error) {
		return s.objectStore, nil
	})

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(s.tlsConfig)))
	proto.RegisterObjectStoreServer(grpcServer, framework.NewObjectStoreGRPCServer(mux))

	go func() {
		<-ctx.Done()
		s.logger.Info("Shutting down BSL worker object store server")
		grpcServer.GracefulStop()
	}()

	s.logger.Infof("Serving BSL worker object store on %s", listener.Addr())
	if err := grpcServer.Serve(listener); err != nil {
		return errors.Wrap(err, "serving gRPC")
	}
	return nil
}
