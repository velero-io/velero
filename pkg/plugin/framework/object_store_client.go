/*
Copyright 2017, 2019 the Velero contributors.

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
	"io"
	"time"

	"context"

	"github.com/cockroachdb/errors"
	"google.golang.org/grpc"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
)

const byteChunkSize = 16384

// NewObjectStorePlugin construct an ObjectStorePlugin.
func NewObjectStorePlugin(options ...common.PluginOption) *ObjectStorePlugin {
	return &ObjectStorePlugin{
		PluginBase: common.NewPluginBase(options...),
	}
}

// ObjectStoreGRPCClient implements the ObjectStore interface and uses a
// gRPC client to make calls to the plugin server.
type ObjectStoreGRPCClient struct {
	*common.ClientBase
	grpcClient proto.ObjectStoreClient
}

func newObjectStoreGRPCClient(base *common.ClientBase, clientConn *grpc.ClientConn) any {
	return &ObjectStoreGRPCClient{
		ClientBase: base,
		grpcClient: proto.NewObjectStoreClient(clientConn),
	}
}

// Init prepares the ObjectStore for usage using the provided map of
// configuration key-value pairs. It returns an error if the ObjectStore
// cannot be initialized from the provided config.
func (c *ObjectStoreGRPCClient) Init(config map[string]string) error {
	req := &proto.ObjectStoreInitRequest{
		Plugin: c.Plugin,
		Config: config,
	}

	if _, err := c.grpcClient.Init(context.Background(), req); err != nil {
		return common.FromGRPCError(err)
	}

	return nil
}

// PutObject creates a new object using the data in body within the specified
// object storage bucket with the given key.
func (c *ObjectStoreGRPCClient) PutObject(bucket, key string, body io.Reader) error {
	stream, err := c.grpcClient.PutObject(context.Background())
	if err != nil {
		return common.FromGRPCError(err)
	}

	// read from the provider io.Reader into chunks, and send each one over
	// the gRPC stream
	chunk := make([]byte, byteChunkSize)
	for {
		n, err := body.Read(chunk)
		if err == io.EOF {
			if _, resErr := stream.CloseAndRecv(); resErr != nil {
				return common.FromGRPCError(resErr)
			}
			return nil
		}
		if err != nil {
			if err := stream.CloseSend(); err != nil {
				return common.FromGRPCError(err)
			}
			return errors.WithStack(err)
		}

		if err := stream.Send(&proto.PutObjectRequest{Plugin: c.Plugin, Bucket: bucket, Key: key, Body: chunk[0:n]}); err != nil {
			return common.FromGRPCError(err)
		}
	}
}

// ObjectExists checks if there is an object with the given key in the object storage bucket.
func (c *ObjectStoreGRPCClient) ObjectExists(bucket, key string) (bool, error) {
	req := &proto.ObjectExistsRequest{
		Plugin: c.Plugin,
		Bucket: bucket,
		Key:    key,
	}

	res, err := c.grpcClient.ObjectExists(context.Background(), req)
	if err != nil {
		return false, err
	}

	return res.Exists, nil
}

// GetObject retrieves the object with the given key from the specified
// bucket in object storage.
func (c *ObjectStoreGRPCClient) GetObject(bucket, key string) (io.ReadCloser, error) {
	req := &proto.GetObjectRequest{
		Plugin: c.Plugin,
		Bucket: bucket,
		Key:    key,
	}

	stream, err := c.grpcClient.GetObject(context.Background(), req)
	if err != nil {
		return nil, common.FromGRPCError(err)
	}

	receive := func() ([]byte, error) {
		data, err := stream.Recv()
		if err == io.EOF {
			// we need to return io.EOF errors unwrapped so that
			// calling code sees them as io.EOF and knows to stop
			// reading.
			return nil, err
		}
		if err != nil {
			return nil, common.FromGRPCError(err)
		}

		return data.Data, nil
	}

	close := func() error {
		if err := stream.CloseSend(); err != nil {
			return common.FromGRPCError(err)
		}
		return nil
	}

	return &StreamReadCloser{receive: receive, close: close}, nil
}

// ListCommonPrefixes gets a list of all object key prefixes that come
// after the provided prefix and before the provided delimiter (this is
// often used to simulate a directory hierarchy in object storage).
func (c *ObjectStoreGRPCClient) ListCommonPrefixes(bucket, prefix, delimiter string) ([]string, error) {
	req := &proto.ListCommonPrefixesRequest{
		Plugin:    c.Plugin,
		Bucket:    bucket,
		Prefix:    prefix,
		Delimiter: delimiter,
	}

	res, err := c.grpcClient.ListCommonPrefixes(context.Background(), req)
	if err != nil {
		return nil, common.FromGRPCError(err)
	}

	return res.Prefixes, nil
}

// ListObjects gets a list of all objects in bucket that have the same prefix.
func (c *ObjectStoreGRPCClient) ListObjects(bucket, prefix string) ([]string, error) {
	req := &proto.ListObjectsRequest{
		Plugin: c.Plugin,
		Bucket: bucket,
		Prefix: prefix,
	}

	res, err := c.grpcClient.ListObjects(context.Background(), req)
	if err != nil {
		return nil, common.FromGRPCError(err)
	}

	return res.Keys, nil
}

// DeleteObject removes object with the specified key from the given
// bucket.
func (c *ObjectStoreGRPCClient) DeleteObject(bucket, key string) error {
	req := &proto.DeleteObjectRequest{
		Plugin: c.Plugin,
		Bucket: bucket,
		Key:    key,
	}

	if _, err := c.grpcClient.DeleteObject(context.Background(), req); err != nil {
		return common.FromGRPCError(err)
	}

	return nil
}

// CreateSignedURL creates a pre-signed URL for the given bucket and key that expires after ttl.
func (c *ObjectStoreGRPCClient) CreateSignedURL(bucket, key string, ttl time.Duration) (string, error) {
	req := &proto.CreateSignedURLRequest{
		Plugin: c.Plugin,
		Bucket: bucket,
		Key:    key,
		Ttl:    int64(ttl),
	}

	res, err := c.grpcClient.CreateSignedURL(context.Background(), req)
	if err != nil {
		return "", common.FromGRPCError(err)
	}

	return res.Url, nil
}
