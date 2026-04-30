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

	"github.com/pkg/errors"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

// ObjectStoreGRPCServer implements the proto-generated ObjectStoreServer interface, and accepts
// gRPC calls and forwards them to an implementation of the pluggable interface.
type ObjectStoreGRPCServer struct {
	mux *common.ServerMux
}

func (s *ObjectStoreGRPCServer) getImpl(name string) (velero.ObjectStore, error) {
	impl, err := s.mux.GetHandler(name)
	if err != nil {
		return nil, err
	}

	itemAction, ok := impl.(velero.ObjectStore)
	if !ok {
		return nil, errors.Errorf("%T is not an object store", impl)
	}

	return itemAction, nil
}

// Init prepares the ObjectStore for usage using the provided map of
// configuration key-value pairs. It returns an error if the ObjectStore
// cannot be initialized from the provided config.
func (s *ObjectStoreGRPCServer) Init(ctx context.Context, req *proto.ObjectStoreInitRequest) (response *proto.Empty, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	if err := impl.Init(req.Config); err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.Empty{}, nil
}

// PutObject creates a new object using the data in body within the specified
// object storage bucket with the given key.
func (s *ObjectStoreGRPCServer) PutObject(stream proto.ObjectStore_PutObjectServer) (err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	// we need to read the first chunk ahead of time to get the bucket and key;
	// in our receive method, we'll use `first` on the first call
	firstChunk, err := stream.Recv()
	if err != nil {
		return common.NewGRPCError(errors.WithStack(err))
	}

	impl, err := s.getImpl(firstChunk.Plugin)
	if err != nil {
		return common.NewGRPCError(err)
	}

	bucket := firstChunk.Bucket
	key := firstChunk.Key

	receive := func() ([]byte, error) {
		if firstChunk != nil {
			res := firstChunk.Body
			firstChunk = nil
			return res, nil
		}

		data, err := stream.Recv()
		if err == io.EOF {
			// we need to return io.EOF errors unwrapped so that
			// calling code sees them as io.EOF and knows to stop
			// reading.
			return nil, err
		}
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return data.Body, nil
	}

	close := func() error {
		return nil
	}

	if err := impl.PutObject(bucket, key, &StreamReadCloser{receive: receive, close: close}); err != nil {
		return common.NewGRPCError(err)
	}

	if err := stream.SendAndClose(&proto.Empty{}); err != nil {
		return common.NewGRPCError(errors.WithStack(err))
	}

	return nil
}

// ObjectExists checks if there is an object with the given key in the object storage bucket.
func (s *ObjectStoreGRPCServer) ObjectExists(ctx context.Context, req *proto.ObjectExistsRequest) (response *proto.ObjectExistsResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	exists, err := impl.ObjectExists(req.Bucket, req.Key)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.ObjectExistsResponse{Exists: exists}, nil
}

// GetObject retrieves the object with the given key from the specified
// bucket in object storage.
func (s *ObjectStoreGRPCServer) GetObject(req *proto.GetObjectRequest, stream proto.ObjectStore_GetObjectServer) (err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return common.NewGRPCError(err)
	}

	rdr, err := impl.GetObject(req.Bucket, req.Key)
	if err != nil {
		return common.NewGRPCError(err)
	}
	defer rdr.Close()

	chunk := make([]byte, byteChunkSize)
	for {
		n, err := rdr.Read(chunk)
		if err != nil && err != io.EOF {
			return common.NewGRPCError(errors.WithStack(err))
		}
		if n == 0 {
			return nil
		}

		if err := stream.Send(&proto.Bytes{Data: chunk[0:n]}); err != nil {
			return common.NewGRPCError(errors.WithStack(err))
		}
	}
}

// ListCommonPrefixes gets a list of all object key prefixes that start with
// the specified prefix and stop at the next instance of the provided delimiter
// (this is often used to simulate a directory hierarchy in object storage).
func (s *ObjectStoreGRPCServer) ListCommonPrefixes(ctx context.Context, req *proto.ListCommonPrefixesRequest) (response *proto.ListCommonPrefixesResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	prefixes, err := impl.ListCommonPrefixes(req.Bucket, req.Prefix, req.Delimiter)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.ListCommonPrefixesResponse{Prefixes: prefixes}, nil
}

// ListObjects gets a list of all objects in bucket that have the same prefix.
func (s *ObjectStoreGRPCServer) ListObjects(ctx context.Context, req *proto.ListObjectsRequest) (response *proto.ListObjectsResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	keys, err := impl.ListObjects(req.Bucket, req.Prefix)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.ListObjectsResponse{Keys: keys}, nil
}

// DeleteObject removes object with the specified key from the given
// bucket.
func (s *ObjectStoreGRPCServer) DeleteObject(ctx context.Context, req *proto.DeleteObjectRequest) (response *proto.Empty, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	if err := impl.DeleteObject(req.Bucket, req.Key); err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.Empty{}, nil
}

// CreateSignedURL creates a pre-signed URL for the given bucket and key that expires after ttl.
func (s *ObjectStoreGRPCServer) CreateSignedURL(ctx context.Context, req *proto.CreateSignedURLRequest) (response *proto.CreateSignedURLResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	url, err := impl.CreateSignedURL(req.Bucket, req.Key, time.Duration(req.Ttl))
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.CreateSignedURLResponse{Url: url}, nil
}
