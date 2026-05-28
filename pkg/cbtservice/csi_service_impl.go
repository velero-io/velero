/*
Copyright The Velero Contributors.

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

package cbtservice

import (
	"context"
	"fmt"

	"github.com/kubernetes-csi/external-snapshot-metadata/pkg/iterator"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
)

var (
	buildClients        = iterator.BuildClients
	getSnapshotMetadata = iterator.GetSnapshotMetadata
)

type emitterImpl struct {
	logger         logrus.FieldLogger
	recordCallBack func([]Range) error
}

func (e *emitterImpl) SnapshotMetadataIteratorRecord(recordNumber int, metadata iterator.IteratorMetadata) error {
	for _, b := range metadata.BlockMetadata {
		// Offset and size should not be negative, if they are, it indicates some error in the metadata and we should return error to stop the iteration.
		if b.ByteOffset < 0 || b.SizeBytes < 0 {
			return fmt.Errorf("invalid CBT metadata: offset: %v, size %v", b.ByteOffset, b.SizeBytes)
		}

		e.logger.Debugf("recording metadata for record number %d, offset: %v, size: %v",
			recordNumber, b.ByteOffset, b.SizeBytes)

		if err := e.recordCallBack([]Range{{Offset: uint64(b.ByteOffset), Length: uint64(b.SizeBytes)}}); err != nil {
			return err
		}
	}

	return nil
}

func (e *emitterImpl) SnapshotMetadataIteratorDone(numberRecords int) error {
	e.logger.Infof("finished iterating snapshot metadata, total number of records: %d", numberRecords)

	return nil
}

type ServiceImpl struct {
	logger       logrus.FieldLogger
	vsNamespace  string
	SAName       string
	clientConfig *rest.Config
}

func NewService(
	logger logrus.FieldLogger,
	vsNamespace,
	saName string,
	clientConfig *rest.Config,
) Service {
	return &ServiceImpl{
		logger:       logger,
		vsNamespace:  vsNamespace,
		SAName:       saName,
		clientConfig: clientConfig,
	}
}

func (s *ServiceImpl) GetAllocatedBlocks(ctx context.Context, snapshot string, record func([]Range) error) error {
	clients, err := buildClients(s.clientConfig)
	if err != nil {
		return err
	}

	args := iterator.Args{
		SnapshotName: snapshot,
		Emitter: &emitterImpl{
			logger:         s.logger,
			recordCallBack: record,
		},

		Clients:         clients,
		Namespace:       s.vsNamespace, // DataUpload is created in the same namespace as Velero server. vsNamespace is the namespace of the Velero server.
		SANamespace:     s.vsNamespace, // The SA is created in the same namespace as Velero server. vsNamespace is the namespace of Velero	server.
		SAName:          s.SAName,
		TokenExpirySecs: iterator.DefaultTokenExpirySeconds,
		MaxResults:      0, // If 0 then the CSI driver decides the value.
	}

	return getSnapshotMetadata(ctx, args)
}

func (s *ServiceImpl) GetChangedBlocks(ctx context.Context, snapshot string, changeID string, record func([]Range) error) error {
	clients, err := buildClients(s.clientConfig)
	if err != nil {
		return err
	}

	args := iterator.Args{
		SnapshotName:     snapshot,
		PrevSnapshotName: changeID,
		Emitter: &emitterImpl{
			logger:         s.logger,
			recordCallBack: record,
		},

		Clients:         clients,
		Namespace:       s.vsNamespace,
		SANamespace:     s.vsNamespace,
		SAName:          s.SAName,
		TokenExpirySecs: iterator.DefaultTokenExpirySeconds,
		MaxResults:      0, // If 0 then the CSI driver decides the value.
	}

	return getSnapshotMetadata(ctx, args)
}
