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
	"encoding/json"

	"context"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
	vsv1 "github.com/vmware-tanzu/velero/pkg/plugin/velero/volumesnapshotter/v1"
)

// VolumeSnapshotterGRPCServer implements the proto-generated VolumeSnapshotterServer interface, and accepts
// gRPC calls and forwards them to an implementation of the pluggable interface.
type VolumeSnapshotterGRPCServer struct {
	mux *common.ServerMux
}

func (s *VolumeSnapshotterGRPCServer) getImpl(name string) (vsv1.VolumeSnapshotter, error) {
	impl, err := s.mux.GetHandler(name)
	if err != nil {
		return nil, err
	}

	volumeSnapshotter, ok := impl.(vsv1.VolumeSnapshotter)
	if !ok {
		return nil, errors.Errorf("%T is not a volume snapshotter", impl)
	}

	return volumeSnapshotter, nil
}

// Init prepares the VolumeSnapshotter for usage using the provided map of
// configuration key-value pairs. It returns an error if the VolumeSnapshotter
// cannot be initialized from the provided config.
func (s *VolumeSnapshotterGRPCServer) Init(ctx context.Context, req *proto.VolumeSnapshotterInitRequest) (response *proto.Empty, err error) {
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

// CreateVolumeFromSnapshot creates a new block volume, initialized from the provided snapshot,
// and with the specified type and IOPS (if using provisioned IOPS).
func (s *VolumeSnapshotterGRPCServer) CreateVolumeFromSnapshot(ctx context.Context, req *proto.CreateVolumeRequest) (response *proto.CreateVolumeResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	snapshotID := req.SnapshotID
	volumeType := req.VolumeType
	volumeAZ := req.VolumeAZ
	var iops *int64

	if req.Iops != 0 {
		iops = &req.Iops
	}

	volumeID, err := impl.CreateVolumeFromSnapshot(snapshotID, volumeType, volumeAZ, iops)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.CreateVolumeResponse{VolumeID: volumeID}, nil
}

// GetVolumeInfo returns the type and IOPS (if using provisioned IOPS) for a specified block
// volume.
func (s *VolumeSnapshotterGRPCServer) GetVolumeInfo(ctx context.Context, req *proto.GetVolumeInfoRequest) (response *proto.GetVolumeInfoResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	volumeType, iops, err := impl.GetVolumeInfo(req.VolumeID, req.VolumeAZ)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	res := &proto.GetVolumeInfoResponse{
		VolumeType: volumeType,
	}

	if iops != nil {
		res.Iops = *iops
	}

	return res, nil
}

// CreateSnapshot creates a snapshot of the specified block volume, and applies the provided
// set of tags to the snapshot.
func (s *VolumeSnapshotterGRPCServer) CreateSnapshot(ctx context.Context, req *proto.CreateSnapshotRequest) (response *proto.CreateSnapshotResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	snapshotID, err := impl.CreateSnapshot(req.VolumeID, req.VolumeAZ, req.Tags)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.CreateSnapshotResponse{SnapshotID: snapshotID}, nil
}

// DeleteSnapshot deletes the specified volume snapshot.
func (s *VolumeSnapshotterGRPCServer) DeleteSnapshot(ctx context.Context, req *proto.DeleteSnapshotRequest) (response *proto.Empty, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	if err := impl.DeleteSnapshot(req.SnapshotID); err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.Empty{}, nil
}

func (s *VolumeSnapshotterGRPCServer) GetVolumeID(ctx context.Context, req *proto.GetVolumeIDRequest) (response *proto.GetVolumeIDResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	var pv unstructured.Unstructured

	if err := json.Unmarshal(req.PersistentVolume, &pv); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	volumeID, err := impl.GetVolumeID(&pv)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.GetVolumeIDResponse{VolumeID: volumeID}, nil
}

func (s *VolumeSnapshotterGRPCServer) SetVolumeID(ctx context.Context, req *proto.SetVolumeIDRequest) (response *proto.SetVolumeIDResponse, err error) {
	defer func() {
		if recoveredErr := common.HandlePanic(recover()); recoveredErr != nil {
			err = recoveredErr
		}
	}()

	impl, err := s.getImpl(req.Plugin)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	var pv unstructured.Unstructured
	if err := json.Unmarshal(req.PersistentVolume, &pv); err != nil {
		return nil, common.NewGRPCError(errors.WithStack(err))
	}

	updatedPV, err := impl.SetVolumeID(&pv, req.VolumeID)
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	updatedPVBytes, err := json.Marshal(updatedPV.UnstructuredContent())
	if err != nil {
		return nil, common.NewGRPCError(err)
	}

	return &proto.SetVolumeIDResponse{PersistentVolume: updatedPVBytes}, nil
}
