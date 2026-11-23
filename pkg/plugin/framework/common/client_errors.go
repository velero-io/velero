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

package common

import (
	"google.golang.org/grpc/status"

	proto "github.com/velero-io/velero/pkg/plugin/generated"
)

// FromGRPCError takes a gRPC status error, extracts a stack trace
// from the details if it exists, and returns an error that can
// provide information about where it was created.
//
// This function should be used in the internal plugin client code to convert
// all errors returned from the plugin server before they're passed back to
// the rest of the Velero codebase. This will enable them to display location
// information when they're logged.
func FromGRPCError(err error) error {
	statusErr, ok := status.FromError(err)
	if !ok {
		return statusErr.Err()
	}

	for _, detail := range statusErr.Details() {
		if t, ok := detail.(*proto.Stack); ok {
			return &ProtoStackError{
				error: err,
				stack: t,
			}
		}
	}

	return err
}

type ProtoStackError struct {
	error
	stack *proto.Stack
}

func (e *ProtoStackError) File() string {
	if e.stack == nil || len(e.stack.Frames) < 1 {
		return ""
	}

	return e.stack.Frames[0].File
}

func (e *ProtoStackError) Line() int32 {
	if e.stack == nil || len(e.stack.Frames) < 1 {
		return 0
	}

	return e.stack.Frames[0].Line
}

func (e *ProtoStackError) Function() string {
	if e.stack == nil || len(e.stack.Frames) < 1 {
		return ""
	}

	return e.stack.Frames[0].Function
}
