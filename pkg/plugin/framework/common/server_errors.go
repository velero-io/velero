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
	"github.com/cockroachdb/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"

	proto "github.com/vmware-tanzu/velero/pkg/plugin/generated"
)

// NewGRPCErrorWithCode wraps err in a gRPC status error with the error's stack trace
// included in the details if it exists. This provides an easy way to send
// stack traces from plugin servers across the wire to the plugin client.
//
// This function should be used in the internal plugin server code to wrap
// all errors before they're returned.
func NewGRPCErrorWithCode(err error, code codes.Code, details ...protoadapt.MessageV1) error {
	// if it's already a gRPC status error, use it; otherwise, create a new one
	statusErr, ok := status.FromError(err)
	if !ok {
		statusErr = status.New(code, err.Error())
	}

	// get a Stack for the error and add it to details
	if stack := ErrorStack(err); stack != nil {
		details = append(details, stack)
	}

	statusErr, err = statusErr.WithDetails(details...)
	if err != nil {
		return status.Errorf(codes.Unknown, "error adding details to the gRPC error: %v", err)
	}

	return statusErr.Err()
}

// NewGRPCError is a convenience function for creating a new gRPC error
// with code = codes.Unknown
func NewGRPCError(err error, details ...protoadapt.MessageV1) error {
	return NewGRPCErrorWithCode(err, codes.Unknown, details...)
}

// ErrorStack gets a stack trace, if it exists, from the provided error, and
// returns it as a *proto.Stack.
func ErrorStack(err error) *proto.Stack {
	stack := errors.GetReportableStackTrace(err)
	if stack == nil {
		return nil
	}

	stackTrace := new(proto.Stack)
	for _, frame := range stack.Frames {
		stackTrace.Frames = append(stackTrace.Frames, &proto.StackFrame{
			File:     frame.Filename,
			Line:     int32(frame.Lineno),
			Function: frame.Function,
		})
	}

	return stackTrace
}
