/*
Copyright 2018 the Velero contributors.

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
package process

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
)

type mockClientProtocol struct {
	mock.Mock
}

func (cp *mockClientProtocol) Close() error {
	args := cp.Called()
	return args.Error(0)
}

func (cp *mockClientProtocol) Dispense(name string) (any, error) {
	args := cp.Called(name)
	return args.Get(0), args.Error(1)
}

func (cp *mockClientProtocol) Ping() error {
	args := cp.Called()
	return args.Error(0)
}

type mockClientDispenser struct {
	mock.Mock
}

func (cd *mockClientDispenser) ClientFor(name string) any {
	args := cd.Called(name)
	return args.Get(0)
}

func TestDispense(t *testing.T) {
	tests := []struct {
		name            string
		missingKeyName  bool
		dispenseError   error
		clientDispenser bool
		expectedError   string
	}{
		{
			name:          "protocol client dispense error",
			dispenseError: errors.Errorf("protocol client dispense"),
			expectedError: "protocol client dispense",
		},
		{
			name: "plugin lister, no error",
		},
		{
			name:            "client dispenser, missing key name",
			clientDispenser: true,
			missingKeyName:  true,
			expectedError:   "ObjectStore plugin requested but name is missing",
		},
		{
			name:            "client dispenser, have key name",
			clientDispenser: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := new(process)
			protocolClient := new(mockClientProtocol)
			defer protocolClient.AssertExpectations(t)
			p.protocolClient = protocolClient

			clientDispenser := new(mockClientDispenser)
			defer clientDispenser.AssertExpectations(t)

			var client any

			key := KindAndName{}
			if tc.clientDispenser {
				key.Kind = common.PluginKindObjectStore
				protocolClient.On("Dispense", key.Kind.String()).Return(clientDispenser, tc.dispenseError)

				if !tc.missingKeyName {
					key.Name = "aws"
					client = &framework.BackupItemActionGRPCClient{}
					clientDispenser.On("ClientFor", key.Name).Return(client)
				}
			} else {
				key.Kind = common.PluginKindPluginLister
				client = &framework.PluginListerGRPCClient{}
				protocolClient.On("Dispense", key.Kind.String()).Return(client, tc.dispenseError)
			}

			dispensed, err := p.dispense(key)

			if tc.expectedError != "" {
				assert.EqualError(t, err, tc.expectedError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, client, dispensed)
		})
	}
}

func Test_removeFeaturesFlag(t *testing.T) {
	tests := []struct {
		name        string
		commandArgs []string
		want        []string
	}{
		{
			name:        "when commandArgs is nil, a nil slice is returned",
			commandArgs: nil,
			want:        nil,
		},
		{
			name:        "when commandArgs is empty, a nil slice is returned",
			commandArgs: []string{},
			want:        nil,
		},
		{
			name:        "when commandArgs does not contain --features, it is returned as-is",
			commandArgs: []string{"--log-level", "debug", "--another-flag", "foo"},
			want:        []string{"--log-level", "debug", "--another-flag", "foo"},
		},
		{
			name:        "when --features is the only flag, a nil slice is returned",
			commandArgs: []string{"--features", "EnableCSI"},
			want:        nil,
		},
		{
			name:        "when --features is the first flag, it's properly removed",
			commandArgs: []string{"--features", "EnableCSI", "--log-level", "debug", "--another-flag", "foo"},
			want:        []string{"--log-level", "debug", "--another-flag", "foo"},
		},
		{
			name:        "when --features is the last flag, it's properly removed",
			commandArgs: []string{"--log-level", "debug", "--another-flag", "foo", "--features", "EnableCSI"},
			want:        []string{"--log-level", "debug", "--another-flag", "foo"},
		},
		{
			name:        "when --features is neither the first nor last flag, it's properly removed",
			commandArgs: []string{"--log-level", "debug", "--features", "EnableCSI", "--another-flag", "foo"},
			want:        []string{"--log-level", "debug", "--another-flag", "foo"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, removeFeaturesFlag(tc.commandArgs))
		})
	}
}
