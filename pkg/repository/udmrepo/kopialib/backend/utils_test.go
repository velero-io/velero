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

package backend

import (
	"testing"

	"github.com/kopia/kopia/repo/logging"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	storagemocks "github.com/velero-io/velero/pkg/repository/udmrepo/kopialib/backend/mocks"
)

func TestOptionalHaveBool(t *testing.T) {
	var expectMsg string
	testCases := []struct {
		name         string
		key          string
		flags        map[string]string
		logger       *storagemocks.Core
		retFuncCheck func(mock.Arguments)
		expectMsg    string
		retValue     bool
	}{
		{
			name:     "key not exist",
			key:      "fake-key",
			flags:    map[string]string{},
			retValue: false,
		},
		{
			name: "value valid",
			key:  "fake-key",
			flags: map[string]string{
				"fake-key": "true",
			},
			retValue: true,
		},
		{
			name: "value invalid",
			key:  "fake-key",
			flags: map[string]string{
				"fake-key": "fake-value",
			},
			logger: new(storagemocks.Core),
			retFuncCheck: func(args mock.Arguments) {
				ent := args[0].(zapcore.Entry)
				if ent.Level == zapcore.ErrorLevel {
					expectMsg = ent.Message
				}
			},
			expectMsg: "Ignore fake-key, value [fake-value] is invalid, err strconv.ParseBool: parsing \"fake-value\": invalid syntax",
			retValue:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.logger != nil {
				tc.logger.On("Enabled", mock.Anything).Return(true)
				tc.logger.On("Check", mock.Anything, mock.Anything).Run(tc.retFuncCheck).Return(&zapcore.CheckedEntry{})
			}

			ctx := logging.WithLogger(t.Context(), func(module string) logging.Logger {
				return zap.New(tc.logger).Sugar()
			})

			retValue := optionalHaveBool(ctx, tc.key, tc.flags)

			require.Equal(t, retValue, tc.retValue)
			require.Equal(t, tc.expectMsg, expectMsg)
		})
	}
}

func TestOptionalHaveIntWithDefault(t *testing.T) {
	var expectMsg string
	testCases := []struct {
		name         string
		key          string
		flags        map[string]string
		defaultValue int64
		logger       *storagemocks.Core
		retFuncCheck func(mock.Arguments)
		expectMsg    string
		retValue     int64
	}{
		{
			name:         "key not exist",
			key:          "fake-key",
			flags:        map[string]string{},
			defaultValue: 2000,
			retValue:     2000,
		},
		{
			name: "value valid",
			key:  "fake-key",
			flags: map[string]string{
				"fake-key": "1000",
			},
			retValue: 1000,
		},
		{
			name: "value invalid",
			key:  "fake-key",
			flags: map[string]string{
				"fake-key": "fake-value",
			},
			logger: new(storagemocks.Core),
			retFuncCheck: func(args mock.Arguments) {
				ent := args[0].(zapcore.Entry)
				if ent.Level == zapcore.ErrorLevel {
					expectMsg = ent.Message
				}
			},
			expectMsg:    "Ignore fake-key, value [fake-value] is invalid, err strconv.ParseInt: parsing \"fake-value\": invalid syntax",
			defaultValue: 2000,
			retValue:     2000,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.logger != nil {
				tc.logger.On("Enabled", mock.Anything).Return(true)
				tc.logger.On("Check", mock.Anything, mock.Anything).Run(tc.retFuncCheck).Return(&zapcore.CheckedEntry{})
			}

			ctx := logging.WithLogger(t.Context(), func(module string) logging.Logger {
				return zap.New(tc.logger).Sugar()
			})

			retValue := optionalHaveIntWithDefault(ctx, tc.key, tc.flags, tc.defaultValue)

			require.Equal(t, retValue, tc.retValue)
			require.Equal(t, tc.expectMsg, expectMsg)
		})
	}
}
