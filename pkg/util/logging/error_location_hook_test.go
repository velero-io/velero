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

package logging

import (
	"errors"
	"testing"

	pkgerrs "github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFire(t *testing.T) {
	tests := []struct {
		name                string
		preEntryFields      map[string]any
		expectedEntryFields map[string]any
		expectedErr         bool
	}{
		{
			name:                "no error",
			preEntryFields:      map[string]any{"foo": "bar"},
			expectedEntryFields: map[string]any{"foo": "bar"},
		},
		{
			name:                "basic (non-pkg/errors) error",
			preEntryFields:      map[string]any{logrus.ErrorKey: errors.New("a normal error")},
			expectedEntryFields: map[string]any{logrus.ErrorKey: errors.New("a normal error")},
		},
		{
			name:                "non-error logged in error field",
			preEntryFields:      map[string]any{logrus.ErrorKey: "not an error"},
			expectedEntryFields: map[string]any{logrus.ErrorKey: "not an error"},
			expectedErr:         false,
		},
		{
			name:           "pkg/errors error",
			preEntryFields: map[string]any{logrus.ErrorKey: pkgerrs.New("a pkg/errors error")},
			expectedEntryFields: map[string]any{
				logrus.ErrorKey:    pkgerrs.New("a pkg/errors error"),
				errorFileField:     "",
				errorFunctionField: "github.com/vmware-tanzu/velero/pkg/util/logging.TestFire",
			},
		},
		{
			name: "already have error file and function fields",
			preEntryFields: map[string]any{
				logrus.ErrorKey:    pkgerrs.New("a pkg/errors error"),
				errorFileField:     "some_file.go:123",
				errorFunctionField: "SomeFunction",
			},
			expectedEntryFields: map[string]any{
				logrus.ErrorKey:    pkgerrs.New("a pkg/errors error"),
				errorFileField:     "some_file.go:123",
				errorFunctionField: "SomeFunction",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hook := &ErrorLocationHook{}

			entry := &logrus.Entry{
				Data: logrus.Fields(test.preEntryFields),
			}

			// method under test
			err := hook.Fire(entry)

			require.Equal(t, test.expectedErr, err != nil)
			require.Len(t, entry.Data, len(test.expectedEntryFields))

			for key, expectedValue := range test.expectedEntryFields {
				actualValue, found := entry.Data[key]
				assert.True(t, found, "expected key not found: %s", key)

				switch key {
				// test existence of this field only since testing the value
				// is fragile
				case errorFileField:
				case errorFunctionField:
				case logrus.ErrorKey:
					if err, ok := expectedValue.(error); ok {
						assert.Equal(t, err.Error(), actualValue.(error).Error())
					} else {
						assert.Equal(t, expectedValue, actualValue)
					}
				default:
					assert.Equal(t, expectedValue, actualValue)
				}
			}
		})
	}
}
