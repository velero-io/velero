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

package util

import (
	"reflect"
	"testing"

	"github.com/cockroachdb/errors"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
)

func TestStoreBackupConfig(t *testing.T) {
	config := &velerov1api.UploaderConfigForBackup{
		ParallelFilesUpload: 3,
	}

	expectedData := map[string]string{
		ParallelFilesUpload: "3",
	}

	result := StoreBackupConfig(config)

	if !reflect.DeepEqual(result, expectedData) {
		t.Errorf("Expected: %v, but got: %v", expectedData, result)
	}
}

func TestStoreRestoreConfig(t *testing.T) {
	var (
		boolTrue  = true
		boolFalse = false
	)
	testCases := []struct {
		name         string
		config       *velerov1api.UploaderConfigForRestore
		expectedData map[string]string
	}{
		{
			name: "WriteSparseFiles is true",
			config: &velerov1api.UploaderConfigForRestore{
				WriteSparseFiles: &boolTrue,
			},
			expectedData: map[string]string{
				WriteSparseFiles: "true",
				DeleteExtraFiles: "false",
			},
		},
		{
			name: "WriteSparseFiles is false",
			config: &velerov1api.UploaderConfigForRestore{
				WriteSparseFiles: &boolFalse,
			},
			expectedData: map[string]string{
				WriteSparseFiles: "false",
				DeleteExtraFiles: "false",
			},
		},
		{
			name: "WriteSparseFiles is nil",
			config: &velerov1api.UploaderConfigForRestore{
				WriteSparseFiles: nil,
			},
			expectedData: map[string]string{
				WriteSparseFiles: "false", // Assuming default value is false for nil case
				DeleteExtraFiles: "false",
			},
		},
		{
			name: "Parallel is set",
			config: &velerov1api.UploaderConfigForRestore{
				ParallelFilesDownload: 5,
			},
			expectedData: map[string]string{
				RestoreConcurrency: "5",
				WriteSparseFiles:   "false",
				DeleteExtraFiles:   "false",
			},
		},
		{
			name: "DeleteExtraFiles is true",
			config: &velerov1api.UploaderConfigForRestore{
				DeleteExtraFiles: &boolTrue,
			},
			expectedData: map[string]string{
				WriteSparseFiles: "false",
				DeleteExtraFiles: "true",
			},
		},
		{
			name: "DeleteExtraFiles is false",
			config: &velerov1api.UploaderConfigForRestore{
				DeleteExtraFiles: &boolFalse,
			},
			expectedData: map[string]string{
				WriteSparseFiles: "false",
				DeleteExtraFiles: "false",
			},
		},
		{
			name: "DeleteExtraFiles is nil",
			config: &velerov1api.UploaderConfigForRestore{
				DeleteExtraFiles: nil,
			},
			expectedData: map[string]string{
				WriteSparseFiles: "false",
				DeleteExtraFiles: "false", // Assuming default value is false for nil case
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := StoreRestoreConfig(tc.config)

			if !reflect.DeepEqual(result, tc.expectedData) {
				t.Errorf("Expected: %v, but got: %v", tc.expectedData, result)
			}
		})
	}
}

func TestGetParallelFilesUpload(t *testing.T) {
	tests := []struct {
		name           string
		uploaderCfg    map[string]string
		expectedResult int
		expectedError  error
	}{
		{
			name:           "Valid ParallelFilesUpload",
			uploaderCfg:    map[string]string{ParallelFilesUpload: "5"},
			expectedResult: 5,
			expectedError:  nil,
		},
		{
			name:           "Missing ParallelFilesUpload",
			uploaderCfg:    map[string]string{},
			expectedResult: 0,
			expectedError:  nil,
		},
		{
			name:           "Invalid ParallelFilesUpload (not a number)",
			uploaderCfg:    map[string]string{ParallelFilesUpload: "invalid"},
			expectedResult: 0,
			expectedError:  errors.Wrap(errors.New("strconv.Atoi: parsing \"invalid\": invalid syntax"), "failed to parse ParallelFilesUpload config"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := GetParallelFilesUpload(test.uploaderCfg)

			if result != test.expectedResult {
				t.Errorf("Expected result %d, but got %d", test.expectedResult, result)
			}

			if (err == nil && test.expectedError != nil) || (err != nil && test.expectedError == nil) || (err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error()) {
				t.Errorf("Expected error '%v', but got '%v'", test.expectedError, err)
			}
		})
	}
}

func TestGetWriteSparseFiles(t *testing.T) {
	tests := []struct {
		name           string
		uploaderCfg    map[string]string
		expectedResult bool
		expectedError  error
	}{
		{
			name:           "Valid WriteSparseFiles (true)",
			uploaderCfg:    map[string]string{WriteSparseFiles: "true"},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name:           "Valid WriteSparseFiles (false)",
			uploaderCfg:    map[string]string{WriteSparseFiles: "false"},
			expectedResult: false,
			expectedError:  nil,
		},
		{
			name:           "Invalid WriteSparseFiles (not a boolean)",
			uploaderCfg:    map[string]string{WriteSparseFiles: "invalid"},
			expectedResult: false,
			expectedError:  errors.Wrap(errors.New("strconv.ParseBool: parsing \"invalid\": invalid syntax"), "failed to parse WriteSparseFiles config"),
		},
		{
			name:           "Missing WriteSparseFiles",
			uploaderCfg:    map[string]string{},
			expectedResult: false,
			expectedError:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := GetWriteSparseFiles(test.uploaderCfg)

			if result != test.expectedResult {
				t.Errorf("Expected result %t, but got %t", test.expectedResult, result)
			}

			if (err == nil && test.expectedError != nil) || (err != nil && test.expectedError == nil) || (err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error()) {
				t.Errorf("Expected error '%v', but got '%v'", test.expectedError, err)
			}
		})
	}
}

func TestGetRestoreConcurrency(t *testing.T) {
	testCases := []struct {
		Name             string
		UploaderCfg      map[string]string
		ExpectedResult   int
		ExpectedError    bool
		ExpectedErrorMsg string
	}{
		{
			Name:           "Valid Configuration",
			UploaderCfg:    map[string]string{RestoreConcurrency: "10"},
			ExpectedResult: 10,
			ExpectedError:  false,
		},
		{
			Name:           "Missing Configuration",
			UploaderCfg:    map[string]string{},
			ExpectedResult: 0,
			ExpectedError:  false,
		},
		{
			Name:             "Invalid Configuration",
			UploaderCfg:      map[string]string{RestoreConcurrency: "not_an_integer"},
			ExpectedResult:   0,
			ExpectedError:    true,
			ExpectedErrorMsg: "failed to parse RestoreConcurrency config: strconv.Atoi: parsing \"not_an_integer\": invalid syntax",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			result, err := GetRestoreConcurrency(tc.UploaderCfg)

			if tc.ExpectedError {
				if err.Error() != tc.ExpectedErrorMsg {
					t.Errorf("Expected error message %s, but got %s", tc.ExpectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got %v", err)
				}
			}

			if result != tc.ExpectedResult {
				t.Errorf("Expected result %d, but got %d", tc.ExpectedResult, result)
			}
		})
	}
}

func TestGetDeleteExtraFiles(t *testing.T) {
	tests := []struct {
		name           string
		uploaderCfg    map[string]string
		expectedResult bool
		expectedError  error
	}{
		{
			name:           "Valid DeleteExtraFiles (true)",
			uploaderCfg:    map[string]string{DeleteExtraFiles: "true"},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			name:           "Valid DeleteExtraFiles (false)",
			uploaderCfg:    map[string]string{DeleteExtraFiles: "false"},
			expectedResult: false,
			expectedError:  nil,
		},
		{
			name:           "Invalid DeleteExtraFiles (not a boolean)",
			uploaderCfg:    map[string]string{DeleteExtraFiles: "invalid"},
			expectedResult: false,
			expectedError:  errors.Wrap(errors.New("strconv.ParseBool: parsing \"invalid\": invalid syntax"), "failed to parse DeleteExtraFiles config"),
		},
		{
			name:           "Missing DeleteExtraFiles",
			uploaderCfg:    map[string]string{},
			expectedResult: false,
			expectedError:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := GetDeleteExtraFiles(test.uploaderCfg)

			if result != test.expectedResult {
				t.Errorf("Expected result %t, but got %t", test.expectedResult, result)
			}

			if (err == nil && test.expectedError != nil) || (err != nil && test.expectedError == nil) || (err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error()) {
				t.Errorf("Expected error '%v', but got '%v'", test.expectedError, err)
			}
		})
	}
}
