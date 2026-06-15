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
package restartabletest

import (
	"reflect"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
)

type MockRestartableProcess struct {
	mock.Mock
}

func (rp *MockRestartableProcess) AddReinitializer(key process.KindAndName, r process.Reinitializer) {
	rp.Called(key, r)
}

func (rp *MockRestartableProcess) Reset() error {
	args := rp.Called()
	return args.Error(0)
}

func (rp *MockRestartableProcess) ResetIfNeeded() error {
	args := rp.Called()
	return args.Error(0)
}

func (rp *MockRestartableProcess) GetByKindAndName(key process.KindAndName) (any, error) {
	args := rp.Called(key)
	return args.Get(0), args.Error(1)
}

func (rp *MockRestartableProcess) Stop() {
	rp.Called()
}

type RestartableDelegateTest struct {
	Function                string
	Inputs                  []any
	ExpectedErrorOutputs    []any
	ExpectedDelegateOutputs []any
}

type Mockable interface {
	Test(t mock.TestingT)
	On(method string, args ...any) *mock.Call
	AssertExpectations(t mock.TestingT) bool
}

func RunRestartableDelegateTests(
	t *testing.T,
	kind common.PluginKind,
	newRestartable func(key process.KindAndName, p process.RestartableProcess) any,
	newMock func() Mockable,
	tests ...RestartableDelegateTest,
) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.Function, func(t *testing.T) {
			p := new(MockRestartableProcess)
			p.Test(t)
			defer p.AssertExpectations(t)

			// getDelegate error
			p.On("ResetIfNeeded").Return(errors.Errorf("reset error")).Once()
			name := "delegateName"
			key := process.KindAndName{Kind: kind, Name: name}
			r := newRestartable(key, p)

			// Get the method we're going to call using reflection
			method := reflect.ValueOf(r).MethodByName(tc.Function)
			require.NotEmpty(t, method)

			// Convert the test case inputs ([]any) to []reflect.Value
			var inputValues []reflect.Value
			for i := range tc.Inputs {
				inputValues = append(inputValues, reflect.ValueOf(tc.Inputs[i]))
			}

			// Invoke the method being tested
			actual := method.Call(inputValues)

			// This Function asserts that the actual outputs match the expected outputs
			checkOutputs := func(expected []any, actual []reflect.Value) {
				require.Len(t, actual, len(expected))

				for i := range actual {
					// Get the underlying value from the reflect.Value
					a := actual[i].Interface()

					// Check if it's an error
					actualErr, actualErrOk := a.(error)
					// Check if the expected output element is an error
					expectedErr, expectedErrOk := expected[i].(error)
					// If both are errors, use EqualError
					if actualErrOk && expectedErrOk {
						require.EqualError(t, actualErr, expectedErr.Error())
						continue
					}

					// If Function returns nil as struct return type, we cannot just
					// compare the interface to nil as its type will not be nil,
					// only the value will be
					if expected[i] == nil && reflect.ValueOf(a).Kind() == reflect.Pointer {
						assert.True(t, reflect.ValueOf(a).IsNil())
						continue
					}

					// Otherwise, use plain Equal
					assert.Equal(t, expected[i], a)
				}
			}

			// Make sure we get what we expected when getDelegate returned an error
			checkOutputs(tc.ExpectedErrorOutputs, actual)

			// Invoke delegate, make sure all returned values are passed through
			p.On("ResetIfNeeded").Return(nil)

			delegate := newMock()
			delegate.Test(t)
			defer delegate.AssertExpectations(t)

			p.On("GetByKindAndName", key).Return(delegate, nil)

			// Set up the mocked method in the delegate
			delegate.On(tc.Function, tc.Inputs...).Return(tc.ExpectedDelegateOutputs...)

			// Invoke the method being tested
			actual = method.Call(inputValues)

			// Make sure we get what we expected when invoking the delegate
			checkOutputs(tc.ExpectedDelegateOutputs, actual)
		})
	}
}
