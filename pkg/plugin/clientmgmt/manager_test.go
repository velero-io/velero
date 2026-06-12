/*
Copyright 2020 the Velero contributors.

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

package clientmgmt

import (
	"fmt"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/vmware-tanzu/velero/internal/restartabletest"
	biav1cli "github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/backupitemaction/v1"
	biav2cli "github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/backupitemaction/v2"
	ibav1cli "github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/itemblockaction/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/process"
	riav1cli "github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/restoreitemaction/v1"
	riav2cli "github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/restoreitemaction/v2"
	vsv1cli "github.com/vmware-tanzu/velero/pkg/plugin/clientmgmt/volumesnapshotter/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/test"
)

type mockRegistry struct {
	mock.Mock
}

func (r *mockRegistry) DiscoverPlugins() error {
	args := r.Called()
	return args.Error(0)
}

func (r *mockRegistry) List(kind common.PluginKind) []framework.PluginIdentifier {
	args := r.Called(kind)
	return args.Get(0).([]framework.PluginIdentifier)
}

func (r *mockRegistry) Get(kind common.PluginKind, name string) (framework.PluginIdentifier, error) {
	args := r.Called(kind, name)
	var id framework.PluginIdentifier
	if args.Get(0) != nil {
		id = args.Get(0).(framework.PluginIdentifier)
	}
	return id, args.Error(1)
}

func TestNewManager(t *testing.T) {
	logger := test.NewLogger()
	logLevel := logrus.InfoLevel

	registry := &mockRegistry{}
	defer registry.AssertExpectations(t)

	m := NewManager(logger, logLevel, registry).(*manager)
	assert.Equal(t, logger, m.logger)
	assert.Equal(t, logLevel, m.logLevel)
	assert.Equal(t, registry, m.registry)
	assert.NotNil(t, m.restartableProcesses)
	assert.Empty(t, m.restartableProcesses)
}

type mockRestartableProcessFactory struct {
	mock.Mock
}

func (f *mockRestartableProcessFactory) NewRestartableProcess(command string, logger logrus.FieldLogger, logLevel logrus.Level) (process.RestartableProcess, error) {
	args := f.Called(command, logger, logLevel)
	var rp process.RestartableProcess
	if args.Get(0) != nil {
		rp = args.Get(0).(process.RestartableProcess)
	}
	return rp, args.Error(1)
}

func TestGetRestartableProcess(t *testing.T) {
	logger := test.NewLogger()
	logLevel := logrus.InfoLevel

	registry := &mockRegistry{}
	defer registry.AssertExpectations(t)

	m := NewManager(logger, logLevel, registry).(*manager)
	factory := &mockRestartableProcessFactory{}
	defer factory.AssertExpectations(t)
	m.restartableProcessFactory = factory

	// Test 1: registry error
	pluginKind := common.PluginKindBackupItemAction
	pluginName := "pod"
	registry.On("Get", pluginKind, pluginName).Return(nil, errors.Errorf("registry")).Once()
	rp, err := m.getRestartableProcess(pluginKind, pluginName)
	assert.Nil(t, rp)
	require.EqualError(t, err, "registry")

	// Test 2: registry ok, factory error
	podID := framework.PluginIdentifier{
		Command: "/command",
		Kind:    pluginKind,
		Name:    pluginName,
	}
	registry.On("Get", pluginKind, pluginName).Return(podID, nil)
	factory.On("NewRestartableProcess", podID.Command, logger, logLevel).Return(nil, errors.Errorf("factory")).Once()
	rp, err = m.getRestartableProcess(pluginKind, pluginName)
	assert.Nil(t, rp)
	require.EqualError(t, err, "factory")

	// Test 3: registry ok, factory ok
	restartableProcess := &restartabletest.MockRestartableProcess{}
	defer restartableProcess.AssertExpectations(t)
	factory.On("NewRestartableProcess", podID.Command, logger, logLevel).Return(restartableProcess, nil).Once()
	rp, err = m.getRestartableProcess(pluginKind, pluginName)
	require.NoError(t, err)
	assert.Equal(t, restartableProcess, rp)

	// Test 4: retrieve from cache
	rp, err = m.getRestartableProcess(pluginKind, pluginName)
	require.NoError(t, err)
	assert.Equal(t, restartableProcess, rp)
}

func TestCleanupClients(t *testing.T) {
	logger := test.NewLogger()
	logLevel := logrus.InfoLevel

	registry := &mockRegistry{}
	defer registry.AssertExpectations(t)

	m := NewManager(logger, logLevel, registry).(*manager)

	for i := 0; i < 5; i++ {
		rp := &restartabletest.MockRestartableProcess{}
		defer rp.AssertExpectations(t)
		rp.On("Stop")
		m.restartableProcesses[fmt.Sprintf("rp%d", i)] = rp
	}

	m.CleanupClients()
}

func TestGetObjectStore(t *testing.T) {
	getPluginTest(t,
		common.PluginKindObjectStore,
		"velero.io/aws",
		func(m Manager, name string) (any, error) {
			return m.GetObjectStore(name)
		},
		func(name string, sharedPluginProcess process.RestartableProcess) any {
			return &restartableObjectStore{
				key:                 process.KindAndName{Kind: common.PluginKindObjectStore, Name: name},
				sharedPluginProcess: sharedPluginProcess,
			}
		},
		true,
	)
}

func TestGetVolumeSnapshotter(t *testing.T) {
	getPluginTest(t,
		common.PluginKindVolumeSnapshotter,
		"velero.io/aws",
		func(m Manager, name string) (any, error) {
			return m.GetVolumeSnapshotter(name)
		},
		func(name string, sharedPluginProcess process.RestartableProcess) any {
			return &vsv1cli.RestartableVolumeSnapshotter{
				Key:                 process.KindAndName{Kind: common.PluginKindVolumeSnapshotter, Name: name},
				SharedPluginProcess: sharedPluginProcess,
			}
		},
		true,
	)
}

func TestGetBackupItemAction(t *testing.T) {
	getPluginTest(t,
		common.PluginKindBackupItemAction,
		"velero.io/pod",
		func(m Manager, name string) (any, error) {
			return m.GetBackupItemAction(name)
		},
		func(name string, sharedPluginProcess process.RestartableProcess) any {
			return &biav1cli.RestartableBackupItemAction{
				Key:                 process.KindAndName{Kind: common.PluginKindBackupItemAction, Name: name},
				SharedPluginProcess: sharedPluginProcess,
			}
		},
		false,
	)
}

func TestGetBackupItemActionV2(t *testing.T) {
	getPluginTest(t,
		common.PluginKindBackupItemActionV2,
		"velero.io/pod",
		func(m Manager, name string) (any, error) {
			return m.GetBackupItemActionV2(name)
		},
		func(name string, sharedPluginProcess process.RestartableProcess) any {
			return &biav2cli.RestartableBackupItemAction{
				Key:                 process.KindAndName{Kind: common.PluginKindBackupItemActionV2, Name: name},
				SharedPluginProcess: sharedPluginProcess,
			}
		},
		false,
	)
}

func TestGetRestoreItemAction(t *testing.T) {
	getPluginTest(t,
		common.PluginKindRestoreItemAction,
		"velero.io/pod",
		func(m Manager, name string) (any, error) {
			return m.GetRestoreItemAction(name)
		},
		func(name string, sharedPluginProcess process.RestartableProcess) any {
			return &riav1cli.RestartableRestoreItemAction{
				Key:                 process.KindAndName{Kind: common.PluginKindRestoreItemAction, Name: name},
				SharedPluginProcess: sharedPluginProcess,
			}
		},
		false,
	)
}

func TestGetRestoreItemActionV2(t *testing.T) {
	getPluginTest(t,
		common.PluginKindRestoreItemActionV2,
		"velero.io/pod",
		func(m Manager, name string) (any, error) {
			return m.GetRestoreItemActionV2(name)
		},
		func(name string, sharedPluginProcess process.RestartableProcess) any {
			return &riav2cli.RestartableRestoreItemAction{
				Key:                 process.KindAndName{Kind: common.PluginKindRestoreItemActionV2, Name: name},
				SharedPluginProcess: sharedPluginProcess,
			}
		},
		false,
	)
}

func TestGetItemBlockAction(t *testing.T) {
	getPluginTest(t,
		common.PluginKindItemBlockAction,
		"velero.io/pod",
		func(m Manager, name string) (any, error) {
			return m.GetItemBlockAction(name)
		},
		func(name string, sharedPluginProcess process.RestartableProcess) any {
			return &ibav1cli.RestartableItemBlockAction{
				Key:                 process.KindAndName{Kind: common.PluginKindItemBlockAction, Name: name},
				SharedPluginProcess: sharedPluginProcess,
			}
		},
		false,
	)
}

func getPluginTest(
	t *testing.T,
	kind common.PluginKind,
	name string,
	getPluginFunc func(m Manager, name string) (any, error),
	expectedResultFunc func(name string, sharedPluginProcess process.RestartableProcess) any,
	reinitializable bool,
) {
	t.Helper()
	logger := test.NewLogger()
	logLevel := logrus.InfoLevel

	registry := &mockRegistry{}
	defer registry.AssertExpectations(t)

	m := NewManager(logger, logLevel, registry).(*manager)
	factory := &mockRestartableProcessFactory{}
	defer factory.AssertExpectations(t)
	m.restartableProcessFactory = factory

	pluginKind := kind
	pluginName := name
	pluginID := framework.PluginIdentifier{
		Command: "/command",
		Kind:    pluginKind,
		Name:    pluginName,
	}
	registry.On("Get", pluginKind, pluginName).Return(pluginID, nil)

	restartableProcess := &restartabletest.MockRestartableProcess{}
	defer restartableProcess.AssertExpectations(t)

	// Test 1: error getting restartable process
	factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(nil, errors.Errorf("NewRestartableProcess")).Once()
	actual, err := getPluginFunc(m, pluginName)
	assert.Nil(t, actual)
	require.EqualError(t, err, "NewRestartableProcess")

	// Test 2: happy path
	factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(restartableProcess, nil).Once()

	expected := expectedResultFunc(name, restartableProcess)
	if reinitializable {
		key := process.KindAndName{Kind: pluginID.Kind, Name: pluginID.Name}
		restartableProcess.On("AddReinitializer", key, expected)
	}

	actual, err = getPluginFunc(m, pluginName)
	require.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestGetBackupItemActions(t *testing.T) {
	tests := []struct {
		name                       string
		names                      []string
		newRestartableProcessError error
		expectedError              string
	}{
		{
			name:  "No items",
			names: []string{},
		},
		{
			name:                       "Error getting restartable process",
			names:                      []string{"velero.io/a", "velero.io/b", "velero.io/c"},
			newRestartableProcessError: errors.Errorf("NewRestartableProcess"),
			expectedError:              "NewRestartableProcess",
		},
		{
			name:  "Happy path",
			names: []string{"velero.io/a", "velero.io/b", "velero.io/c"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := test.NewLogger()
			logLevel := logrus.InfoLevel

			registry := &mockRegistry{}
			defer registry.AssertExpectations(t)

			m := NewManager(logger, logLevel, registry).(*manager)
			factory := &mockRestartableProcessFactory{}
			defer factory.AssertExpectations(t)
			m.restartableProcessFactory = factory

			pluginKind := common.PluginKindBackupItemAction
			var pluginIDs []framework.PluginIdentifier
			for i := range tc.names {
				pluginID := framework.PluginIdentifier{
					Command: "/command",
					Kind:    pluginKind,
					Name:    tc.names[i],
				}
				pluginIDs = append(pluginIDs, pluginID)
			}
			registry.On("List", pluginKind).Return(pluginIDs)

			var expectedActions []any
			for i := range pluginIDs {
				pluginID := pluginIDs[i]
				pluginName := pluginID.Name

				registry.On("Get", pluginKind, pluginName).Return(pluginID, nil)

				restartableProcess := &restartabletest.MockRestartableProcess{}
				defer restartableProcess.AssertExpectations(t)

				expected := &biav1cli.RestartableBackupItemAction{
					Key:                 process.KindAndName{Kind: pluginKind, Name: pluginName},
					SharedPluginProcess: restartableProcess,
				}

				if tc.newRestartableProcessError != nil {
					// Test 1: error getting restartable process
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(nil, errors.Errorf("NewRestartableProcess")).Once()
					break
				}

				// Test 2: happy path
				if i == 0 {
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(restartableProcess, nil).Once()
				}

				expectedActions = append(expectedActions, expected)
			}

			backupItemActions, err := m.GetBackupItemActions()
			if tc.newRestartableProcessError != nil {
				assert.Nil(t, backupItemActions)
				assert.EqualError(t, err, "NewRestartableProcess")
			} else {
				require.NoError(t, err)
				var actual []any
				for i := range backupItemActions {
					actual = append(actual, backupItemActions[i])
				}
				assert.Equal(t, expectedActions, actual)
			}
		})
	}
}

func TestGetBackupItemActionsV2(t *testing.T) {
	tests := []struct {
		name                       string
		names                      []string
		newRestartableProcessError error
		expectedError              string
	}{
		{
			name:  "No items",
			names: []string{},
		},
		{
			name:                       "Error getting restartable process",
			names:                      []string{"velero.io/a", "velero.io/b", "velero.io/c"},
			newRestartableProcessError: errors.Errorf("NewRestartableProcess"),
			expectedError:              "NewRestartableProcess",
		},
		{
			name:  "Happy path",
			names: []string{"velero.io/a", "velero.io/b", "velero.io/c"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := test.NewLogger()
			logLevel := logrus.InfoLevel

			registry := &mockRegistry{}
			defer registry.AssertExpectations(t)

			m := NewManager(logger, logLevel, registry).(*manager)
			factory := &mockRestartableProcessFactory{}
			defer factory.AssertExpectations(t)
			m.restartableProcessFactory = factory

			pluginKind := common.PluginKindBackupItemActionV2
			var pluginIDs []framework.PluginIdentifier
			for i := range tc.names {
				pluginID := framework.PluginIdentifier{
					Command: "/command",
					Kind:    pluginKind,
					Name:    tc.names[i],
				}
				pluginIDs = append(pluginIDs, pluginID)
			}
			registry.On("List", pluginKind).Return(pluginIDs)

			var expectedActions []any
			for i := range pluginIDs {
				pluginID := pluginIDs[i]
				pluginName := pluginID.Name

				registry.On("Get", pluginKind, pluginName).Return(pluginID, nil)

				restartableProcess := &restartabletest.MockRestartableProcess{}
				defer restartableProcess.AssertExpectations(t)

				expected := &biav2cli.RestartableBackupItemAction{
					Key:                 process.KindAndName{Kind: pluginKind, Name: pluginName},
					SharedPluginProcess: restartableProcess,
				}

				if tc.newRestartableProcessError != nil {
					// Test 1: error getting restartable process
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(nil, errors.Errorf("NewRestartableProcess")).Once()
					break
				}

				// Test 2: happy path
				if i == 0 {
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(restartableProcess, nil).Once()
				}

				expectedActions = append(expectedActions, expected)
			}

			backupItemActions, err := m.GetBackupItemActionsV2()
			if tc.newRestartableProcessError != nil {
				assert.Nil(t, backupItemActions)
				assert.EqualError(t, err, "NewRestartableProcess")
			} else {
				require.NoError(t, err)
				var actual []any
				for i := range backupItemActions {
					actual = append(actual, backupItemActions[i])
				}
				assert.Equal(t, expectedActions, actual)
			}
		})
	}
}

func TestGetRestoreItemActions(t *testing.T) {
	tests := []struct {
		name                       string
		names                      []string
		newRestartableProcessError error
		expectedError              string
	}{
		{
			name:  "No items",
			names: []string{},
		},
		{
			name:                       "Error getting restartable process",
			names:                      []string{"velero.io/a", "velero.io/b", "velero.io/c"},
			newRestartableProcessError: errors.Errorf("NewRestartableProcess"),
			expectedError:              "NewRestartableProcess",
		},
		{
			name:  "Happy path",
			names: []string{"velero.io/a", "velero.io/b", "velero.io/c"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := test.NewLogger()
			logLevel := logrus.InfoLevel

			registry := &mockRegistry{}
			defer registry.AssertExpectations(t)

			m := NewManager(logger, logLevel, registry).(*manager)
			factory := &mockRestartableProcessFactory{}
			defer factory.AssertExpectations(t)
			m.restartableProcessFactory = factory

			pluginKind := common.PluginKindRestoreItemAction
			var pluginIDs []framework.PluginIdentifier
			for i := range tc.names {
				pluginID := framework.PluginIdentifier{
					Command: "/command",
					Kind:    pluginKind,
					Name:    tc.names[i],
				}
				pluginIDs = append(pluginIDs, pluginID)
			}
			registry.On("List", pluginKind).Return(pluginIDs)

			var expectedActions []any
			for i := range pluginIDs {
				pluginID := pluginIDs[i]
				pluginName := pluginID.Name

				registry.On("Get", pluginKind, pluginName).Return(pluginID, nil)

				restartableProcess := &restartabletest.MockRestartableProcess{}
				defer restartableProcess.AssertExpectations(t)

				expected := &riav1cli.RestartableRestoreItemAction{
					Key:                 process.KindAndName{Kind: pluginKind, Name: pluginName},
					SharedPluginProcess: restartableProcess,
				}

				if tc.newRestartableProcessError != nil {
					// Test 1: error getting restartable process
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(nil, errors.Errorf("NewRestartableProcess")).Once()
					break
				}

				// Test 2: happy path
				if i == 0 {
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(restartableProcess, nil).Once()
				}

				expectedActions = append(expectedActions, expected)
			}

			restoreItemActions, err := m.GetRestoreItemActions()
			if tc.newRestartableProcessError != nil {
				assert.Nil(t, restoreItemActions)
				assert.EqualError(t, err, "NewRestartableProcess")
			} else {
				require.NoError(t, err)
				var actual []any
				for i := range restoreItemActions {
					actual = append(actual, restoreItemActions[i])
				}
				assert.Equal(t, expectedActions, actual)
			}
		})
	}
}

func TestGetRestoreItemActionsV2(t *testing.T) {
	tests := []struct {
		name                       string
		names                      []string
		newRestartableProcessError error
		expectedError              string
	}{
		{
			name:  "No items",
			names: []string{},
		},
		{
			name:                       "Error getting restartable process",
			names:                      []string{"velero.io/a", "velero.io/b", "velero.io/c"},
			newRestartableProcessError: errors.Errorf("NewRestartableProcess"),
			expectedError:              "NewRestartableProcess",
		},
		{
			name:  "Happy path",
			names: []string{"velero.io/a", "velero.io/b", "velero.io/c"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := test.NewLogger()
			logLevel := logrus.InfoLevel

			registry := &mockRegistry{}
			defer registry.AssertExpectations(t)

			m := NewManager(logger, logLevel, registry).(*manager)
			factory := &mockRestartableProcessFactory{}
			defer factory.AssertExpectations(t)
			m.restartableProcessFactory = factory

			pluginKind := common.PluginKindRestoreItemActionV2
			var pluginIDs []framework.PluginIdentifier
			for i := range tc.names {
				pluginID := framework.PluginIdentifier{
					Command: "/command",
					Kind:    pluginKind,
					Name:    tc.names[i],
				}
				pluginIDs = append(pluginIDs, pluginID)
			}
			registry.On("List", pluginKind).Return(pluginIDs)

			var expectedActions []any
			for i := range pluginIDs {
				pluginID := pluginIDs[i]
				pluginName := pluginID.Name

				registry.On("Get", pluginKind, pluginName).Return(pluginID, nil)

				restartableProcess := &restartabletest.MockRestartableProcess{}
				defer restartableProcess.AssertExpectations(t)

				expected := &riav2cli.RestartableRestoreItemAction{
					Key:                 process.KindAndName{Kind: pluginKind, Name: pluginName},
					SharedPluginProcess: restartableProcess,
				}

				if tc.newRestartableProcessError != nil {
					// Test 1: error getting restartable process
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(nil, errors.Errorf("NewRestartableProcess")).Once()
					break
				}

				// Test 2: happy path
				if i == 0 {
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(restartableProcess, nil).Once()
				}

				expectedActions = append(expectedActions, expected)
			}

			restoreItemActions, err := m.GetRestoreItemActionsV2()
			if tc.newRestartableProcessError != nil {
				assert.Nil(t, restoreItemActions)
				assert.EqualError(t, err, "NewRestartableProcess")
			} else {
				require.NoError(t, err)
				var actual []any
				for i := range restoreItemActions {
					actual = append(actual, restoreItemActions[i])
				}
				assert.Equal(t, expectedActions, actual)
			}
		})
	}
}

func TestGetDeleteItemAction(t *testing.T) {
	getPluginTest(t,
		common.PluginKindDeleteItemAction,
		"velero.io/deleter",
		func(m Manager, name string) (any, error) {
			return m.GetDeleteItemAction(name)
		},
		func(name string, sharedPluginProcess process.RestartableProcess) any {
			return &restartableDeleteItemAction{
				key:                 process.KindAndName{Kind: common.PluginKindDeleteItemAction, Name: name},
				sharedPluginProcess: sharedPluginProcess,
			}
		},
		false,
	)
}

func TestGetDeleteItemActions(t *testing.T) {
	tests := []struct {
		name                       string
		names                      []string
		newRestartableProcessError error
		expectedError              string
	}{
		{
			name:  "No items",
			names: []string{},
		},
		{
			name:                       "Error getting restartable process",
			names:                      []string{"velero.io/a", "velero.io/b", "velero.io/c"},
			newRestartableProcessError: errors.Errorf("NewRestartableProcess"),
			expectedError:              "NewRestartableProcess",
		},
		{
			name:  "Happy path",
			names: []string{"velero.io/a", "velero.io/b", "velero.io/c"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := test.NewLogger()
			logLevel := logrus.InfoLevel

			registry := &mockRegistry{}
			defer registry.AssertExpectations(t)

			m := NewManager(logger, logLevel, registry).(*manager)
			factory := &mockRestartableProcessFactory{}
			defer factory.AssertExpectations(t)
			m.restartableProcessFactory = factory

			pluginKind := common.PluginKindDeleteItemAction
			var pluginIDs []framework.PluginIdentifier
			for i := range tc.names {
				pluginID := framework.PluginIdentifier{
					Command: "/command",
					Kind:    pluginKind,
					Name:    tc.names[i],
				}
				pluginIDs = append(pluginIDs, pluginID)
			}
			registry.On("List", pluginKind).Return(pluginIDs)

			var expectedActions []any
			for i := range pluginIDs {
				pluginID := pluginIDs[i]
				pluginName := pluginID.Name

				registry.On("Get", pluginKind, pluginName).Return(pluginID, nil)

				restartableProcess := &restartabletest.MockRestartableProcess{}
				defer restartableProcess.AssertExpectations(t)

				expected := &restartableDeleteItemAction{
					key:                 process.KindAndName{Kind: pluginKind, Name: pluginName},
					sharedPluginProcess: restartableProcess,
				}

				if tc.newRestartableProcessError != nil {
					// Test 1: error getting restartable process
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(nil, errors.Errorf("NewRestartableProcess")).Once()
					break
				}

				// Test 2: happy path
				if i == 0 {
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(restartableProcess, nil).Once()
				}

				expectedActions = append(expectedActions, expected)
			}

			deleteItemActions, err := m.GetDeleteItemActions()
			if tc.newRestartableProcessError != nil {
				assert.Nil(t, deleteItemActions)
				assert.EqualError(t, err, "NewRestartableProcess")
			} else {
				require.NoError(t, err)
				var actual []any
				for i := range deleteItemActions {
					actual = append(actual, deleteItemActions[i])
				}
				assert.Equal(t, expectedActions, actual)
			}
		})
	}
}

func TestGetItemBlockActions(t *testing.T) {
	tests := []struct {
		name                       string
		names                      []string
		newRestartableProcessError error
		expectedError              string
	}{
		{
			name:  "No items",
			names: []string{},
		},
		{
			name:                       "Error getting restartable process",
			names:                      []string{"velero.io/a", "velero.io/b", "velero.io/c"},
			newRestartableProcessError: errors.Errorf("NewRestartableProcess"),
			expectedError:              "NewRestartableProcess",
		},
		{
			name:  "Happy path",
			names: []string{"velero.io/a", "velero.io/b", "velero.io/c"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := test.NewLogger()
			logLevel := logrus.InfoLevel

			registry := &mockRegistry{}
			defer registry.AssertExpectations(t)

			m := NewManager(logger, logLevel, registry).(*manager)
			factory := &mockRestartableProcessFactory{}
			defer factory.AssertExpectations(t)
			m.restartableProcessFactory = factory

			pluginKind := common.PluginKindItemBlockAction
			var pluginIDs []framework.PluginIdentifier
			for i := range tc.names {
				pluginID := framework.PluginIdentifier{
					Command: "/command",
					Kind:    pluginKind,
					Name:    tc.names[i],
				}
				pluginIDs = append(pluginIDs, pluginID)
			}
			registry.On("List", pluginKind).Return(pluginIDs)

			var expectedActions []any
			for i := range pluginIDs {
				pluginID := pluginIDs[i]
				pluginName := pluginID.Name

				registry.On("Get", pluginKind, pluginName).Return(pluginID, nil)

				restartableProcess := &restartabletest.MockRestartableProcess{}
				defer restartableProcess.AssertExpectations(t)

				expected := &ibav1cli.RestartableItemBlockAction{
					Key:                 process.KindAndName{Kind: pluginKind, Name: pluginName},
					SharedPluginProcess: restartableProcess,
				}

				if tc.newRestartableProcessError != nil {
					// Test 1: error getting restartable process
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(nil, errors.Errorf("NewRestartableProcess")).Once()
					break
				}

				// Test 2: happy path
				if i == 0 {
					factory.On("NewRestartableProcess", pluginID.Command, logger, logLevel).Return(restartableProcess, nil).Once()
				}

				expectedActions = append(expectedActions, expected)
			}

			itemBlockActions, err := m.GetItemBlockActions()
			if tc.newRestartableProcessError != nil {
				assert.Nil(t, itemBlockActions)
				assert.EqualError(t, err, "NewRestartableProcess")
			} else {
				require.NoError(t, err)
				var actual []any
				for i := range itemBlockActions {
					actual = append(actual, itemBlockActions[i])
				}
				assert.Equal(t, expectedActions, actual)
			}
		})
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name, pluginName, expectedName string
	}{
		{
			name:         "Legacy, non-namespaced plugin",
			pluginName:   "aws",
			expectedName: "velero.io/aws",
		},
		{
			name:         "A Velero plugin",
			pluginName:   "velero.io/aws",
			expectedName: "velero.io/aws",
		},
		{
			name:         "A non-Velero plugin with a Velero namespace",
			pluginName:   "velero.io/plugin-for-velero",
			expectedName: "velero.io/plugin-for-velero",
		},
		{
			name:         "A non-Velero plugin with a non-Velero namespace",
			pluginName:   "digitalocean.com/velero",
			expectedName: "digitalocean.com/velero",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sanitizedName := sanitizeName(tc.pluginName)
			assert.Equal(t, tc.expectedName, sanitizedName)
		})
	}
}
