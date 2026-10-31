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

package backup

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	cmdtest "github.com/velero-io/velero/pkg/cmd/test"
	"github.com/velero-io/velero/pkg/cmd/util/cacert"
	"github.com/velero-io/velero/pkg/cmd/util/downloadrequest"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestNewLogsCommand(t *testing.T) {
	t.Run("Flag test", func(t *testing.T) {
		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)

		timeout := "1m0s"
		insecureSkipTLSVerify := "true"
		caCertFile := "testing"

		flags.Parse([]string{"--timeout", timeout})
		flags.Parse([]string{"--insecure-skip-tls-verify", insecureSkipTLSVerify})
		flags.Parse([]string{"--cacert", caCertFile})

		require.Equal(t, timeout, l.Timeout.String())
		require.Equal(t, insecureSkipTLSVerify, strconv.FormatBool(l.InsecureSkipTLSVerify))
		require.Equal(t, caCertFile, l.CaCertFile)
	})

	t.Run("Backup not complete test", func(t *testing.T) {
		backupName := "bk-logs-1"

		// create a factory
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).Result()
		err := kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{})
		require.NoError(t, err)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewLogsCommand(f)
		assert.Equal(t, "Get backup logs", c.Short)

		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)
		err = l.Complete([]string{backupName}, f)
		require.NoError(t, err)

		err = l.Run(c, f)
		require.Error(t, err)
		require.ErrorContains(t, err, fmt.Sprintf("logs for backup \"%s\" are not available until it's finished processing", backupName))
	})

	t.Run("Backup not exist test", func(t *testing.T) {
		backupName := "not-exist"
		// create a factory
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewLogsCommand(f)
		assert.Equal(t, "Get backup logs", c.Short)

		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)
		err := l.Complete([]string{backupName}, f)
		require.NoError(t, err)

		err = l.Run(c, f)
		require.Error(t, err)

		require.Equal(t, fmt.Sprintf("backup \"%s\" does not exist", backupName), err.Error())

		c.Execute()
	})

	t.Run("Normal backup log test", func(t *testing.T) {
		backupName := "bk-logs-1"

		// create a factory
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).Phase(velerov1api.BackupPhaseCompleted).Result()
		err := kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{})
		require.NoError(t, err)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewLogsCommand(f)
		assert.Equal(t, "Get backup logs", c.Short)

		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)
		err = l.Complete([]string{backupName}, f)
		require.NoError(t, err)

		timeout := time.After(3 * time.Second)
		done := make(chan bool)
		go func() {
			err = l.Run(c, f)
			require.Error(t, err)
		}()

		select {
		case <-timeout:
			t.Skip("Test didn't finish in time, because BSL is not in Available state.")
		case <-done:
		}
	})

	t.Run("Invalid client test", func(t *testing.T) {
		// create a factory
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)

		c := NewLogsCommand(f)
		assert.Equal(t, "Get backup logs", c.Short)

		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)

		f.On("KubebuilderClient").Return(kbClient, fmt.Errorf("test error"))
		err := l.Complete([]string{""}, f)
		require.Equal(t, "test error", err.Error())
	})

	t.Run("Backup with BSL cacert test", func(t *testing.T) {
		backupName := "bk-logs-with-cacert"
		bslName := "test-bsl"
		expectedCACert := "test-cacert-content"
		expectedLogContent := "test backup log content"

		// create a factory
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)

		// Create BSL with cacert
		bsl := builder.ForBackupStorageLocation(cmdtest.VeleroNameSpace, bslName).
			Provider("aws").
			Bucket("test-bucket").
			CACert([]byte(expectedCACert)).
			Result()
		err := kbClient.Create(t.Context(), bsl, &kbclient.CreateOptions{})
		require.NoError(t, err)

		// Create backup referencing the BSL
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).
			Phase(velerov1api.BackupPhaseCompleted).
			StorageLocation(bslName).
			Result()
		err = kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{})
		require.NoError(t, err)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewLogsCommand(f)
		assert.Equal(t, "Get backup logs", c.Short)

		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)
		err = l.Complete([]string{backupName}, f)
		require.NoError(t, err)

		// Verify that the BSL cacert can be fetched correctly before running the command
		fetchedBackup := &velerov1api.Backup{}
		err = kbClient.Get(t.Context(), kbclient.ObjectKey{Namespace: cmdtest.VeleroNameSpace, Name: backupName}, fetchedBackup)
		require.NoError(t, err)

		// Test the cacert fetching logic directly
		cacertValue, err := cacert.GetCACertFromBackup(t.Context(), kbClient, cmdtest.VeleroNameSpace, fetchedBackup)
		require.NoError(t, err)
		assert.Equal(t, expectedCACert, cacertValue, "BSL cacert should be retrieved correctly")

		// Create a mock HTTP server to serve the log content
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// For logs, we need to gzip the content
			gzipWriter := gzip.NewWriter(w)
			defer gzipWriter.Close()
			gzipWriter.Write([]byte(expectedLogContent))
		}))
		defer mockServer.Close()

		// Mock the download request controller by updating DownloadRequests
		go func() {
			time.Sleep(50 * time.Millisecond) // Wait a bit for the request to be created

			// List all DownloadRequests
			downloadRequestList := &velerov1api.DownloadRequestList{}
			if err := kbClient.List(t.Context(), downloadRequestList, &kbclient.ListOptions{
				Namespace: cmdtest.VeleroNameSpace,
			}); err == nil {
				// Update each download request with the mock server URL
				for _, dr := range downloadRequestList.Items {
					if dr.Spec.Target.Kind == velerov1api.DownloadTargetKindBackupLog &&
						dr.Spec.Target.Name == backupName {
						dr.Status.DownloadURL = mockServer.URL
						dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
						kbClient.Update(t.Context(), &dr)
					}
				}
			}
		}()

		// Capture the output
		var logOutput bytes.Buffer
		// Temporarily redirect stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Run the logs command - it should now succeed
		l.Timeout = 5 * time.Second
		err = l.Run(c, f)

		// Restore stdout and read the output
		w.Close()
		os.Stdout = oldStdout
		io.Copy(&logOutput, r)

		// Verify the command succeeded and output is correct
		require.NoError(t, err)
		assert.Equal(t, expectedLogContent, logOutput.String())
	})
}

func TestLogsAvailabilityByPhase(t *testing.T) {
	tests := []struct {
		phase     velerov1api.BackupPhase
		available bool
	}{
		{phase: velerov1api.BackupPhaseNew, available: false},
		{phase: velerov1api.BackupPhaseInProgress, available: false},
		{phase: velerov1api.BackupPhaseFailedValidation, available: false},
		{phase: velerov1api.BackupPhaseWaitingForPluginOperations, available: true},
		{phase: velerov1api.BackupPhaseWaitingForPluginOperationsPartiallyFailed, available: true},
		{phase: velerov1api.BackupPhaseFinalizing, available: true},
		{phase: velerov1api.BackupPhaseFinalizingPartiallyFailed, available: true},
		{phase: velerov1api.BackupPhaseCompleted, available: true},
		{phase: velerov1api.BackupPhasePartiallyFailed, available: true},
		{phase: velerov1api.BackupPhaseFailed, available: true},
	}

	for _, tc := range tests {
		t.Run(string(tc.phase), func(t *testing.T) {
			backupName := "bk-logs-phase"

			kbClient := velerotest.NewFakeControllerRuntimeClient(t)
			backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).Phase(tc.phase).Result()
			require.NoError(t, kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{}))

			f := &factorymocks.Factory{}
			f.On("Namespace").Return(cmdtest.VeleroNameSpace)
			f.On("KubebuilderClient").Return(kbClient, nil)

			l := NewLogsOptions()
			require.NoError(t, l.Complete([]string{backupName}, f))
			// Nothing processes the DownloadRequest here, so a phase that passes the
			// check ends in the download URL timeout instead of the phase error.
			l.Timeout = 100 * time.Millisecond

			err := l.Run(NewLogsCommand(f), f)
			if tc.available {
				require.ErrorIs(t, err, downloadrequest.ErrDownloadRequestDownloadURLTimeout)
			} else {
				require.ErrorContains(t, err, fmt.Sprintf("logs for backup %q are not available until it's finished processing", backupName))
			}
		})
	}
}

func TestBSLCACertBehavior(t *testing.T) {
	t.Run("Backup with BSL without cacert test", func(t *testing.T) {
		backupName := "bk-logs-without-cacert"
		bslName := "test-bsl-no-cacert"

		// create a factory
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)

		// Create BSL without cacert
		bsl := builder.ForBackupStorageLocation(cmdtest.VeleroNameSpace, bslName).
			Provider("aws").
			Bucket("test-bucket").
			// No CACert() call - BSL will have no cacert
			Result()
		err := kbClient.Create(t.Context(), bsl, &kbclient.CreateOptions{})
		require.NoError(t, err)

		// Create backup referencing the BSL
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).
			Phase(velerov1api.BackupPhaseCompleted).
			StorageLocation(bslName).
			Result()
		err = kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{})
		require.NoError(t, err)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewLogsCommand(f)
		assert.Equal(t, "Get backup logs", c.Short)

		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)
		err = l.Complete([]string{backupName}, f)
		require.NoError(t, err)

		// Verify that the BSL cacert returns empty string when not present
		fetchedBackup := &velerov1api.Backup{}
		err = kbClient.Get(t.Context(), kbclient.ObjectKey{Namespace: cmdtest.VeleroNameSpace, Name: backupName}, fetchedBackup)
		require.NoError(t, err)

		// Test the cacert fetching logic directly
		cacertValue, err := cacert.GetCACertFromBackup(t.Context(), kbClient, cmdtest.VeleroNameSpace, fetchedBackup)
		require.NoError(t, err)
		assert.Empty(t, cacertValue, "BSL cacert should be empty when not configured")

		// The command should still work without cacert
		l.Timeout = 100 * time.Millisecond
		err = l.Run(c, f)
		require.Error(t, err)
		// The error should be about download request timeout, not about cacert fetching
		assert.Contains(t, err.Error(), "download")
	})

	t.Run("Backup with nonexistent BSL test", func(t *testing.T) {
		backupName := "bk-logs-with-missing-bsl"
		bslName := "nonexistent-bsl"

		// create a factory
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)

		// Create backup referencing a BSL that doesn't exist
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).
			Phase(velerov1api.BackupPhaseCompleted).
			StorageLocation(bslName).
			Result()
		err := kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{})
		require.NoError(t, err)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewLogsCommand(f)
		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)
		err = l.Complete([]string{backupName}, f)
		require.NoError(t, err)

		// Verify that the BSL cacert returns empty string when BSL doesn't exist
		fetchedBackup := &velerov1api.Backup{}
		err = kbClient.Get(t.Context(), kbclient.ObjectKey{Namespace: cmdtest.VeleroNameSpace, Name: backupName}, fetchedBackup)
		require.NoError(t, err)

		// Test the cacert fetching logic directly - should not error when BSL is missing
		cacertValue, err := cacert.GetCACertFromBackup(t.Context(), kbClient, cmdtest.VeleroNameSpace, fetchedBackup)
		require.NoError(t, err)
		assert.Empty(t, cacertValue, "BSL cacert should be empty when BSL doesn't exist")

		// The command should still try to run even without BSL
		l.Timeout = 100 * time.Millisecond
		err = l.Run(c, f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "download")
	})
}
