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
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestNewItemOutcomesCommand(t *testing.T) {
	t.Run("Flag test", func(t *testing.T) {
		o := NewItemOutcomesOptions()
		flags := new(flag.FlagSet)
		o.BindFlags(flags)

		timeout := "1m0s"
		insecureSkipTLSVerify := "true"
		caCertFile := "testing"

		flags.Parse([]string{"--timeout", timeout})
		flags.Parse([]string{"--insecure-skip-tls-verify", insecureSkipTLSVerify})
		flags.Parse([]string{"--cacert", caCertFile})

		require.Equal(t, timeout, o.Timeout.String())
		require.Equal(t, insecureSkipTLSVerify, strconv.FormatBool(o.InsecureSkipTLSVerify))
		require.Equal(t, caCertFile, o.CaCertFile)
	})

	t.Run("Backup not exist test", func(t *testing.T) {
		backupName := "not-exist"

		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewItemOutcomesCommand(f)
		assert.Equal(t, "Get the per-item backup outcomes artifact", c.Short)

		o := NewItemOutcomesOptions()
		flags := new(flag.FlagSet)
		o.BindFlags(flags)
		err := o.Complete([]string{backupName}, f)
		require.NoError(t, err)

		err = o.Run(c, f)
		require.Error(t, err)
		require.Equal(t, fmt.Sprintf("backup %q does not exist", backupName), err.Error())
	})

	t.Run("Invalid client test", func(t *testing.T) {
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)

		c := NewItemOutcomesCommand(f)
		assert.Equal(t, "Get the per-item backup outcomes artifact", c.Short)

		o := NewItemOutcomesOptions()
		flags := new(flag.FlagSet)
		o.BindFlags(flags)

		f.On("KubebuilderClient").Return(kbClient, fmt.Errorf("test error"))
		err := o.Complete([]string{""}, f)
		require.Equal(t, "test error", err.Error())
	})

	// runAgainstArtifacts serves one mock object-store body per download target
	// kind, so a command that reads more than one artifact can be exercised.
	runAgainstArtifacts := func(t *testing.T, backupName string, artifacts map[velerov1api.DownloadTargetKind]string, configure func(*ItemOutcomesOptions)) (string, string) {
		t.Helper()

		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).Phase(velerov1api.BackupPhaseCompleted).Result()
		err := kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{})
		require.NoError(t, err)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewItemOutcomesCommand(f)

		o := NewItemOutcomesOptions()
		flags := new(flag.FlagSet)
		o.BindFlags(flags)
		err = o.Complete([]string{backupName}, f)
		require.NoError(t, err)
		if configure != nil {
			configure(&o)
		}

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Every request names the artifact it wants, so one server can serve all
			// of them.
			content, ok := artifacts[velerov1api.DownloadTargetKind(r.URL.Query().Get("kind"))]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			gzipWriter := gzip.NewWriter(w)
			defer gzipWriter.Close()
			gzipWriter.Write([]byte(content))
		}))
		defer mockServer.Close()

		// A command that reads several artifacts creates them one after another, so
		// the patcher has to keep looking rather than sweep once.
		done := make(chan struct{})
		defer close(done)
		go func() {
			for {
				select {
				case <-done:
					return
				case <-time.After(20 * time.Millisecond):
				}

				downloadRequestList := &velerov1api.DownloadRequestList{}
				if err := kbClient.List(t.Context(), downloadRequestList, &kbclient.ListOptions{
					Namespace: cmdtest.VeleroNameSpace,
				}); err != nil {
					continue
				}
				for _, dr := range downloadRequestList.Items {
					if _, ok := artifacts[dr.Spec.Target.Kind]; !ok {
						continue
					}
					if dr.Spec.Target.Name != backupName {
						continue
					}
					if dr.Status.DownloadURL != "" {
						continue
					}
					dr.Status.DownloadURL = mockServer.URL + "?kind=" + string(dr.Spec.Target.Kind)
					dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
					kbClient.Update(t.Context(), &dr)
				}
			}
		}()

		var stdout, stderr bytes.Buffer
		oldStdout, oldStderr := os.Stdout, os.Stderr
		rOut, wOut, _ := os.Pipe()
		rErr, wErr, _ := os.Pipe()
		os.Stdout, os.Stderr = wOut, wErr

		o.Timeout = 5 * time.Second
		err = o.Run(c, f)

		wOut.Close()
		wErr.Close()
		os.Stdout, os.Stderr = oldStdout, oldStderr
		io.Copy(&stdout, rOut)
		io.Copy(&stderr, rErr)

		require.NoError(t, err)
		return stdout.String(), stderr.String()
	}

	runAgainstMockArtifact := func(t *testing.T, backupName string, content string, configure func(*ItemOutcomesOptions)) string {
		t.Helper()
		stdout, _ := runAgainstArtifacts(t, backupName, map[velerov1api.DownloadTargetKind]string{
			velerov1api.DownloadTargetKindBackupItemOutcomes: content,
		}, configure)
		return stdout
	}

	t.Run("Pretty-prints the decompressed artifact by default", func(t *testing.T) {
		content := `{"schemaVersion":"v1","items":[{"groupResource":"configmaps","namespace":"ns","name":"cm","outcome":"Succeeded"}]}`

		output := runAgainstMockArtifact(t, "bk-item-outcomes-1", content, nil)

		assert.JSONEq(t, `{"schemaVersion":"v1","finalized":false,"items":[{"groupResource":"configmaps","namespace":"ns","name":"cm","outcome":"Succeeded"}]}`, output)
		assert.Contains(t, output, "\n  \"schemaVersion\": \"v1\",", "output is indented, not compact")
	})

	t.Run("Streams the raw compact artifact with --raw", func(t *testing.T) {
		content := `{"schemaVersion":"v1","items":[{"groupResource":"configmaps","namespace":"ns","name":"cm","outcome":"Succeeded"}]}`

		output := runAgainstMockArtifact(t, "bk-item-outcomes-raw", content, func(o *ItemOutcomesOptions) {
			o.Raw = true
		})

		assert.Equal(t, content, output)
	})

	t.Run("Default JSON warns when the artifact was not finalized", func(t *testing.T) {
		content := `{"schemaVersion":"v1","items":[{"groupResource":"configmaps","namespace":"ns","name":"cm","outcome":"Succeeded"}]}`

		stdout, stderr := runAgainstArtifacts(t, "bk-item-outcomes-json-unfinalized", map[velerov1api.DownloadTargetKind]string{
			velerov1api.DownloadTargetKindBackupItemOutcomes: content,
		}, nil)

		assert.Contains(t, stderr, "was not finalized")
		assert.Contains(t, stdout, `"name": "cm"`)
	})

	t.Run("--raw warns without changing the stored bytes", func(t *testing.T) {
		content := `{"schemaVersion":"v2","finalized":true,"items":[]}`

		stdout, stderr := runAgainstArtifacts(t, "bk-item-outcomes-raw-future", map[velerov1api.DownloadTargetKind]string{
			velerov1api.DownloadTargetKindBackupItemOutcomes: content,
		}, func(o *ItemOutcomesOptions) {
			o.Raw = true
		})

		assert.Contains(t, stderr, "does not understand")
		assert.Equal(t, content, stdout)
	})

	t.Run("Prints one row per item with -o table", func(t *testing.T) {
		content := `{"schemaVersion":"v1","finalized":true,"items":[
			{"groupResource":"pods","namespace":"ns","name":"pod1","outcome":"Succeeded"},
			{"groupResource":"persistentvolumeclaims","namespace":"ns","name":"disk1","outcome":"Failed","messages":["snapshot failed"]}
		]}`

		output := runAgainstMockArtifact(t, "bk-item-outcomes-table", content, func(o *ItemOutcomesOptions) {
			o.Output = "table"
		})

		assert.Contains(t, output, "GROUP/RESOURCE")
		assert.Contains(t, output, "disk1")
		assert.Contains(t, output, "Failed")
		assert.Contains(t, output, "pod1")
		assert.Contains(t, output, "BackedUp")
	})

	t.Run("Not collected for this backup", func(t *testing.T) {
		backupName := "bk-item-outcomes-not-collected"

		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).Phase(velerov1api.BackupPhaseCompleted).Result()
		err := kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{})
		require.NoError(t, err)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewItemOutcomesCommand(f)

		o := NewItemOutcomesOptions()
		flags := new(flag.FlagSet)
		o.BindFlags(flags)
		err = o.Complete([]string{backupName}, f)
		require.NoError(t, err)

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer mockServer.Close()

		go func() {
			time.Sleep(50 * time.Millisecond)

			downloadRequestList := &velerov1api.DownloadRequestList{}
			if err := kbClient.List(t.Context(), downloadRequestList, &kbclient.ListOptions{
				Namespace: cmdtest.VeleroNameSpace,
			}); err == nil {
				for _, dr := range downloadRequestList.Items {
					if dr.Spec.Target.Kind == velerov1api.DownloadTargetKindBackupItemOutcomes &&
						dr.Spec.Target.Name == backupName {
						dr.Status.DownloadURL = mockServer.URL
						dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
						kbClient.Update(t.Context(), &dr)
					}
				}
			}
		}()

		o.Timeout = 5 * time.Second
		err = o.Run(c, f)
		require.Error(t, err)
		assert.Equal(t, fmt.Sprintf("item outcomes were not collected for backup %q", backupName), err.Error())
	})

	t.Run("warns when the artifact schema is newer", func(t *testing.T) {
		artifact := `{"schemaVersion":"v2","finalized":true,"items":[{"groupResource":"configmaps","namespace":"ns","name":"cm","outcome":"Succeeded"}]}`

		_, stderr := runAgainstArtifacts(t, "bk-future-schema", map[velerov1api.DownloadTargetKind]string{
			velerov1api.DownloadTargetKindBackupItemOutcomes: artifact,
		}, nil)

		assert.Contains(t, stderr, "does not understand",
			"an unknown schema must not be read as a complete result")
	})

	t.Run("warns when the backup recorded errors no item shows", func(t *testing.T) {
		backupName := "bk-unattributed"

		f := &factorymocks.Factory{}
		kbClient := velerotest.NewFakeControllerRuntimeClient(t)
		// A backup can fail while listing resources, before any item exists: every
		// item then reads BackedUp and only the status holds the error count.
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).Phase(velerov1api.BackupPhasePartiallyFailed).Result()
		backup.Status.Errors = 7
		require.NoError(t, kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{}))

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		o := NewItemOutcomesOptions()
		flags := new(flag.FlagSet)
		o.BindFlags(flags)
		require.NoError(t, o.Complete([]string{backupName}, f))

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gzipWriter := gzip.NewWriter(w)
			defer gzipWriter.Close()
			gzipWriter.Write([]byte(`{"schemaVersion":"v1","finalized":true,"items":[{"groupResource":"configmaps","namespace":"ns","name":"cm","outcome":"Succeeded"}]}`))
		}))
		defer mockServer.Close()

		done := make(chan struct{})
		defer close(done)
		go func() {
			for {
				select {
				case <-done:
					return
				case <-time.After(20 * time.Millisecond):
				}
				downloadRequestList := &velerov1api.DownloadRequestList{}
				if err := kbClient.List(t.Context(), downloadRequestList, &kbclient.ListOptions{
					Namespace: cmdtest.VeleroNameSpace,
				}); err != nil {
					continue
				}
				for _, dr := range downloadRequestList.Items {
					dr.Status.DownloadURL = mockServer.URL
					dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
					kbClient.Update(t.Context(), &dr)
				}
			}
		}()

		var stdout, stderr bytes.Buffer
		oldStdout, oldStderr := os.Stdout, os.Stderr
		rOut, wOut, _ := os.Pipe()
		rErr, wErr, _ := os.Pipe()
		os.Stdout, os.Stderr = wOut, wErr

		o.Timeout = 5 * time.Second
		err := o.Run(NewItemOutcomesCommand(f), f)

		wOut.Close()
		wErr.Close()
		os.Stdout, os.Stderr = oldStdout, oldStderr
		io.Copy(&stdout, rOut)
		io.Copy(&stderr, rErr)

		require.NoError(t, err)
		assert.Contains(t, stderr.String(), "recorded 7 error(s)")
		assert.Contains(t, stdout.String(), `"name": "cm"`)
	})

	t.Run("rejects an unknown output format", func(t *testing.T) {
		f := &factorymocks.Factory{}
		kbClient := velerotest.NewFakeControllerRuntimeClient(t)
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, "bk-bad-format").Phase(velerov1api.BackupPhaseCompleted).Result()
		require.NoError(t, kbClient.Create(t.Context(), backup, &kbclient.CreateOptions{}))

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		o := NewItemOutcomesOptions()
		flags := new(flag.FlagSet)
		o.BindFlags(flags)
		require.NoError(t, o.Complete([]string{"bk-bad-format"}, f))
		o.Output = "yaml"

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gzipWriter := gzip.NewWriter(w)
			defer gzipWriter.Close()
			gzipWriter.Write([]byte(`{"schemaVersion":"v1","finalized":true,"items":[]}`))
		}))
		defer mockServer.Close()

		go func() {
			time.Sleep(50 * time.Millisecond)
			downloadRequestList := &velerov1api.DownloadRequestList{}
			if err := kbClient.List(t.Context(), downloadRequestList, &kbclient.ListOptions{
				Namespace: cmdtest.VeleroNameSpace,
			}); err == nil {
				for _, dr := range downloadRequestList.Items {
					dr.Status.DownloadURL = mockServer.URL
					dr.Status.Phase = velerov1api.DownloadRequestPhaseProcessed
					kbClient.Update(t.Context(), &dr)
				}
			}
		}()

		o.Timeout = 5 * time.Second
		err := o.Run(NewItemOutcomesCommand(f), f)
		require.Error(t, err)
		assert.Equal(t, `unsupported output format "yaml": use json or table`, err.Error())
	})

	t.Run("warns when the artifact is not a backup artifact", func(t *testing.T) {
		artifact := `{"schemaVersion":"v1","kind":"other","finalized":true,"items":[{"groupResource":"configmaps","namespace":"ns","name":"cm","outcome":"Succeeded"}]}`

		stdout, stderr := runAgainstArtifacts(t, "bk-other-artifact", map[velerov1api.DownloadTargetKind]string{
			velerov1api.DownloadTargetKindBackupItemOutcomes: artifact,
		}, func(o *ItemOutcomesOptions) {
			o.Output = "table"
		})

		assert.Contains(t, stderr, `records "other" outcomes`)
		assert.Contains(t, stdout, "BackedUp")
	})
}

func TestNewItemOutcomesOptionsSetsEmptyDefaultOutput(t *testing.T) {
	assert.Equal(t, "", NewItemOutcomesOptions().Output)
}
