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

package restore

import (
	"fmt"
	"os"
	"testing"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/velero-io/velero/pkg/builder"
	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	cmdtest "github.com/velero-io/velero/pkg/cmd/test"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestNewLogsCommand(t *testing.T) {
	t.Run("Flag test", func(t *testing.T) {
		// create a factory
		f := &factorymocks.Factory{}

		c := NewLogsCommand(f)
		require.Equal(t, "Get restore logs", c.Short)

		// Test flag parsing
		timeout := "1s"
		insecureSkipTLSVerify := "true"
		caCertFile := "testing"

		c.Flags().Set("timeout", timeout)
		c.Flags().Set("insecure-skip-tls-verify", insecureSkipTLSVerify)
		c.Flags().Set("cacert", caCertFile)

		timeoutFlag, _ := c.Flags().GetDuration("timeout")
		require.Equal(t, 1*time.Second, timeoutFlag)

		insecureFlag, _ := c.Flags().GetBool("insecure-skip-tls-verify")
		require.True(t, insecureFlag)

		caCertFlag, _ := c.Flags().GetString("cacert")
		require.Equal(t, caCertFile, caCertFlag)
	})

	t.Run("Restore not complete test", func(t *testing.T) {
		restoreName := "rs-logs-1"

		// create a factory
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)
		restore := builder.ForRestore(cmdtest.VeleroNameSpace, restoreName).Result()
		err := kbClient.Create(t.Context(), restore, &kbclient.CreateOptions{})
		require.NoError(t, err)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewLogsCommand(f)
		assert.Equal(t, "Get restore logs", c.Short)

		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)
		err = l.Complete([]string{restoreName}, f)
		require.NoError(t, err)

		err = l.Run(c, f)
		require.Error(t, err)
		require.ErrorContains(t, err, fmt.Sprintf("logs for restore %q are not available until it's finished processing", restoreName))
	})

	t.Run("Restore not exist test", func(t *testing.T) {
		restoreName := "not-exist"

		// create a factory
		f := &factorymocks.Factory{}

		kbClient := velerotest.NewFakeControllerRuntimeClient(t)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderClient").Return(kbClient, nil)

		c := NewLogsCommand(f)
		assert.Equal(t, "Get restore logs", c.Short)

		l := NewLogsOptions()
		flags := new(flag.FlagSet)
		l.BindFlags(flags)
		err := l.Complete([]string{restoreName}, f)
		require.NoError(t, err)

		err = l.Run(c, f)
		require.Error(t, err)
		require.Equal(t, fmt.Sprintf("restore %q does not exist", restoreName), err.Error())
	})

	t.Run("CLI execution test", func(t *testing.T) {
		// create a factory
		f := &factorymocks.Factory{}

		c := NewLogsCommand(f)
		require.Equal(t, "Get restore logs", c.Short)

		if os.Getenv(cmdtest.CaptureFlag) == "1" {
			c.SetArgs([]string{"test"})
			e := c.Execute()
			assert.NoError(t, e)
			return
		}
	})
}
