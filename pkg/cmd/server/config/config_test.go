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

package config

import (
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDefaultConfig(t *testing.T) {
	config := GetDefaultConfig()
	assert.Equal(t, 1, config.ItemBlockWorkerCount)
}

func TestBindFlags(t *testing.T) {
	config := GetDefaultConfig()
	config.BindFlags(pflag.CommandLine)
	assert.Equal(t, 1, config.ItemBlockWorkerCount)
}

func TestGlobalBackupVolumePoliciesConfigMapFlag(t *testing.T) {
	config := GetDefaultConfig()
	// Opt-in: defaults to empty.
	assert.Empty(t, config.GlobalBackupVolumePoliciesConfigMap)

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.NoError(t, flags.Parse([]string{"--global-backup-volume-policies-configmap", "global-volume-policy"}))
	assert.Equal(t, "global-volume-policy", config.GlobalBackupVolumePoliciesConfigMap)
}

func TestGracefulShutdownTimeoutFlag(t *testing.T) {
	config := GetDefaultConfig()
	// Opt-in: zero value means "derive automatically".
	assert.Zero(t, config.GracefulShutdownTimeout)

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.NoError(t, flags.Parse([]string{"--graceful-shutdown-timeout", "45m"}))
	assert.Equal(t, 45*time.Minute, config.GracefulShutdownTimeout)

	config = GetDefaultConfig()
	flags = pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.Error(t, flags.Parse([]string{"--graceful-shutdown-timeout", "0s"}))

	config = GetDefaultConfig()
	flags = pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.Error(t, flags.Parse([]string{"--graceful-shutdown-timeout", "-5m"}))

	config = GetDefaultConfig()
	flags = pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.Error(t, flags.Parse([]string{"--graceful-shutdown-timeout", "not-a-duration"}))

	config = GetDefaultConfig()
	flags = pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	assert.Equal(t, "duration", flags.Lookup("graceful-shutdown-timeout").Value.Type())
}

func TestGracefulShutdownSafetyBufferFlag(t *testing.T) {
	config := GetDefaultConfig()
	assert.Equal(t, 2*time.Second, config.GracefulShutdownSafetyBuffer)

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.NoError(t, flags.Parse([]string{"--graceful-shutdown-safety-buffer", "30s"}))
	assert.Equal(t, 30*time.Second, config.GracefulShutdownSafetyBuffer)

	config = GetDefaultConfig()
	flags = pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.Error(t, flags.Parse([]string{"--graceful-shutdown-safety-buffer", "-5m"}))

	config = GetDefaultConfig()
	flags = pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.NoError(t, flags.Parse([]string{"--graceful-shutdown-safety-buffer", "0s"}))
	assert.Zero(t, config.GracefulShutdownSafetyBuffer)

	config = GetDefaultConfig()
	flags = pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.Error(t, flags.Parse([]string{"--graceful-shutdown-safety-buffer", "not-a-duration"}))

	config = GetDefaultConfig()
	flags = pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	assert.Equal(t, "duration", flags.Lookup("graceful-shutdown-safety-buffer").Value.Type())
}
