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
	assert.Equal(t, 10*time.Minute, config.DefaultBackupCSISnapshotTimeout)
	assert.Equal(t, 30*time.Minute, config.DefaultRestoreCSISnapshotTimeout)
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
