package config

import (
	"testing"

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

func TestCRDSchemaCheckFlag(t *testing.T) {
	config := GetDefaultConfig()
	assert.Equal(t, "warn", config.CRDSchemaCheck.String())

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	require.NoError(t, flags.Parse([]string{"--crd-schema-check", "strict"}))
	assert.Equal(t, "strict", config.CRDSchemaCheck.String())
}

func TestCRDSchemaCheckFlagRejectsInvalidValue(t *testing.T) {
	config := GetDefaultConfig()

	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.BindFlags(flags)
	err := flags.Parse([]string{"--crd-schema-check", "foo"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid value")
}
