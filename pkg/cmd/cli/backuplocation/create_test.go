/*
Copyright the Velero Contributors.

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

package backuplocation

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	factorymocks "github.com/velero-io/velero/pkg/client/mocks"
	veleroflag "github.com/velero-io/velero/pkg/cmd/util/flag"
	velerotest "github.com/velero-io/velero/pkg/test"
)

func TestBuildBackupStorageLocationSetsNamespace(t *testing.T) {
	o := NewCreateOptions()

	bsl, err := o.BuildBackupStorageLocation("velero-test-ns", false, false)
	require.NoError(t, err)
	assert.Equal(t, "velero-test-ns", bsl.Namespace)
}

func TestBuildBackupStorageLocationSetsSyncPeriod(t *testing.T) {
	o := NewCreateOptions()
	o.BackupSyncPeriod = 2 * time.Minute

	bsl, err := o.BuildBackupStorageLocation("velero-test-ns", false, false)
	require.NoError(t, err)
	assert.Nil(t, bsl.Spec.BackupSyncPeriod)

	bsl, err = o.BuildBackupStorageLocation("velero-test-ns", true, false)
	require.NoError(t, err)
	assert.Equal(t, &metav1.Duration{Duration: 2 * time.Minute}, bsl.Spec.BackupSyncPeriod)
}

func TestBuildBackupStorageLocationSetsValidationFrequency(t *testing.T) {
	o := NewCreateOptions()
	o.ValidationFrequency = 2 * time.Minute

	bsl, err := o.BuildBackupStorageLocation("velero-test-ns", false, false)
	require.NoError(t, err)
	assert.Nil(t, bsl.Spec.ValidationFrequency)

	bsl, err = o.BuildBackupStorageLocation("velero-test-ns", false, true)
	require.NoError(t, err)
	assert.Equal(t, &metav1.Duration{Duration: 2 * time.Minute}, bsl.Spec.ValidationFrequency)
}

func TestBuildBackupStorageLocationSetsCredential(t *testing.T) {
	o := NewCreateOptions()

	bsl, err := o.BuildBackupStorageLocation("velero-test-ns", false, false)
	require.NoError(t, err)
	assert.Nil(t, bsl.Spec.Credential)

	setErr := o.Credential.Set("my-secret=key-from-secret")
	require.NoError(t, setErr)

	bsl, err = o.BuildBackupStorageLocation("velero-test-ns", false, true)
	require.NoError(t, err)
	assert.Equal(t, &corev1api.SecretKeySelector{
		LocalObjectReference: corev1api.LocalObjectReference{Name: "my-secret"},
		Key:                  "key-from-secret",
	}, bsl.Spec.Credential)
}

func TestBuildBackupStorageLocationSetsLabels(t *testing.T) {
	o := NewCreateOptions()

	err := o.Labels.Set("key=value")
	require.NoError(t, err)

	bsl, err := o.BuildBackupStorageLocation("velero-test-ns", false, false)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"key": "value"}, bsl.Labels)
}

func TestCreateCommand_Run(t *testing.T) {
	// create a factory
	f := &factorymocks.Factory{}

	// create command
	c := NewCreateCommand(f, "")
	assert.Equal(t, "Create a backup storage location", c.Short)

	// create a CreateOptions with full options set and then run this backup command
	name := "bsl-name-to-be-created"
	provider := "aws"
	bucket := "velero123456"
	credential := veleroflag.NewMap()
	credential.Set("secret=a")

	defaultBackupStorageLocation := true
	prefix := "builds"
	backupSyncPeriod := "1m30s"
	validationFrequency := "128h1m6s"
	bslConfig := veleroflag.NewMap()
	bslConfigStr := "region=minio"
	bslConfig.Set(bslConfigStr)

	labels := "a=too,b=woo"
	caCertFile := "bsl-name-1"
	accessMode := "ReadWrite"

	flags := new(flag.FlagSet)
	o := NewCreateOptions()
	o.BindFlags(flags)

	flags.Parse([]string{"--provider", provider})
	flags.Parse([]string{"--bucket", bucket})
	flags.Parse([]string{"--credential", credential.String()})
	flags.Parse([]string{"--default"})
	flags.Parse([]string{"--prefix", prefix})
	flags.Parse([]string{"--backup-sync-period", backupSyncPeriod})
	flags.Parse([]string{"--validation-frequency", validationFrequency})
	flags.Parse([]string{"--config", bslConfigStr})
	flags.Parse([]string{"--labels", labels})
	flags.Parse([]string{"--cacert", caCertFile})
	flags.Parse([]string{"--access-mode", accessMode})

	args := []string{name, "arg2"}

	kbclient := velerotest.NewFakeControllerRuntimeClient(t)
	f.On("Namespace").Return(mock.Anything)
	f.On("KubebuilderClient").Return(kbclient, nil)

	o.Complete(args, f)
	e := o.Validate(c, args, f)
	require.NoError(t, e)

	e = o.Run(c, f)
	require.ErrorContains(t, e, fmt.Sprintf("%s: no such file or directory", caCertFile))

	// verify all options are set as expected
	assert.Equal(t, name, o.Name)
	assert.Equal(t, provider, o.Provider)
	assert.Equal(t, bucket, o.Bucket)
	assert.True(t, reflect.DeepEqual(credential, o.Credential))
	assert.Equal(t, defaultBackupStorageLocation, o.DefaultBackupStorageLocation)
	assert.Equal(t, prefix, o.Prefix)
	assert.Equal(t, backupSyncPeriod, o.BackupSyncPeriod.String())
	assert.Equal(t, validationFrequency, o.ValidationFrequency.String())
	assert.True(t, reflect.DeepEqual(bslConfig, o.Config))
	assert.True(t, velerotest.CompareSlice(strings.Split(labels, ","), strings.Split(o.Labels.String(), ",")))
	assert.Equal(t, caCertFile, o.CACertFile)
	assert.Equal(t, accessMode, o.AccessMode.String())

	// create the other create command without fromSchedule option for Run() other branches
	c = NewCreateCommand(f, "velero backup-location create")
	assert.Equal(t, "Create a backup storage location", c.Short)

	o = NewCreateOptions()
	o.Labels.Set("velero.io/test=true")

	args = []string{"backup-name-2", "arg2"}
	o.Complete(args, f)

	e = o.Run(c, f)
	require.NoError(t, e)
	c.SetArgs([]string{"bsl-1", "--provider=aws", "--bucket=bk1", "--default"})
	e = c.Execute()
	assert.NoError(t, e)
}
