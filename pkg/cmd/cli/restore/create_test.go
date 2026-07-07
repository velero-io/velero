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

package restore

import (
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"
	kbclient "sigs.k8s.io/controller-runtime/pkg/client"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/builder"
	factorymocks "github.com/vmware-tanzu/velero/pkg/client/mocks"
	cmdtest "github.com/vmware-tanzu/velero/pkg/cmd/test"
	velerotest "github.com/vmware-tanzu/velero/pkg/test"
)

func TestMostRecentBackup(t *testing.T) {
	backups := []velerov1api.Backup{
		*builder.ForBackup(cmdtest.VeleroNameSpace, "backup0").StartTimestamp(time.Now().Add(3 * time.Second)).Phase(velerov1api.BackupPhaseDeleting).Result(),
		*builder.ForBackup(cmdtest.VeleroNameSpace, "backup1").StartTimestamp(time.Now().Add(time.Second)).Phase(velerov1api.BackupPhaseCompleted).Result(),
		*builder.ForBackup(cmdtest.VeleroNameSpace, "backup2").StartTimestamp(time.Now().Add(2 * time.Second)).Phase(velerov1api.BackupPhasePartiallyFailed).Result(),
	}

	expectedBackup := builder.ForBackup(cmdtest.VeleroNameSpace, "backup2").StartTimestamp(time.Now().Add(2 * time.Second)).Phase(velerov1api.BackupPhasePartiallyFailed).Result()

	resultBackup := mostRecentBackup(backups, velerov1api.BackupPhaseCompleted, velerov1api.BackupPhasePartiallyFailed)

	require.Equal(t, expectedBackup.Name, resultBackup.Name)
}

func TestCreateCommand(t *testing.T) {
	name := "nameToBeCreated"
	args := []string{name}

	t.Run("create a backup create command with full options except fromSchedule and wait, then run by create option", func(t *testing.T) {
		// create a factory
		f := &factorymocks.Factory{}

		// create command
		cmd := NewCreateCommand(f, "")
		require.Equal(t, "Create a restore", cmd.Short)

		backupName := "backup1"
		scheduleName := "schedule1"
		restoreVolumes := "true"
		preserveNodePorts := "true"
		labels := "c=foo"
		annotations := "ann=foo"
		includeNamespaces := "app1,app2"
		excludeNamespaces := "pod1,pod2,pod3"
		existingResourcePolicy := "none"
		includeResources := "sc,sts"
		excludeResources := "job"
		statusIncludeResources := "sc,sts"
		statusExcludeResources := "job"
		namespaceMappings := "a:b"
		selector := "foo=bar"
		includeClusterResources := "true"
		allowPartiallyFailed := "true"
		itemOperationTimeout := "10m0s"
		resourceModifierConfigMap := "modifier-cm"
		ResourcePoliciesConfigMap := "policies-cm"
		writeSparseFiles := "true"
		parallel := 2
		flags := new(pflag.FlagSet)
		o := NewCreateOptions()
		o.BindFlags(flags)

		flags.Parse([]string{"--from-backup", backupName})
		flags.Parse([]string{"--from-schedule", scheduleName})
		flags.Parse([]string{"--restore-volumes", restoreVolumes})
		flags.Parse([]string{"--preserve-nodeports", preserveNodePorts})
		flags.Parse([]string{"--labels", labels})
		flags.Parse([]string{"--annotations", annotations})
		flags.Parse([]string{"--existing-resource-policy", existingResourcePolicy})
		flags.Parse([]string{"--include-namespaces", includeNamespaces})
		flags.Parse([]string{"--exclude-namespaces", excludeNamespaces})
		flags.Parse([]string{"--include-resources", includeResources})
		flags.Parse([]string{"--exclude-resources", excludeResources})
		flags.Parse([]string{"--status-include-resources", statusIncludeResources})
		flags.Parse([]string{"--status-exclude-resources", statusExcludeResources})
		flags.Parse([]string{"--namespace-mappings", namespaceMappings})
		flags.Parse([]string{"--selector", selector})
		flags.Parse([]string{"--include-cluster-resources", includeClusterResources})
		flags.Parse([]string{"--allow-partially-failed", allowPartiallyFailed})
		flags.Parse([]string{"--item-operation-timeout", itemOperationTimeout})
		flags.Parse([]string{"--resource-modifier-configmap", resourceModifierConfigMap})
		flags.Parse([]string{"--resource-policies-configmap", ResourcePoliciesConfigMap})
		flags.Parse([]string{"--write-sparse-files", writeSparseFiles})
		flags.Parse([]string{"--parallel-files-download", "2"})
		client := velerotest.NewFakeControllerRuntimeClient(t).(kbclient.WithWatch)

		f.On("Namespace").Return(mock.Anything)
		f.On("KubebuilderWatchClient").Return(client, nil)

		//Complete
		e := o.Complete(args, f)
		require.NoError(t, e)

		//Validate
		e = o.Validate(cmd, args, f)
		require.ErrorContains(t, e, "either a backup or schedule must be specified, but not both")

		//cmd
		e = o.Run(cmd, f)
		require.NoError(t, e)

		require.Equal(t, backupName, o.BackupName)
		require.Equal(t, scheduleName, o.ScheduleName)
		require.Equal(t, restoreVolumes, o.RestoreVolumes.String())
		require.Equal(t, preserveNodePorts, o.PreserveNodePorts.String())
		require.Equal(t, labels, o.Labels.String())
		require.Equal(t, annotations, o.Annotations.String())
		require.Equal(t, includeNamespaces, o.IncludeNamespaces.String())
		require.Equal(t, excludeNamespaces, o.ExcludeNamespaces.String())
		require.Equal(t, existingResourcePolicy, o.ExistingResourcePolicy)
		require.Equal(t, includeResources, o.IncludeResources.String())
		require.Equal(t, excludeResources, o.ExcludeResources.String())

		require.Equal(t, statusIncludeResources, o.StatusIncludeResources.String())
		require.Equal(t, statusExcludeResources, o.StatusExcludeResources.String())
		require.Equal(t, namespaceMappings, o.NamespaceMappings.String())
		require.Equal(t, selector, o.Selector.String())
		require.Equal(t, includeClusterResources, o.IncludeClusterResources.String())
		require.Equal(t, allowPartiallyFailed, o.AllowPartiallyFailed.String())
		require.Equal(t, itemOperationTimeout, o.ItemOperationTimeout.String())
		require.Equal(t, resourceModifierConfigMap, o.ResourceModifierConfigMap)
		require.Equal(t, ResourcePoliciesConfigMap, o.ResourcePoliciesConfigMap)
		require.Equal(t, writeSparseFiles, o.WriteSparseFiles.String())
		require.Equal(t, parallel, o.ParallelFilesDownload)
	})

	t.Run("create a restore from schedule", func(t *testing.T) {
		f := &factorymocks.Factory{}
		c := NewCreateCommand(f, "")
		require.Equal(t, "Create a restore", c.Short)
		flags := new(pflag.FlagSet)
		o := NewCreateOptions()
		o.BindFlags(flags)

		fromSchedule := "schedule-name-1"
		flags.Parse([]string{"--from-schedule", fromSchedule})

		kbclient := velerotest.NewFakeControllerRuntimeClient(t).(kbclient.WithWatch)
		schedule := builder.ForSchedule(cmdtest.VeleroNameSpace, fromSchedule).Result()
		require.NoError(t, kbclient.Create(t.Context(), schedule, &controllerclient.CreateOptions{}))
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, "test-backup").FromSchedule(schedule).Phase(velerov1api.BackupPhaseCompleted).Result()
		require.NoError(t, kbclient.Create(t.Context(), backup, &controllerclient.CreateOptions{}))

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderWatchClient").Return(kbclient, nil)

		require.NoError(t, o.Complete(args, f))
		require.NoError(t, o.Validate(c, []string{}, f))
		require.NoError(t, o.Run(c, f))
	})

	t.Run("create a restore from not-existed backup", func(t *testing.T) {
		f := &factorymocks.Factory{}
		c := NewCreateCommand(f, "")
		require.Equal(t, "Create a restore", c.Short)
		flags := new(pflag.FlagSet)
		o := NewCreateOptions()
		o.BindFlags(flags)
		nonExistedBackupName := "not-exist"

		flags.Parse([]string{"--wait", "true"})
		flags.Parse([]string{"--from-backup", nonExistedBackupName})

		kbclient := velerotest.NewFakeControllerRuntimeClient(t).(kbclient.WithWatch)

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderWatchClient").Return(kbclient, nil)

		require.NoError(t, o.Complete(nil, f))
		err := o.Validate(c, []string{}, f)
		require.Equal(t, "backups.velero.io \"not-exist\" not found", err.Error())
	})

	t.Run("create a restore with resource policies configmap", func(t *testing.T) {
		f := &factorymocks.Factory{}
		c := NewCreateCommand(f, "")
		require.Equal(t, "Create a restore", c.Short)
		flags := new(pflag.FlagSet)
		o := NewCreateOptions()
		o.BindFlags(flags)

		backupName := "backup-with-policies"
		ResourcePoliciesConfigMap := "test-policies-cm"
		flags.Parse([]string{"--from-backup", backupName})
		flags.Parse([]string{"--resource-policies-configmap", ResourcePoliciesConfigMap})

		kbclient := velerotest.NewFakeControllerRuntimeClient(t).(kbclient.WithWatch)
		backup := builder.ForBackup(cmdtest.VeleroNameSpace, backupName).Phase(velerov1api.BackupPhaseCompleted).Result()
		require.NoError(t, kbclient.Create(t.Context(), backup, &controllerclient.CreateOptions{}))

		f.On("Namespace").Return(cmdtest.VeleroNameSpace)
		f.On("KubebuilderWatchClient").Return(kbclient, nil)

		require.NoError(t, o.Complete(args, f))
		require.NoError(t, o.Validate(c, []string{}, f))
		require.NoError(t, o.Run(c, f))

		// Verify the created restore object
		createdRestore := &velerov1api.Restore{}
		err := kbclient.Get(t.Context(), controllerclient.ObjectKey{Namespace: cmdtest.VeleroNameSpace, Name: name}, createdRestore)
		require.NoError(t, err)
		require.NotNil(t, createdRestore.Spec.ResourcePolicy)
		require.Equal(t, "configmap", createdRestore.Spec.ResourcePolicy.Kind)
		require.Equal(t, ResourcePoliciesConfigMap, createdRestore.Spec.ResourcePolicy.Name)
	})
}
