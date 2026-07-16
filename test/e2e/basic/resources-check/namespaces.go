/*
Copyright the Velero contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the Licensm.
You may obtain a copy of the License at

    http://www.apachm.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the Licensm.
*/

package basic

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/vmware-tanzu/velero/test/e2e/test"
	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

type MultiNSBackup struct {
	TestCase
	IsScaleTest     bool
	NSExcluded      *[]string
	TimeoutDuration time.Duration
}

func (m *MultiNSBackup) Init() error {
	m.TestCase.Init()
	m.CaseBaseName = "nstest-" + m.UUIDgen
	m.BackupName = "backup-" + m.CaseBaseName
	m.RestoreName = "restore-" + m.CaseBaseName
	m.NSExcluded = &[]string{}

	if m.IsScaleTest {
		m.NamespacesTotal = 2500
		m.TimeoutDuration = time.Hour * 2
		m.TestMsg = &TestMSG{
			Text:      "When I create 2500 namespaces should be successfully backed up and restored",
			FailedMSG: "Failed to successfully backup and restore multiple namespaces",
		}
	} else {
		m.NamespacesTotal = 2
		m.TimeoutDuration = time.Minute * 10
		m.TestMsg = &TestMSG{
			Text:      "When I create 2 namespaces should be successfully backed up and restored",
			FailedMSG: "Failed to successfully backup and restore multiple namespaces",
		}
	}

	// Currently it's hard to build a large list of namespaces to include and wildcards do not work so instead
	// we will exclude all of the namespaces that existed prior to the test from the backup
	namespaces, err := m.Client.ClientGo.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return errors.Wrap(err, "Could not retrieve namespaces")
	}

	for _, excludeNamespace := range namespaces.Items {
		*m.NSExcluded = append(*m.NSExcluded, excludeNamespace.Name)
	}
	// Add Velero installed namespace into the exclude list.
	*m.NSExcluded = append(*m.NSExcluded, m.VeleroCfg.VeleroNamespace)

	m.BackupArgs = []string{
		"create", "--namespace", m.VeleroCfg.VeleroNamespace, "backup", m.BackupName,
		"--exclude-namespaces", strings.Join(*m.NSExcluded, ","),
		"--default-volumes-to-fs-backup", "--wait",
	}

	m.RestoreArgs = []string{
		"create", "--namespace", m.VeleroCfg.VeleroNamespace, "restore", m.RestoreName,
		"--from-backup", m.BackupName, "--wait",
	}
	return nil
}

func (m *MultiNSBackup) CreateResources() error {
	fmt.Printf("Creating namespaces ...\n")
	labels := map[string]string{
		"ns-test": "true",
	}
	for nsNum := 0; nsNum < m.NamespacesTotal; nsNum++ {
		createNSName := fmt.Sprintf("%s-%00000d", m.CaseBaseName, nsNum)
		if err := CreateNamespaceWithLabel(m.Ctx, m.Client, createNSName, labels); err != nil {
			return errors.Wrapf(err, "Failed to create namespace %s", createNSName)
		}
	}
	return nil
}

func (m *MultiNSBackup) Verify() error {
	// Verify that we got back all of the namespaces we created
	for nsNum := 0; nsNum < m.NamespacesTotal; nsNum++ {
		checkNSName := fmt.Sprintf("%s-%00000d", m.CaseBaseName, nsNum)
		checkNS, err := GetNamespace(m.Ctx, m.Client, checkNSName)
		if err != nil {
			return errors.Wrapf(err, "Could not retrieve test namespace %s", checkNSName)
		} else if checkNS.Name != checkNSName {
			return errors.Errorf("Retrieved namespace for %s has name %s instead", checkNSName, checkNS.Name)
		}
	}
	return nil
}

func (m *MultiNSBackup) Destroy() error {
	err := CleanupNamespaces(m.Ctx, m.Client, m.CaseBaseName)
	if err != nil {
		return errors.Wrap(err, "Could cleanup retrieve namespaces")
	}
	return WaitAllSelectedNSDeleted(m.Ctx, m.Client, "ns-test=true")
}
