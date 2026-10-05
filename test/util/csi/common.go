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

package util

import (
	"context"
	"fmt"
	"strings"

	"github.com/cockroachdb/errors"
	volumeSnapshotV1 "github.com/kubernetes-csi/external-snapshotter/client/v8/apis/volumesnapshot/v1"
	snapshotterClientSet "github.com/kubernetes-csi/external-snapshotter/client/v8/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	. "github.com/vmware-tanzu/velero/test/util/k8s"
)

func GetClients() (*kubernetes.Clientset, *snapshotterClientSet.Clientset, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	clientConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	client, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	snapshotterClient, err := snapshotterClientSet.NewForConfig(clientConfig)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	return client, snapshotterClient, nil
}

func GetCsiSnapshotHandle(client TestClient, apiVersion string, index map[string]string) ([]string, error) {
	_, snapshotClient, err := GetClients()

	var vscList *volumeSnapshotV1.VolumeSnapshotContentList
	if err != nil {
		return nil, err
	}
	switch apiVersion {
	// case "v1beta1":
	// 	vscList, err = snapshotterClientSetV1beta1.SnapshotV1beta1().VolumeSnapshotContents().List(context.TODO(), metav1.ListOptions{})
	case "v1":
		vscList, err = snapshotClient.SnapshotV1().VolumeSnapshotContents().List(context.TODO(), metav1.ListOptions{})
	default:
		errors.New(fmt.Sprintf("API version %s is not valid", apiVersion))
	}

	if err != nil {
		return nil, err
	}

	var snapshotHandleList []string
	for _, i := range vscList.Items {
		if i.Status == nil {
			fmt.Println("VolumeSnapshotContent status is nil")
			continue
		}
		if i.Status.SnapshotHandle == nil {
			fmt.Println("SnapshotHandle is nil")
			continue
		}
		if (index["backupNameLabel"] != "" && i.Labels != nil && i.Labels["velero.io/backup-name"] == index["backupNameLabel"]) ||
			(index["namespace"] != "" && i.Spec.VolumeSnapshotRef.Namespace == index["namespace"]) {
			tmp := strings.Split(*i.Status.SnapshotHandle, "/")
			snapshotHandleList = append(snapshotHandleList, tmp[len(tmp)-1])
		}
	}

	if len(snapshotHandleList) == 0 {
		fmt.Printf("No VolumeSnapshotContent from key %v\n", index)
	} else {
		fmt.Printf("Volume snapshot content list: %v\n", snapshotHandleList)
	}
	return snapshotHandleList, nil
}

func GetVolumeSnapshotContentNameByPod(client TestClient, podName, namespace, backupName string) (string, error) {
	pvcList, err := GetPvcByPVCName(context.Background(), namespace, podName)
	if err != nil {
		return "", err
	}
	if len(pvcList) != 1 {
		return "", errors.New(fmt.Sprintf("Only 1 PVC of pod %s should be found under namespace %s", podName, namespace))
	}
	pvList, err := GetPvByPvc(context.Background(), namespace, pvcList[0])
	if err != nil {
		return "", err
	}
	if len(pvList) != 1 {
		return "", errors.New(fmt.Sprintf("Only 1 PV of PVC %s pod %s should be found under namespace %s", pvcList[0], podName, namespace))
	}
	pvValue, err := GetPersistentVolume(context.Background(), client, "", pvList[0])
	fmt.Println(pvValue.Annotations["pv.kubernetes.io/provisioned-by"])
	if err != nil {
		return "", err
	}
	_, snapshotClient, err := GetClients()
	if err != nil {
		return "", err
	}
	vsList, err := snapshotClient.SnapshotV1().VolumeSnapshots(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	for _, i := range vsList.Items {
		if pvcList[0] == *i.Spec.Source.PersistentVolumeClaimName &&
			i.Labels["velero.io/backup-name"] == backupName {
			return *i.Status.BoundVolumeSnapshotContentName, nil
		}
	}
	return "", errors.New(fmt.Sprintf("Fail to get VolumeSnapshotContentName for pod %s under namespace %s", podName, namespace))
}

func CheckVolumeSnapshotCR(client TestClient, index map[string]string, expectedCount int) ([]string, error) {
	var err error
	var snapshotContentNameList []string

	resourceName := "snapshot.storage.k8s.io"

	apiVersion, err := GetAPIVersions(&client, resourceName)
	if err != nil {
		return nil, err
	}
	if len(apiVersion) == 0 {
		return nil, errors.New("Fail to get APIVersion")
	}

	if apiVersion[0] == "v1" {
		if snapshotContentNameList, err = GetCsiSnapshotHandle(client, apiVersion[0], index); err != nil {
			return nil, errors.Wrap(err, "Fail to get CSI snapshot content")
		}
	} else {
		return nil, errors.New("API version is invalid")
	}
	if expectedCount >= 0 {
		if len(snapshotContentNameList) != expectedCount {
			return nil, errors.New(fmt.Sprintf("Snapshot content count %d is not as expect %d", len(snapshotContentNameList), expectedCount))
		}
	}
	fmt.Printf("snapshotContentNameList: %v \n", snapshotContentNameList)
	return snapshotContentNameList, nil
}
