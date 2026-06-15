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

package k8s

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	waitutil "k8s.io/apimachinery/pkg/util/wait"

	"github.com/vmware-tanzu/velero/pkg/builder"
	veleroexec "github.com/vmware-tanzu/velero/pkg/util/exec"
)

func CreateNamespace(ctx context.Context, client TestClient, namespace string) error {
	ns := builder.ForNamespace(namespace).Result()
	// Add label to avoid PSA check.
	ns.Labels = map[string]string{
		"pod-security.kubernetes.io/enforce":         "baseline",
		"pod-security.kubernetes.io/enforce-version": "latest",
	}
	_, err := client.ClientGo.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func CreateNamespaceWithLabel(ctx context.Context, client TestClient, namespace string, label map[string]string) error {
	ns := builder.ForNamespace(namespace).Result()
	ns.Labels = label
	// Add label to avoid PSA check.
	if _, ok := ns.Labels["pod-security.kubernetes.io/enforce"]; !ok {
		ns.Labels["pod-security.kubernetes.io/enforce"] = "baseline"
	}
	if _, ok := ns.Labels["pod-security.kubernetes.io/enforce-version"]; !ok {
		ns.Labels["pod-security.kubernetes.io/enforce-version"] = "latest"
	}
	_, err := client.ClientGo.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func CreateNamespaceWithAnnotation(ctx context.Context, client TestClient, namespace string, annotation map[string]string) error {
	ns := builder.ForNamespace(namespace).Result()
	// Add label to avoid PSA check.
	ns.Labels = map[string]string{
		"pod-security.kubernetes.io/enforce":         "baseline",
		"pod-security.kubernetes.io/enforce-version": "latest",
	}
	ns.ObjectMeta.Annotations = annotation
	_, err := client.ClientGo.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func GetNamespace(ctx context.Context, client TestClient, namespace string) (*corev1api.Namespace, error) {
	return client.ClientGo.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
}

func KubectlDeleteNamespace(ctx context.Context, namespace string) error {
	args := []string{"delete", "namespace", namespace}
	fmt.Println(args)

	cmd := exec.CommandContext(ctx, "kubectl", args...)
	fmt.Println(cmd)
	stdout, stderr, err := veleroexec.RunCommand(cmd)
	fmt.Printf("Output: %v\n", stdout)
	if strings.Contains(stderr, "NotFound") {
		err = nil
	}
	return err
}

func DeleteNamespace(ctx context.Context, client TestClient, namespace string, wait bool) error {
	tenMinuteTimeout, ctxCancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer ctxCancel()

	return waitutil.PollImmediateInfinite(5*time.Second,
		func() (bool, error) {
			// Retry namespace deletion, see issue: https://github.com/kubernetes/kubernetes/issues/60807
			if err := KubectlDeleteNamespace(tenMinuteTimeout, namespace); err != nil {
				fmt.Printf("Delete namespace %s err: %v", namespace, err)
				return false, errors.Wrap(err, fmt.Sprintf("failed to delete the namespace %q", namespace))
			}
			if !wait {
				return true, nil
			}
			nsList, err := KubectlGetNS(tenMinuteTimeout, namespace)
			fmt.Println("kubectl get ns output:")
			fmt.Println(nsList)
			if err != nil {
				fmt.Printf("Get namespace %s err: %v", namespace, err)
				return false, err
			} else {
				if !slices.Contains(nsList, namespace) {
					return true, nil
				}
			}
			fmt.Printf("namespace %q is still being deleted...\n", namespace)
			logrus.Debugf("namespace %q is still being deleted...", namespace)
			return false, nil
		})
}

func CleanupNamespacesWithPoll(ctx context.Context, client TestClient, CaseBaseName string) error {
	namespaces, err := client.ClientGo.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})

	if err != nil {
		return errors.Wrap(err, "Could not retrieve namespaces")
	}
	for _, checkNamespace := range namespaces.Items {
		if strings.HasPrefix(checkNamespace.Name, CaseBaseName) {
			err := DeleteNamespace(ctx, client, checkNamespace.Name, true)
			if err != nil {
				return errors.Wrapf(err, "Could not delete namespace %s", checkNamespace.Name)
			}
			fmt.Printf("Namespace %s was deleted\n", checkNamespace.Name)
		}
	}
	return nil
}

func CleanupNamespacesFiterdByExcludes(ctx context.Context, client TestClient, excludeNS []string) error {
	namespaces, err := client.ClientGo.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})

	if err != nil {
		return errors.Wrap(err, "Could not retrieve namespaces")
	}
	for _, checkNamespace := range namespaces.Items {
		isExclude := false
		for k := range excludeNS {
			if checkNamespace.Name == excludeNS[k] {
				isExclude = true
			}
		}
		if !isExclude {
			err := DeleteNamespace(ctx, client, checkNamespace.Name, true)
			if err != nil {
				return errors.Wrapf(err, "Could not delete namespace %s", checkNamespace.Name)
			}
			fmt.Printf("Namespace %s was deleted\n", checkNamespace.Name)
		}
	}
	return nil
}

func CleanupNamespaces(ctx context.Context, client TestClient, CaseBaseName string) error {
	if ctx == nil {
		fmt.Println("ctx is nil ....")
	}
	namespaces, err := client.ClientGo.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return errors.Wrap(err, "Could not retrieve namespaces")
	}
	for _, checkNamespace := range namespaces.Items {
		if strings.HasPrefix(checkNamespace.Name, CaseBaseName) {
			err = client.ClientGo.CoreV1().Namespaces().Delete(ctx, checkNamespace.Name, metav1.DeleteOptions{})
			if err != nil {
				return errors.Wrapf(err, "Could not delete namespace %s", checkNamespace.Name)
			}
		}
	}
	return nil
}

func WaitAllSelectedNSDeleted(ctx context.Context, client TestClient, label string) error {
	return waitutil.PollImmediateInfinite(5*time.Second,
		func() (bool, error) {
			if ns, err := client.ClientGo.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: label}); err != nil {
				return false, err
			} else if ns == nil {
				return true, nil
			} else if len(ns.Items) == 0 {
				return true, nil
			} else {
				logrus.Debugf("%d namespaces is still being deleted...\n", len(ns.Items))
				return false, nil
			}
		})
}

func NamespaceShouldNotExist(ctx context.Context, client TestClient, namespace string) error {
	namespaces, err := client.ClientGo.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return errors.Wrap(err, "Could not retrieve namespaces")
	}
	for _, checkNamespace := range namespaces.Items {
		if checkNamespace.Name == namespace {
			return errors.New(fmt.Sprintf("Namespace %s still exist", checkNamespace.Name))
		}
	}
	return nil
}

func GetBackupNamespaces(ctx context.Context, client TestClient, excludeNS []string) ([]string, error) {
	namespaces, err := client.ClientGo.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Could not retrieve namespaces")
	}
	var backupNamespaces []string
	for _, checkNamespace := range namespaces.Items {
		isExclude := false
		for k := range excludeNS {
			if checkNamespace.Name == excludeNS[k] {
				isExclude = true
			}
		}
		if !isExclude {
			backupNamespaces = append(backupNamespaces, checkNamespace.Name)
		}
	}
	return backupNamespaces, nil
}

func GetMappingNamespaces(ctx context.Context, client TestClient, excludeNS []string) (string, error) {
	ns, err := GetBackupNamespaces(ctx, client, excludeNS)
	if err != nil {
		return "", errors.Wrap(err, "Could not retrieve namespaces")
	} else if len(ns) == 0 {
		return "", errors.Wrap(err, "Get empty namespaces in backup")
	}

	nsMapping := []string{}
	for _, n := range ns {
		nsMapping = append(nsMapping, n+":mapping-"+n)
	}
	joinedNsMapping := strings.Join(nsMapping, ",")
	if len(joinedNsMapping) > 0 {
		joinedNsMapping = joinedNsMapping[:len(joinedNsMapping)-1]
	}
	return joinedNsMapping, nil
}

func KubectlCreateNamespace(ctx context.Context, name string) error {
	args := []string{"create", "namespace", name}
	fmt.Println(args)
	return exec.CommandContext(ctx, "kubectl", args...).Run()
}
