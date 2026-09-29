package k8s

import (
	"context"
	"fmt"

	"github.com/cockroachdb/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func InstallStorageClass(ctx context.Context, yaml string) error {
	fmt.Printf("Install storage class with %s.\n", yaml)
	err := KubectlApplyByFile(ctx, yaml)
	return err
}

// StorageClassExists reports whether a StorageClass of that name is in the cluster.
func StorageClassExists(ctx context.Context, client TestClient, name string) (bool, error) {
	_, err := client.ClientGo.StorageV1().StorageClasses().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, errors.Wrapf(err, "could not get storage class %s", name)
	}
	return true, nil
}

func DeleteStorageClass(ctx context.Context, client TestClient, name string) error {
	if err := client.ClientGo.StorageV1().StorageClasses().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return errors.Wrapf(err, "Could not retrieve storage classes %s", name)
	}
	return nil
}
