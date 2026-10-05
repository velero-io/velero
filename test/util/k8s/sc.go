package k8s

import (
	"context"
	"os"

	"github.com/cockroachdb/errors"
	storagev1api "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func CreateStorageClassFromYaml(ctx context.Context, client TestClient, yamlPath string, nameOverride string) error {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return errors.Wrapf(err, "failed to read storage class yaml %s", yamlPath)
	}

	sc := &storagev1api.StorageClass{}
	if err := yaml.Unmarshal(data, sc); err != nil {
		return errors.Wrapf(err, "failed to unmarshal storage class from %s", yamlPath)
	}

	if nameOverride != "" {
		sc.Name = nameOverride
	}

	_, err = client.ClientGo.StorageV1().StorageClasses().Create(ctx, sc, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return errors.Wrapf(err, "failed to create storage class %s", sc.Name)
	}
	return nil
}

func DeleteStorageClass(ctx context.Context, client TestClient, name string) error {
	if err := client.ClientGo.StorageV1().StorageClasses().Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return errors.Wrapf(err, "Could not delete storage class %s", name)
	}
	return nil
}
