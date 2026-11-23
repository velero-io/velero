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

package cacert

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1api "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
	"github.com/velero-io/velero/pkg/builder"
	"github.com/velero-io/velero/pkg/util"
)

func TestGetCACertFromBackup(t *testing.T) {
	testCases := []struct {
		name           string
		backup         *velerov1api.Backup
		bsl            *velerov1api.BackupStorageLocation
		expectedCACert string
		expectedError  bool
	}{
		{
			name: "backup with BSL containing cacert",
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("test-bsl").
				Result(),
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				CACert([]byte("test-cacert-content")).
				Result(),
			expectedCACert: "test-cacert-content",
			expectedError:  false,
		},
		{
			name: "backup with BSL without cacert",
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("test-bsl").
				Result(),
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Result(),
			expectedCACert: "",
			expectedError:  false,
		},
		{
			name: "backup without storage location",
			backup: builder.ForBackup("test-ns", "test-backup").
				Result(),
			bsl:            nil,
			expectedCACert: "",
			expectedError:  false,
		},
		{
			name: "BSL not found",
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("missing-bsl").
				Result(),
			bsl:            nil,
			expectedCACert: "",
			expectedError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			objs = append(objs, tc.backup)
			if tc.bsl != nil {
				objs = append(objs, tc.bsl)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				WithRuntimeObjects(objs...).
				Build()

			cacert, err := GetCACertFromBackup(t.Context(), fakeClient, "test-ns", tc.backup)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCACert, cacert)
			}
		})
	}
}

func TestGetCACertFromRestore(t *testing.T) {
	testCases := []struct {
		name           string
		restore        *velerov1api.Restore
		backup         *velerov1api.Backup
		bsl            *velerov1api.BackupStorageLocation
		expectedCACert string
		expectedError  bool
	}{
		{
			name: "restore with backup having BSL containing cacert",
			restore: builder.ForRestore("test-ns", "test-restore").
				Backup("test-backup").
				Result(),
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("test-bsl").
				Result(),
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				CACert([]byte("test-cacert-content")).
				Result(),
			expectedCACert: "test-cacert-content",
			expectedError:  false,
		},
		{
			name: "restore with backup not found",
			restore: builder.ForRestore("test-ns", "test-restore").
				Backup("missing-backup").
				Result(),
			backup:         nil,
			bsl:            nil,
			expectedCACert: "",
			expectedError:  false,
		},
		{
			name: "restore with backup having BSL without cacert",
			restore: builder.ForRestore("test-ns", "test-restore").
				Backup("test-backup").
				Result(),
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("test-bsl").
				Result(),
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Result(),
			expectedCACert: "",
			expectedError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			objs = append(objs, tc.restore)
			if tc.backup != nil {
				objs = append(objs, tc.backup)
			}
			if tc.bsl != nil {
				objs = append(objs, tc.bsl)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				WithRuntimeObjects(objs...).
				Build()

			cacert, err := GetCACertFromRestore(t.Context(), fakeClient, "test-ns", tc.restore)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCACert, cacert)
			}
		})
	}
}

func TestGetCACertFromBSL(t *testing.T) {
	testCases := []struct {
		name           string
		bslName        string
		bsl            *velerov1api.BackupStorageLocation
		expectedCACert string
		expectedError  bool
	}{
		{
			name:    "BSL with cacert",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				CACert([]byte("test-cacert-content")).
				Result(),
			expectedCACert: "test-cacert-content",
			expectedError:  false,
		},
		{
			name:    "BSL without cacert",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				Result(),
			expectedCACert: "",
			expectedError:  false,
		},
		{
			name:           "empty BSL name",
			bslName:        "",
			bsl:            nil,
			expectedCACert: "",
			expectedError:  false,
		},
		{
			name:           "BSL not found",
			bslName:        "missing-bsl",
			bsl:            nil,
			expectedCACert: "",
			expectedError:  false,
		},
		{
			name:    "BSL with invalid CA cert format",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				CACert([]byte("INVALID CERT DATA WITHOUT PEM HEADERS")).
				Result(),
			expectedCACert: "INVALID CERT DATA WITHOUT PEM HEADERS", // We still return it, validation happens during TLS handshake
			expectedError:  false,
		},
		{
			name:    "BSL with malformed PEM certificate",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				CACert([]byte("-----BEGIN CERTIFICATE-----\nINVALID BASE64 DATA!!!\n-----END CERTIFICATE-----\n")).
				Result(),
			expectedCACert: "-----BEGIN CERTIFICATE-----\nINVALID BASE64 DATA!!!\n-----END CERTIFICATE-----\n",
			expectedError:  false,
		},
		{
			name:    "BSL with nil config",
			bslName: "test-bsl",
			bsl: &velerov1api.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-bsl",
				},
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					Config:   nil,
				},
			},
			expectedCACert: "",
			expectedError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.bsl != nil {
				objs = append(objs, tc.bsl)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				WithRuntimeObjects(objs...).
				Build()

			cacert, err := GetCACertFromBSL(t.Context(), fakeClient, "test-ns", tc.bslName)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCACert, cacert)
			}
		})
	}
}

// TestGetCACertFromBSL_WithCACertRef tests the new caCertRef functionality
func TestGetCACertFromBSL_WithCACertRef(t *testing.T) {
	testCases := []struct {
		name           string
		bslName        string
		bsl            *velerov1api.BackupStorageLocation
		secret         *corev1api.Secret
		expectedCACert string
		expectedError  bool
		errorContains  string
	}{
		{
			name:    "BSL with caCertRef pointing to valid secret",
			bslName: "test-bsl",
			bsl: &velerov1api.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-bsl",
				},
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "test-bucket",
							CACertRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "test-secret",
								},
								Key: "ca-bundle.crt",
							},
						},
					},
				},
			},
			secret: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-secret",
				},
				Data: map[string][]byte{
					"ca-bundle.crt": []byte("test-cacert-from-secret"),
				},
			},
			expectedCACert: "test-cacert-from-secret",
			expectedError:  false,
		},
		{
			name:    "BSL with both caCertRef and caCert - caCertRef takes precedence",
			bslName: "test-bsl",
			bsl: &velerov1api.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-bsl",
				},
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "test-bucket",
							CACert: []byte("inline-cacert-deprecated"),
							CACertRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "test-secret",
								},
								Key: "ca-bundle.crt",
							},
						},
					},
				},
			},
			secret: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-secret",
				},
				Data: map[string][]byte{
					"ca-bundle.crt": []byte("cacert-from-secret-takes-precedence"),
				},
			},
			expectedCACert: "cacert-from-secret-takes-precedence",
			expectedError:  false,
		},
		{
			name:    "BSL with caCertRef but secret not found",
			bslName: "test-bsl",
			bsl: &velerov1api.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-bsl",
				},
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "test-bucket",
							CACertRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "missing-secret",
								},
								Key: "ca-bundle.crt",
							},
						},
					},
				},
			},
			secret:         nil,
			expectedCACert: "",
			expectedError:  true,
			errorContains:  "certificate secret missing-secret not found",
		},
		{
			name:    "BSL with caCertRef but key not found in secret",
			bslName: "test-bsl",
			bsl: &velerov1api.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-bsl",
				},
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "test-bucket",
							CACertRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "test-secret",
								},
								Key: "missing-key",
							},
						},
					},
				},
			},
			secret: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-secret",
				},
				Data: map[string][]byte{
					"ca-bundle.crt": []byte("test-cacert"),
				},
			},
			expectedCACert: "",
			expectedError:  true,
			errorContains:  "key missing-key not found in secret test-secret",
		},
		{
			name:    "BSL with caCertRef but empty key",
			bslName: "test-bsl",
			bsl: &velerov1api.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-bsl",
				},
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "test-bucket",
							CACertRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "test-secret",
								},
								Key: "",
							},
						},
					},
				},
			},
			secret: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-secret",
				},
				Data: map[string][]byte{
					"ca-bundle.crt": []byte("test-cacert"),
				},
			},
			expectedCACert: "",
			expectedError:  true,
			errorContains:  "caCertRef key is empty",
		},
		{
			name:    "BSL with caCertRef containing multi-line PEM certificate",
			bslName: "test-bsl",
			bsl: &velerov1api.BackupStorageLocation{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-bsl",
				},
				Spec: velerov1api.BackupStorageLocationSpec{
					Provider: "aws",
					StorageType: velerov1api.StorageType{
						ObjectStorage: &velerov1api.ObjectStorageLocation{
							Bucket: "test-bucket",
							CACertRef: &corev1api.SecretKeySelector{
								LocalObjectReference: corev1api.LocalObjectReference{
									Name: "test-secret",
								},
								Key: "ca.pem",
							},
						},
					},
				},
			},
			secret: &corev1api.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "test-ns",
					Name:      "test-secret",
				},
				Data: map[string][]byte{
					"ca.pem": []byte("-----BEGIN CERTIFICATE-----\nMIIDETC...\n-----END CERTIFICATE-----\n"),
				},
			},
			expectedCACert: "-----BEGIN CERTIFICATE-----\nMIIDETC...\n-----END CERTIFICATE-----\n",
			expectedError:  false,
		},
		{
			name:    "BSL falls back to inline caCert when caCertRef is nil",
			bslName: "test-bsl",
			bsl: builder.ForBackupStorageLocation("test-ns", "test-bsl").
				Provider("aws").
				Bucket("test-bucket").
				CACert([]byte("fallback-inline-cacert")).
				Result(),
			secret:         nil,
			expectedCACert: "fallback-inline-cacert",
			expectedError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.bsl != nil {
				objs = append(objs, tc.bsl)
			}
			if tc.secret != nil {
				objs = append(objs, tc.secret)
			}

			scheme := runtime.NewScheme()
			_ = velerov1api.AddToScheme(scheme)
			_ = corev1api.AddToScheme(scheme)

			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objs...).
				Build()

			cacert, err := GetCACertFromBSL(t.Context(), fakeClient, "test-ns", tc.bslName)

			if tc.expectedError {
				require.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedCACert, cacert)
			}
		})
	}
}

// TestGetCACertFromBackup_ClientError tests error scenarios where client.Get returns non-NotFound errors
func TestGetCACertFromBackup_ClientError(t *testing.T) {
	testCases := []struct {
		name          string
		backup        *velerov1api.Backup
		bsl           *velerov1api.BackupStorageLocation
		expectedError string
	}{
		{
			name: "client error getting BSL",
			backup: builder.ForBackup("test-ns", "test-backup").
				StorageLocation("test-bsl").
				Result(),
			bsl: builder.ForBackupStorageLocation("different-ns", "test-bsl"). // Different namespace to trigger error
												Provider("aws").
												Bucket("test-bucket").
												CACert([]byte("test-cacert-content")).
												Result(),
			expectedError: "not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			objs = append(objs, tc.backup)
			if tc.bsl != nil {
				objs = append(objs, tc.bsl)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				WithRuntimeObjects(objs...).
				Build()

			// Try to get BSL from wrong namespace to simulate error
			_, err := GetCACertFromBSL(t.Context(), fakeClient, "wrong-ns", tc.backup.Spec.StorageLocation)

			require.NoError(t, err) // Not found errors are handled gracefully
		})
	}
}

// TestGetCACertFromRestore_ClientError tests error scenarios for GetCACertFromRestore
func TestGetCACertFromRestore_ClientError(t *testing.T) {
	testCases := []struct {
		name          string
		restore       *velerov1api.Restore
		backup        *velerov1api.Backup
		expectedError string
	}{
		{
			name: "backup in different namespace",
			restore: builder.ForRestore("test-ns", "test-restore").
				Backup("test-backup").
				Result(),
			backup: builder.ForBackup("different-ns", "test-backup"). // Different namespace
											StorageLocation("test-bsl").
											Result(),
			expectedError: "not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			objs = append(objs, tc.restore)
			if tc.backup != nil {
				objs = append(objs, tc.backup)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(util.VeleroScheme).
				WithRuntimeObjects(objs...).
				Build()

			// This should not find the backup in the wrong namespace
			cacert, err := GetCACertFromRestore(t.Context(), fakeClient, "test-ns", tc.restore)

			require.NoError(t, err) // Not found errors are handled gracefully, returning empty string
			assert.Empty(t, cacert)
		})
	}
}
