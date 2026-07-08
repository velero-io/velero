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

package controller

import (
	"bytes"
	"context"
	"net"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	appsv1api "k8s.io/api/apps/v1"
	corev1api "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/bslworker"
	"github.com/vmware-tanzu/velero/pkg/constant"
)

const (
	// bslWorkerFinalizer is added to worker-backed BackupStorageLocations so their
	// worker Deployment/Service/Secret can be torn down before the BSL is removed.
	bslWorkerFinalizer = "velero.io/bsl-worker"

	// workerNamespaceAnnotation records the namespace a BSL's worker resources were
	// created in. Because worker resources can live in a tenant namespace (not the
	// Velero namespace) and cross-namespace owner references are impossible, this
	// annotation lets teardown find those resources even after Spec.Worker (and thus
	// its Namespace) has been cleared or changed.
	workerNamespaceAnnotation = "velero.io/bsl-worker-namespace"

	veleroDeploymentName = "velero"
)

// BackupStorageLocationWorkerReconciler reconciles BackupStorageLocations that set
// Spec.Worker into a dedicated worker Deployment, Service, and mutual-TLS Secret so
// the location's object-store operations run under the worker's identity. It runs
// only when the EnableBSLWorkerIdentity feature flag is enabled.
type BackupStorageLocationWorkerReconciler struct {
	client          client.Client
	apiReader       client.Reader
	veleroNamespace string
	ca              *bslworker.CA
	getterFactory   *bslworker.WorkerGetterFactory
	logLevel        string
	logFormat       string
	log             logrus.FieldLogger
}

// NewBackupStorageLocationWorkerReconciler returns a new worker reconciler. apiReader
// must be an uncached reader (e.g. mgr.GetAPIReader()) so worker resources can be read
// in tenant namespaces outside the manager's cached Velero namespace.
func NewBackupStorageLocationWorkerReconciler(
	client client.Client,
	apiReader client.Reader,
	veleroNamespace string,
	ca *bslworker.CA,
	getterFactory *bslworker.WorkerGetterFactory,
	logLevel string,
	logFormat string,
	log logrus.FieldLogger,
) *BackupStorageLocationWorkerReconciler {
	return &BackupStorageLocationWorkerReconciler{
		client:          client,
		apiReader:       apiReader,
		veleroNamespace: veleroNamespace,
		ca:              ca,
		getterFactory:   getterFactory,
		logLevel:        logLevel,
		logFormat:       logFormat,
		log:             log,
	}
}

// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services;secrets,verbs=get;list;watch;create;update;patch;delete

func (r *BackupStorageLocationWorkerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.log.WithField("controller", "backupStorageLocationWorker").WithField("backupStorageLocation", req.NamespacedName.String())

	var location velerov1api.BackupStorageLocation
	if err := r.client.Get(ctx, req.NamespacedName, &location); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, errors.Wrap(err, "getting BackupStorageLocation")
	}

	recordedNamespace := location.Annotations[workerNamespaceAnnotation]

	// Teardown path: BSL is being deleted, or no longer wants a worker.
	if !location.DeletionTimestamp.IsZero() || location.Spec.Worker == nil {
		if controllerutil.ContainsFinalizer(&location, bslWorkerFinalizer) {
			// Prefer the recorded namespace, since Spec.Worker (and its Namespace)
			// may already be gone; fall back for objects created before the
			// annotation existed.
			namespace := recordedNamespace
			if namespace == "" {
				namespace = r.veleroNamespace
				if location.Spec.Worker != nil {
					namespace = bslworker.WorkerNamespace(location.Spec.Worker, r.veleroNamespace)
				}
			}
			if err := r.teardownWorker(ctx, &location, namespace, log); err != nil {
				return ctrl.Result{}, err
			}
			original := location.DeepCopy()
			controllerutil.RemoveFinalizer(&location, bslWorkerFinalizer)
			delete(location.Annotations, workerNamespaceAnnotation)
			if err := r.client.Patch(ctx, &location, client.MergeFrom(original)); err != nil {
				return ctrl.Result{}, errors.Wrap(err, "removing worker finalizer")
			}
		}
		return ctrl.Result{}, nil
	}

	namespace := bslworker.WorkerNamespace(location.Spec.Worker, r.veleroNamespace)

	// If the worker namespace changed, tear down the resources in the old namespace
	// before (re)creating them in the new one, so they are not orphaned.
	if recordedNamespace != "" && recordedNamespace != namespace {
		if err := r.teardownWorker(ctx, &location, recordedNamespace, log); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "tearing down worker in previous namespace")
		}
	}

	// Ensure the finalizer and recorded namespace are present before creating any
	// worker resources, so teardown can always find them.
	if !controllerutil.ContainsFinalizer(&location, bslWorkerFinalizer) || location.Annotations[workerNamespaceAnnotation] != namespace {
		original := location.DeepCopy()
		controllerutil.AddFinalizer(&location, bslWorkerFinalizer)
		if location.Annotations == nil {
			location.Annotations = map[string]string{}
		}
		location.Annotations[workerNamespaceAnnotation] = namespace
		if err := r.client.Patch(ctx, &location, client.MergeFrom(original)); err != nil {
			return ctrl.Result{}, errors.Wrap(err, "recording worker finalizer and namespace")
		}
	}

	if err := r.ensureTLSSecret(ctx, &location, namespace, log); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "ensuring worker TLS secret")
	}

	if err := r.ensureService(ctx, &location, namespace, log); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "ensuring worker Service")
	}

	if err := r.ensureDeployment(ctx, &location, namespace, log); err != nil {
		return ctrl.Result{}, errors.Wrap(err, "ensuring worker Deployment")
	}

	return ctrl.Result{}, nil
}

// ensureTLSSecret creates the per-worker mutual-TLS Secret (CA + server cert/key) if
// it does not already exist, and reissues the server certificate when it is missing,
// approaching expiry, or no longer signed by the current CA. The server certificate
// is issued for the worker Service DNS name so the central client can verify it.
func (r *BackupStorageLocationWorkerReconciler) ensureTLSSecret(ctx context.Context, location *velerov1api.BackupStorageLocation, namespace string, log logrus.FieldLogger) error {
	name := bslworker.WorkerTLSSecretName(location.Name)
	key := types.NamespacedName{Name: name, Namespace: namespace}

	var existing corev1api.Secret
	err := r.apiReader.Get(ctx, key, &existing)
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "getting worker TLS secret")
	}
	found := err == nil

	if found {
		// Reissue if the CA rotated (stored CA differs) or the cert is near expiry.
		caCurrent := bytes.Equal(existing.Data[bslworker.CACertFileName], r.ca.CertPEM)
		if caCurrent && !bslworker.CertNeedsRenewal(existing.Data[bslworker.ServerCertFileName]) {
			return nil
		}
	}

	dns := bslworker.WorkerServiceDNS(location.Name, namespace)
	serverPair, err := r.ca.IssueServerCert(dns, []string{dns, bslworker.WorkerServiceName(location.Name)}, []net.IP{})
	if err != nil {
		return errors.Wrap(err, "issuing worker server certificate")
	}

	data := map[string][]byte{
		bslworker.CACertFileName:     r.ca.CertPEM,
		bslworker.ServerCertFileName: serverPair.CertPEM,
		bslworker.ServerKeyFileName:  serverPair.KeyPEM,
	}

	if found {
		existing.Data = data
		if err := r.client.Update(ctx, &existing); err != nil {
			return errors.Wrap(err, "renewing worker TLS secret")
		}
		log.Info("Renewed worker TLS secret")
		return nil
	}

	secret := &corev1api.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    bslworker.WorkerSelectorLabels(location.Name),
		},
		Type: corev1api.SecretTypeTLS,
		Data: data,
	}

	if err := r.client.Create(ctx, secret); err != nil && !apierrors.IsAlreadyExists(err) {
		return errors.Wrap(err, "creating worker TLS secret")
	}
	log.Info("Created worker TLS secret")
	return nil
}

func (r *BackupStorageLocationWorkerReconciler) ensureService(ctx context.Context, location *velerov1api.BackupStorageLocation, namespace string, log logrus.FieldLogger) error {
	desired := bslworker.BuildWorkerService(location, namespace)

	var existing corev1api.Service
	err := r.apiReader.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: namespace}, &existing)
	if apierrors.IsNotFound(err) {
		if err := r.client.Create(ctx, desired); err != nil && !apierrors.IsAlreadyExists(err) {
			return errors.Wrap(err, "creating worker Service")
		}
		log.Info("Created worker Service")
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "getting worker Service")
	}

	existing.Spec.Selector = desired.Spec.Selector
	existing.Spec.Ports = desired.Spec.Ports
	if err := r.client.Update(ctx, &existing); err != nil {
		return errors.Wrap(err, "updating worker Service")
	}
	return nil
}

func (r *BackupStorageLocationWorkerReconciler) ensureDeployment(ctx context.Context, location *velerov1api.BackupStorageLocation, namespace string, log logrus.FieldLogger) error {
	var veleroDeployment appsv1api.Deployment
	if err := r.apiReader.Get(ctx, types.NamespacedName{Name: veleroDeploymentName, Namespace: r.veleroNamespace}, &veleroDeployment); err != nil {
		return errors.Wrap(err, "getting Velero server deployment")
	}

	desired := bslworker.BuildWorkerDeployment(location, &veleroDeployment, namespace, r.logLevel, r.logFormat)

	var existing appsv1api.Deployment
	err := r.apiReader.Get(ctx, types.NamespacedName{Name: desired.Name, Namespace: namespace}, &existing)
	if apierrors.IsNotFound(err) {
		if err := r.client.Create(ctx, desired); err != nil && !apierrors.IsAlreadyExists(err) {
			return errors.Wrap(err, "creating worker Deployment")
		}
		log.Info("Created worker Deployment")
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "getting worker Deployment")
	}

	existing.Spec = desired.Spec
	if err := r.client.Update(ctx, &existing); err != nil {
		return errors.Wrap(err, "updating worker Deployment")
	}
	return nil
}

// teardownWorker deletes the worker Deployment, Service, and TLS Secret for a BSL in
// the given namespace and drops any cached client connection to it. The namespace is
// passed explicitly (rather than re-derived from Spec.Worker) because Spec.Worker may
// already be nil or point at a different namespace than where the resources live.
func (r *BackupStorageLocationWorkerReconciler) teardownWorker(ctx context.Context, location *velerov1api.BackupStorageLocation, namespace string, log logrus.FieldLogger) error {
	objects := []client.Object{
		&appsv1api.Deployment{ObjectMeta: metav1.ObjectMeta{Name: bslworker.WorkerDeploymentName(location.Name), Namespace: namespace}},
		&corev1api.Service{ObjectMeta: metav1.ObjectMeta{Name: bslworker.WorkerServiceName(location.Name), Namespace: namespace}},
		&corev1api.Secret{ObjectMeta: metav1.ObjectMeta{Name: bslworker.WorkerTLSSecretName(location.Name), Namespace: namespace}},
	}
	for _, obj := range objects {
		if err := r.client.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return errors.Wrapf(err, "deleting worker resource %T", obj)
		}
	}

	if r.getterFactory != nil {
		r.getterFactory.Forget(location.Name, namespace)
	}

	log.WithField("workerNamespace", namespace).Info("Tore down worker resources")
	return nil
}

// SetupWithManager registers the reconciler, watching BackupStorageLocations. It
// reconciles on all BSL events (including deletion) because worker reconciliation is
// idempotent and must observe finalizer/deletion transitions.
func (r *BackupStorageLocationWorkerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(constant.ControllerBackupStorageLocation + "-worker").
		For(&velerov1api.BackupStorageLocation{}).
		Complete(r)
}
