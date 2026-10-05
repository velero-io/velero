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
	"context"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocks "k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"github.com/vmware-tanzu/velero/internal/velero"
	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/buildinfo"
	"github.com/vmware-tanzu/velero/pkg/constant"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework"
	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
)

const (
	ttl                       = time.Minute
	statusRequestResyncPeriod = 5 * time.Minute
)

type PluginLister interface {
	// List returns all PluginIdentifiers for kind.
	List(kind common.PluginKind) []framework.PluginIdentifier
}

// serverStatusRequestReconciler reconciles a ServerStatusRequest object
type serverStatusRequestReconciler struct {
	client         client.Client
	ctx            context.Context
	pluginRegistry PluginLister
	clock          clocks.WithTickerAndDelayedExecution

	log logrus.FieldLogger
}

// NewServerStatusRequestReconciler initializes and returns serverStatusRequestReconciler struct.
func NewServerStatusRequestReconciler(
	ctx context.Context,
	client client.Client,
	pluginRegistry PluginLister,
	clock clocks.WithTickerAndDelayedExecution,
	log logrus.FieldLogger) *serverStatusRequestReconciler {
	return &serverStatusRequestReconciler{
		client:         client,
		ctx:            ctx,
		pluginRegistry: pluginRegistry,
		clock:          clock,
		log:            log,
	}
}

// +kubebuilder:rbac:groups=velero.io,resources=serverstatusrequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=velero.io,resources=serverstatusrequests/status,verbs=get;update;patch

func (r *serverStatusRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.log.WithFields(logrus.Fields{
		"controller":          constant.ControllerServerStatusRequest,
		"serverStatusRequest": req.NamespacedName,
	})

	// Fetch the ServerStatusRequest instance.
	log.Debug("Getting ServerStatusRequest")
	statusRequest := &velerov1api.ServerStatusRequest{}
	if err := r.client.Get(r.ctx, req.NamespacedName, statusRequest); err != nil {
		if apierrors.IsNotFound(err) {
			log.Debug("Unable to find ServerStatusRequest")
			return ctrl.Result{}, nil
		}

		log.WithError(err).Error("Error getting ServerStatusRequest")
		return ctrl.Result{}, err
	}

	log = r.log.WithFields(logrus.Fields{
		"controller":          constant.ControllerServerStatusRequest,
		"serverStatusRequest": req.NamespacedName,
		"phase":               statusRequest.Status.Phase,
	})

	switch statusRequest.Status.Phase {
	case "", velerov1api.ServerStatusRequestPhaseNew:
		log.Info("Processing new ServerStatusRequest")
		original := statusRequest.DeepCopy()
		statusRequest.Status.ServerVersion = buildinfo.Version
		statusRequest.Status.Phase = velerov1api.ServerStatusRequestPhaseProcessed
		statusRequest.Status.ProcessedTimestamp = &metav1.Time{Time: r.clock.Now()}
		statusRequest.Status.Plugins = velero.GetInstalledPluginInfo(r.pluginRegistry)

		if err := r.client.Patch(r.ctx, statusRequest, client.MergeFrom(original)); err != nil {
			log.WithError(err).Error("Error updating ServerStatusRequest status")
			return ctrl.Result{RequeueAfter: statusRequestResyncPeriod}, err
		}
	case velerov1api.ServerStatusRequestPhaseProcessed:
		log.Debug("Checking whether ServerStatusRequest has expired")
		expiration := statusRequest.Status.ProcessedTimestamp.Add(ttl)
		if expiration.After(r.clock.Now()) {
			log.Debug("ServerStatusRequest has not expired")
			return ctrl.Result{RequeueAfter: statusRequestResyncPeriod}, nil
		}

		log.Debug("ServerStatusRequest has expired, deleting it")
		if err := r.client.Delete(r.ctx, statusRequest); err != nil {
			log.WithError(err).Error("Unable to delete the request")
			return ctrl.Result{}, nil
		}
	default:
		return ctrl.Result{}, errors.New("unexpected ServerStatusRequest phase")
	}

	// Requeue is mostly to handle deleting any expired status requests that were not
	// deleted as part of the normal client flow for whatever reason.
	return ctrl.Result{RequeueAfter: statusRequestResyncPeriod}, nil
}

func (r *serverStatusRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&velerov1api.ServerStatusRequest{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 10,
		}).
		Complete(r)
}
