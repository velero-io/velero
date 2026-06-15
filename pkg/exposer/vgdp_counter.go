package exposer

import (
	"context"
	"sync/atomic"

	"github.com/cockroachdb/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	velerov1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	velerov2alpha1api "github.com/vmware-tanzu/velero/pkg/apis/velero/v2alpha1"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	ctlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type dynamicQueueLength struct {
	queueLength int
	changeID    uint64
}

type VgdpCounter struct {
	client             ctlclient.Client
	allowedQueueLength int

	duState  dynamicQueueLength
	ddState  dynamicQueueLength
	pvbState dynamicQueueLength
	pvrState dynamicQueueLength

	duCacheState  dynamicQueueLength
	ddCacheState  dynamicQueueLength
	pvbCacheState dynamicQueueLength
	pvrCacheState dynamicQueueLength
}

func StartVgdpCounter(ctx context.Context, mgr manager.Manager, queueLength int) (*VgdpCounter, error) {
	counter := &VgdpCounter{
		client:             mgr.GetClient(),
		allowedQueueLength: queueLength,
	}

	atomic.StoreUint64(&counter.duState.changeID, 1)
	atomic.StoreUint64(&counter.ddState.changeID, 1)
	atomic.StoreUint64(&counter.pvbState.changeID, 1)
	atomic.StoreUint64(&counter.pvrState.changeID, 1)

	if err := counter.initListeners(ctx, mgr); err != nil {
		return nil, err
	}

	return counter, nil
}

func (w *VgdpCounter) initListeners(ctx context.Context, mgr manager.Manager) error {
	duInformer, err := mgr.GetCache().GetInformer(ctx, &velerov2alpha1api.DataUpload{})
	if err != nil {
		return errors.Wrap(err, "error getting du informer")
	}

	if _, err := duInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj any) {
				oldDu := oldObj.(*velerov2alpha1api.DataUpload)
				newDu := newObj.(*velerov2alpha1api.DataUpload)

				if oldDu.Status.Phase == newDu.Status.Phase {
					return
				}

				if newDu.Status.Phase == velerov2alpha1api.DataUploadPhaseAccepted ||
					oldDu.Status.Phase == velerov2alpha1api.DataUploadPhasePrepared ||
					oldDu.Status.Phase == velerov2alpha1api.DataUploadPhaseAccepted && newDu.Status.Phase != velerov2alpha1api.DataUploadPhasePrepared {
					atomic.AddUint64(&w.duState.changeID, 1)
				}
			},
		},
	); err != nil {
		return errors.Wrap(err, "error registering du handler")
	}

	ddInformer, err := mgr.GetCache().GetInformer(ctx, &velerov2alpha1api.DataDownload{})
	if err != nil {
		return errors.Wrap(err, "error getting dd informer")
	}

	if _, err := ddInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj any) {
				oldDd := oldObj.(*velerov2alpha1api.DataDownload)
				newDd := newObj.(*velerov2alpha1api.DataDownload)

				if oldDd.Status.Phase == newDd.Status.Phase {
					return
				}

				if newDd.Status.Phase == velerov2alpha1api.DataDownloadPhaseAccepted ||
					oldDd.Status.Phase == velerov2alpha1api.DataDownloadPhasePrepared ||
					oldDd.Status.Phase == velerov2alpha1api.DataDownloadPhaseAccepted && newDd.Status.Phase != velerov2alpha1api.DataDownloadPhasePrepared {
					atomic.AddUint64(&w.ddState.changeID, 1)
				}
			},
		},
	); err != nil {
		return errors.Wrap(err, "error registering dd handler")
	}

	pvbInformer, err := mgr.GetCache().GetInformer(ctx, &velerov1api.PodVolumeBackup{})
	if err != nil {
		return errors.Wrap(err, "error getting PVB informer")
	}

	if _, err := pvbInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj any) {
				oldPvb := oldObj.(*velerov1api.PodVolumeBackup)
				newPvb := newObj.(*velerov1api.PodVolumeBackup)

				if oldPvb.Status.Phase == newPvb.Status.Phase {
					return
				}

				if newPvb.Status.Phase == velerov1api.PodVolumeBackupPhaseAccepted ||
					oldPvb.Status.Phase == velerov1api.PodVolumeBackupPhasePrepared ||
					oldPvb.Status.Phase == velerov1api.PodVolumeBackupPhaseAccepted && newPvb.Status.Phase != velerov1api.PodVolumeBackupPhasePrepared {
					atomic.AddUint64(&w.pvbState.changeID, 1)
				}
			},
		},
	); err != nil {
		return errors.Wrap(err, "error registering PVB handler")
	}

	pvrInformer, err := mgr.GetCache().GetInformer(ctx, &velerov1api.PodVolumeRestore{})
	if err != nil {
		return errors.Wrap(err, "error getting PVR informer")
	}

	if _, err := pvrInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj any) {
				oldPvr := oldObj.(*velerov1api.PodVolumeRestore)
				newPvr := newObj.(*velerov1api.PodVolumeRestore)

				if oldPvr.Status.Phase == newPvr.Status.Phase {
					return
				}

				if newPvr.Status.Phase == velerov1api.PodVolumeRestorePhaseAccepted ||
					oldPvr.Status.Phase == velerov1api.PodVolumeRestorePhasePrepared ||
					oldPvr.Status.Phase == velerov1api.PodVolumeRestorePhaseAccepted && newPvr.Status.Phase != velerov1api.PodVolumeRestorePhasePrepared {
					atomic.AddUint64(&w.pvrState.changeID, 1)
				}
			},
		},
	); err != nil {
		return errors.Wrap(err, "error registering PVR handler")
	}

	return nil
}

func (w *VgdpCounter) IsConstrained(ctx context.Context, log logrus.FieldLogger) bool {
	id := atomic.LoadUint64(&w.duState.changeID)
	if id != w.duCacheState.changeID {
		duList := &velerov2alpha1api.DataUploadList{}
		if err := w.client.List(ctx, duList, &ctlclient.ListOptions{LabelSelector: labels.SelectorFromSet(labels.Set(map[string]string{ExposeOnGoingLabel: "true"}))}); err != nil {
			log.WithError(err).Warn("Failed to list data uploads, skip counting")
		} else {
			w.duCacheState.queueLength = len(duList.Items)
			w.duCacheState.changeID = id

			log.Infof("Query queue length for du %d", w.duCacheState.queueLength)
		}
	}

	id = atomic.LoadUint64(&w.ddState.changeID)
	if id != w.ddCacheState.changeID {
		ddList := &velerov2alpha1api.DataDownloadList{}
		if err := w.client.List(ctx, ddList, &ctlclient.ListOptions{LabelSelector: labels.SelectorFromSet(labels.Set(map[string]string{ExposeOnGoingLabel: "true"}))}); err != nil {
			log.WithError(err).Warn("Failed to list data downloads, skip counting")
		} else {
			w.ddCacheState.queueLength = len(ddList.Items)
			w.ddCacheState.changeID = id

			log.Infof("Query queue length for dd %d", w.ddCacheState.queueLength)
		}
	}

	id = atomic.LoadUint64(&w.pvbState.changeID)
	if id != w.pvbCacheState.changeID {
		pvbList := &velerov1api.PodVolumeBackupList{}
		if err := w.client.List(ctx, pvbList, &ctlclient.ListOptions{LabelSelector: labels.SelectorFromSet(labels.Set(map[string]string{ExposeOnGoingLabel: "true"}))}); err != nil {
			log.WithError(err).Warn("Failed to list PVB, skip counting")
		} else {
			w.pvbCacheState.queueLength = len(pvbList.Items)
			w.pvbCacheState.changeID = id

			log.Infof("Query queue length for pvb %d", w.pvbCacheState.queueLength)
		}
	}

	id = atomic.LoadUint64(&w.pvrState.changeID)
	if id != w.pvrCacheState.changeID {
		pvrList := &velerov1api.PodVolumeRestoreList{}
		if err := w.client.List(ctx, pvrList, &ctlclient.ListOptions{LabelSelector: labels.SelectorFromSet(labels.Set(map[string]string{ExposeOnGoingLabel: "true"}))}); err != nil {
			log.WithError(err).Warn("Failed to list PVR, skip counting")
		} else {
			w.pvrCacheState.queueLength = len(pvrList.Items)
			w.pvrCacheState.changeID = id

			log.Infof("Query queue length for pvr %d", w.pvrCacheState.queueLength)
		}
	}

	existing := w.duCacheState.queueLength + w.ddCacheState.queueLength + w.pvbCacheState.queueLength + w.pvrCacheState.queueLength
	constrained := existing >= w.allowedQueueLength

	return constrained
}
