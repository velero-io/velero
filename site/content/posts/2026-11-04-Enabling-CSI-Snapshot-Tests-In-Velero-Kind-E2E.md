---
title: "We've enabled CSI Snapshot Tests in Velero Kind E2E"
excerpt: Velero's kind end-to-end job now runs seven rows of CSI coverage, where it ran none. Snapshot regressions are caught before a change merges. Here is what was stopping those tests, and three adjacent things the work turned up.
author_name: Krishna Tupe
slug: Enabling-CSI-Snapshot-Tests-In-Velero-Kind-E2E
categories: ['velero','testing']
image: /img/posts/csi-announce-blog.jpg
# Tag should match author to drive author pages
tags: ['Velero Team', 'Krishna Tupe']
---

Velero's end-to-end suite now runs its CSI volume snapshot cases on a [kind](https://kind.sigs.k8s.io/) cluster in CI. Seven matrix rows cover CSI snapshots, the data mover, VolumeGroupSnapshot, Kibishii snapshot and file system backup, namespace mapping, backup storage location deletion, and backup deletion with file system backup. Until recently that job ran none of them.

This is Velero's only automated end-to-end coverage, and it runs on every pull request that touches Go code. So a change that breaks the CSI backup path, the data mover or VolumeGroupSnapshot is now caught before it merges, against a real CSI driver taking real `VolumeSnapshot` objects, on hardware the project already pays nothing for.

Getting there was my [LFX Mentorship](https://mentorship.lfx.linuxfoundation.org/) project with the Velero community, tracked in [issue #7507](https://github.com/velero-io/velero/issues/7507). What follows is what had been switching those tests off, and three adjacent things the work turned up that are worth knowing if you maintain a test suite of your own.

## Why they did not run before

Eight provider checks across six test files skipped the snapshot cases on kind, each carrying a comment that said the same thing: volume snapshots and file system backups are not supported on kind. The oldest of those checks dates to 2021. Not one of them is obviously wrong, which is why all eight survived.

kind can take CSI snapshots. `csi-driver-host-path` installs into a kind cluster and takes real `VolumeSnapshot` objects. The real cause was in a different repository altogether.

Velero's suite uses [Kibishii](https://github.com/vmware-tanzu-experiments/distributed-data-generator) as its sample workload. The suite installs the StorageClass named by its `--storage-class-file` flag, but Kibishii's kustomize overlay ships a class of its own and points its PersistentVolumeClaims at that one instead. On kind, the overlay declared it like this:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: kibishii-storage-class
provisioner: rancher.io/local-path
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
```

So every PersistentVolume Kibishii created was a hostPath volume, whatever the suite had installed. Velero declines to act on those twice over. The CSI backup action returns early unless the volume has a `CSI` source (`pkg/backup/actions/csi/pvc_action.go`). The file system backup path reads the PersistentVolume, finds a `HostPath` source, and skips it too (`pkg/podvolume/backupper.go`).

Skipping produced the right outcome for the wrong reason. There was genuinely nothing to snapshot, so the tests would have failed had they run. But the comments named kind, and the fix was one line in a fixture in another repository. It was a believable wrong answer, too: kind does ship a local-path provisioner that cannot snapshot, so the explanation fit everything anyone could see from inside Velero.

## Three things that hid in plain sight

Fixing the StorageClass was the small part. Finding out what else had quietly never run was the rest.

**A label filter matches a bare token by equality.** Velero selects test cases with Ginkgo label filters. Ginkgo compares a bare token like this:

```go
if strings.ToLower(labels[i]) == expected {
```

So the filter `CSISnapshot` does not select a case labelled `CSIVolumeGroupSnapshot`. Substring intuition is wrong here, and I found that out on my own work: I had added a VolumeGroupSnapshot case a few days earlier, and the filter I was about to write for it would not have selected it. No CSI job existed yet, so nothing was lost, but nothing would have told me either.

**A filter that selects nothing reports success.** Ginkgo runs zero specs, prints `SUCCESS!` and exits 0. A label expression with a typo in it passes. The example command in the header of one of my own pull requests did exactly that, and it looked green. The suite now runs with `--fail-on-empty`, so an expression that matches nothing fails instead.

**Tests can exist without ever being wired in.** Velero's unit test script listed `pkg/` and `internal/`. It listed nothing under `test/`. Six test files already in the tree had never run, the oldest of them sitting there since July 2023.

## What it took

Order mattered more than size. The StorageClass lived in another repository, so a CSI-backed overlay had to merge there first. Only then could Velero map the combination of kind and CSI onto that overlay and move its pinned Kibishii commit forward. Only then could the provider checks narrow from "kind" to "kind without CSI", which is what they had always meant. Only then could the CI matrix select the cases.

Done in that order, each change was small and reviewable on its own.

Eight provider checks are now one. The case behind it needs a second cluster to migrate between, so it is still correctly skipped. The CSI matrix went from no rows to seven, and it is still growing: the most recent row landed while this post was in review.

## Run it yourself

All of it runs locally with one command:

```sh
make -C test/ run-e2e-kind
```

The target creates a kind cluster and a MinIO container, builds and loads the Velero image, runs the suite, and removes what it created, including on a failure or an interrupt. The cluster's kubeconfig goes to a temporary directory, so your current context is untouched. That target did not exist when this project started.

Add `FEATURES=EnableCSI` and it installs the snapshot stack and points Kibishii at the CSI-backed StorageClass, which is the path this post has been about. `GINKGO_LABELS` picks which cases run.

If you are changing anything in Velero's backup or restore paths, that is now a way to see the CSI cases pass on your laptop before you open a pull request, and to see them pass again in CI after you do.

And if you maintain a Ginkgo suite of your own, the three above are worth checking in it: what your label filters actually select, whether a filter matching nothing fails, and whether every test file you have written sits in a package your CI runs.
