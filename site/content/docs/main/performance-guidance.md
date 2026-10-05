---
title: "Velero File System Backup Performance Guide"
layout: docs
---

When using Velero to do file system backup & restore, Kopia uploader performance can vary based on data shape and resource settings.

We've done several rounds of tests against Kopia uploader through Velero, which may give you some guidance. But the test results will vary from different infrastructures, and our tests are limited and couldn't cover a variety of data scenarios, **the test results and analysis are for reference only**.

## Infrastructure

Minio is used as Velero backend storage,  Network File System (NFS) is used to create the persistent volumes (PVs) and Persistent Volume Claims (PVC) based on the storage. The minio and NFS server are deployed independently in different virtual machines (VM), which with 300 MB/s write throughput and 175 MB/s read throughput representatively.

The details of environmental information as below:

```
### KUBERNETES VERSION
root@velero-host-01:~# kubectl version
Client Version: version.Info{Major:"1", Minor:"22", GitVersion:"v1.22.4"
Server Version: version.Info{Major:"1", Minor:"21", GitVersion:"v1.21.14"

### DOCKER VERSION
root@velero-host-01:~# docker version
Client:
 Version:           20.10.12
 API version:       1.41

Server:
 Engine:
  Version:          20.10.12
  API version:      1.41 (minimum version 1.12)
  Go version:       go1.16.2
 containerd:
  Version:          1.5.9-0ubuntu1~20.04.4
 runc:
  Version:          1.1.0-0ubuntu1~20.04.1
 docker-init:
  Version:          0.19.0

### NODES
root@velero-host-01:~# kubectl get nodes |wc -l 
6 // one master with 6 work nodes

### DISK INFO
root@velero-host-01:~# smartctl -a /dev/sda
smartctl 7.1 2019-12-30 r5022 [x86_64-linux-5.4.0-126-generic] (local build)
Copyright (C) 2002-19, Bruce Allen, Christian Franke, www.smartmontools.org

=== START OF INFORMATION SECTION ===
Vendor:               VMware
Product:              Virtual disk
Revision:             1.0
Logical block size:   512 bytes
Rotation Rate:        Solid State Device
Device type:          disk
### MEMORY INFO
root@velero-host-01:~# free -h
              total        used        free      shared  buff/cache   available
Mem:          3.8Gi       328Mi       3.1Gi       1.0Mi       469Mi       3.3Gi
Swap:            0B          0B          0B

### CPU INFO
root@velero-host-01:~# cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq -c
      4  Intel(R) Xeon(R) Gold 6230R CPU @ 2.10GHz

### SYSTEM INFO
root@velero-host-01:~# cat /proc/version
root@velero-host-01:~# cat /proc/version
Linux version 5.4.0-126-generic (build@lcy02-amd64-072) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #142-Ubuntu SMP Fri Aug 26 12:12:57 UTC 2022

### VELERO VERSION
root@velero-host-01:~# velero version
Client:
	Version: main ###v1.10 pre-release version
	Git commit: 9b22ca6100646523876b18a491d881561b4dbcf3-dirty
Server:
	Version: main ###v1.10 pre-release version
```

## Test

Below we've done 6 groups of tests. For each single group of test, we used limited resources (1 core CPU 2 GB memory or 4 cores CPU 4 GB memory) to do Velero file system backup under Kopia path.

Recorded the metrics of time consumption, maximum CPU usage, maximum memory usage, and minio storage usage for node-agent daemonset. The metrics of Velero deployment are not included.

Compression is disabled for testing purposes.

### Case 1: 4194304(4M) files, 2396745(2M) directories, 0B per file total 0B content
#### result:
|Uploader| Resources|Times |Max CPU|Max Memory|Repo Usage|
|--------|----------|:----:|------:|:--------:|:--------:|
| Kopia  | 1c2g     |24m54s| 65%   |1530 MB   |80 MB     |
| Kopia  | 4c4g     |24m52s| 63%   |2216 MB   |80 MB     |
#### conclusion:
- The memory usage is larger than Velero's default memory limit (1GB) for Kopia under massive empty files.
- There is no significant time reduction by increasing resources from 1c2g to 4c4g.

### Case 2: Using the same size (100B) of file and default Velero's resource configuration, the testing quantity of files from 20 thousand to 2 million, these groups of cases mainly test the behavior with the increasing quantity of files.

### Case 2.1: 235298(23K) files, 137257 (10k)directories, 100B per file total 22.440MB content
#### result:
| Uploader  | Resources|Times |Max CPU|Max Memory|Repo Usage|
|-------|----------|:----:|------:|:--------:|:--------:|
| Kopia | 1c1g     |2m34s | 70%   |692 MB   |108 MB     |

### Case 2.2 470596(40k) files, 137257 (10k)directories, 100B per file total 44.880MB content
#### result:
| Uploader  | Resources|Times |Max CPU|Max Memory|Repo Usage|
|-------|----------|:----:|------:|:--------:|:--------:|
| Kopia | 1c1g     |3m45s | 68%   |831 MB   |108 MB     |

### Case 2.3 705894(70k) files, 137257(10k) directories, 100B per file total 67.319MB content
#### result:
|Uploader| Resources|Times |Max CPU|Max Memory|Repo Usage|
|--------|----------|:----:|------:|:--------:|:--------:|
| Kopia  | 1c1g     |5m06s | 71%   |861 MB    |108 MB    |

### Case 2.4 2097152(2M) files, 2396745(2M) directories, 100B per file total 200.000MB content
#### result:
|Uploader| Resources|Times |Max CPU|Max Memory|Repo Usage|
|--------|----------|:----:|------:|:--------:|:--------:|
| Kopia  | 1c1g     |OOM   | 74%   |N/A       |N/A       |
#### conclusion:
- With the increasing number of files, there is no memory abnormal surge, and memory usage is linearly increasing until it exceeds 1GB where Case 2.4 Kopia uploader OOM happened.
- Kopia uploader gets increasingly faster along with the increasing number of files.

### Case 3: 10625(10k) files, 781 directories, 1.000MB per file total 10.376GB content
#### result:
|Uploader| Resources|Times |Max CPU|Max Memory|Repo Usage|
|--------|----------|:----:|------:|:--------:|:--------:|
| Kopia  | 1c2g     |1m37s | 75%   |251 MB    |10 GB     |
| Kopia  | 4c4g     |1m35s | 75%   |248 MB    |10 GB     |
#### conclusion:
- This case involves a relatively large backup size, and there is no significant time reduction by increasing resources from 1c2g to 4c4g for Kopia uploader.

### Case 4: 900 files, 1 directory, 1.000GB per file total 900.000GB content
#### result:
|Uploader| Resources|Times  |Max CPU|Max Memory|Repo Usage|
|--------|----------|:-----:|------:|:--------:|:--------:|
| Kopia  | 1c2g     |2h30m  | 100%  |714 MB   |900 GB     |
| Kopia  | 4c4g     |1h42m  | 138%  |786 MB   |900 GB     |
#### conclusion:
- For backup large amounts of data, allocating more resources can reduce backup time for Kopia uploader.

## Summary
- With the same specification resources, Kopia uploader is less time-consuming when backup.
- Kopia uploader performs well when backing up large amounts of data or massive small files.
- It's better to set one reasonable resource configuration instead of the default depending on your scenario. With default configuration, it's easy to hit timeout or OOM in large-scale backups.
