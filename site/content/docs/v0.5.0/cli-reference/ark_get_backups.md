---
title: "ark get backups"
layout: docs
---

Get backups

### Synopsis


Get backups

```
ark get backups [flags]
```

### Options

```
  -h, --help                        help for backups
      --label-columns stringArray   a comma-separated list of labels to be displayed as columns
  -o, --output string               Output display format. For create commands, display the object but do not send it to the server. Valid formats are 'table', 'json', and 'yaml'. (default "table")
  -l, --selector string             only show items matching this label selector
      --show-labels                 show labels in the last column
```

### Options inherited from parent commands

```
      --alsologtostderr                  log to standard error as well as files
      --kubeconfig string                Path to the kubeconfig file to use to talk to the Kubernetes apiserver. If unset, try the environment variable KUBECONFIG, as well as in-cluster configuration
      --log_backtrace_at traceLocation   when logging hits line file:N, emit a stack trace (default :0)
      --log_dir string                   If non-empty, write log files in this directory
      --logtostderr                      log to standard error instead of files
      --stderrthreshold severity         logs at or above this threshold go to stderr (default 2)
  -v, --v Level                          log level for V logs
      --vmodule moduleSpec               comma-separated list of pattern=N settings for file-filtered logging
```

**Note:** For backups in the "New" state (not yet executed), the EXPIRES column will display "N/A" instead of a date, indicating that the backup is not yet eligible for expiration or garbage collection.

### SEE ALSO
* [ark get](ark_get.md)	 - Get ark resources

