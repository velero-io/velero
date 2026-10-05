---
title: "Code Standards"
layout: docs
---

## Adding a changelog

Authors are expected to include a changelog file with their pull requests. The changelog file
should be a new file created in the `changelogs/unreleased` folder. The file should follow the
naming convention of `pr-username` and the contents of the file should be your text for the
changelog.

    velero/changelogs/unreleased   <- folder
        000-username            <- file

Add that to the PR.

## Code

- Log messages are capitalized.

- Error messages are kept lower-cased.

- Wrap/add a stack only to errors that are being directly returned from non-velero code, such as an API call to the Kubernetes server.

    ```bash
    errors.WithStack(err)
    ```

- Prefer to use the utilities in the Kubernetes package [`sets`](https://godoc.org/github.com/kubernetes/apimachinery/pkg/util/sets).

    ```bash
    k8s.io/apimachinery/pkg/util/sets
    ```

## Imports

For imports, we use the following convention:

<group><version><api | client | informer | ...>

Example:

    import (
        corev1api "k8s.io/api/core/v1"
    	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
    	corev1listers "k8s.io/client-go/listers/core/v1"
        velerov1api "github.com/velero-io/velero/pkg/apis/velero/v1"
        velerov1client "github.com/velero-io/velero/pkg/generated/clientset/versioned/typed/velero/v1"
    )

## Mocks

We use a package to generate mocks for our interfaces.

Example: if you want to change this mock: https://github.com/velero-io/velero/blob/v1.3.1/pkg/restic/mocks/restorer.go

Run:

```bash
go get github.com/vektra/mockery/.../
cd pkg/restic
mockery -name=Restorer
```

Might need to run `make update` to update the imports.

## DCO Sign off

All authors to the project retain copyright to their work. However, to ensure
that they are only submitting work that they have rights to, we are requiring
everyone to acknowledge this by signing their work.

Any copyright notices in this repo should specify the authors as "the Velero contributors".

To sign your work, just add a line like this at the end of your commit message:

```
Signed-off-by: Joe Beda <joe@heptio.com>
```

This can easily be done with the `--signoff` option to `git commit`.

By doing this you state that you can certify the following (from [https://developercertificate.org/](https://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
1 Letterman Drive
Suite D4700
San Francisco, CA, 94129

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```
