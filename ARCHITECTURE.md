# Velero Architecture

This is a high-level entry point to Velero's architecture. It links to the
authoritative material rather than duplicating it, so the details stay in one
place and do not drift.

## How Velero works

Velero runs a server (a set of controllers) as a single replica deployment in your cluster and a command-line
client that runs locally. Backups and restores are driven by Kubernetes custom
resources and reconciled by the server. Volume data is moved by the built-in
file-system backup and by the data mover, and object and volume snapshot
operations are handled through provider plugins.

For the full component overview, the backup and restore flows, and the object
storage and snapshot model, see:

- [How Velero works](https://velero.io/docs/main/how-velero-works/)
- [Velero documentation](https://velero.io/docs/)

## Goals

Velero gives you tools to back up and restore your Kubernetes cluster resources
and persistent volumes, on public cloud or on-premises. The primary use cases
are:

- Take backups of your cluster and restore in case of loss.
- Migrate cluster resources to other clusters.
- Replicate your production cluster to development and testing clusters.

## Design proposals

Accepted and proposed designs live in the [`design/`](design/) directory. New
designs follow [`design/_template.md`](design/_template.md) and are reviewed
through pull requests and the community meetings. Implemented designs are
archived under [`design/Implemented/`](design/Implemented/).

## Related documents

- [Roadmap](ROADMAP.md)
- [Governance](https://github.com/velero-io/.github/blob/main/GOVERNANCE.md)
- [Contributing](https://github.com/velero-io/.github/blob/main/CONTRIBUTING.md)
