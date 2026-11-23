---
name: Bug report
about: Tell us about a problem you are experiencing

---

**What steps did you take and what happened:**
<!--A clear and concise description of what the bug is, and what commands you ran.-->


**What did you expect to happen:**

**The following information will help us better understand what's going on**:

_If you are using velero v1.7.0+:_  
Please use `velero debug  --backup <backupname> --restore <restorename>` to generate the support bundle, and attach to this issue, more options please refer to `velero debug --help` 

_If you are using earlier versions:_  
Please provide the output of the following commands (Pasting long output into a [GitHub gist](https://gist.github.com) or other pastebin is fine.)
- `kubectl logs deployment/velero -n velero`
- `velero backup describe <backupname>` or `kubectl get backup/<backupname> -n velero -o yaml`
- `velero backup logs <backupname>`
- `velero restore describe <restorename>` or `kubectl get restore/<restorename> -n velero -o yaml`
- `velero restore logs <restorename>`


**Anything else you would like to add:**
<!--Miscellaneous information that will assist in solving the issue.-->


**Environment:**

- Velero version (use `velero version`): 
- Velero features (use `velero client config get features`): 
- Kubernetes version (use `kubectl version`):
- Kubernetes installer & version:
- Cloud provider or hardware configuration:
- OS (e.g. from `/etc/os-release`):


**Vote on this issue!**

This is an invitation to the Velero community to vote on issues, you can see the project's [top voted issues listed here](https://github.com/velero-io/velero/issues?q=is%3Aissue+is%3Aopen+sort%3Areactions-%2B1-desc).  
Use the "reaction smiley face" up to the right of this comment to vote.

- :+1: for "I would like to see this bug fixed as soon as possible"
- :-1: for "There are more important bugs to focus on right now"
