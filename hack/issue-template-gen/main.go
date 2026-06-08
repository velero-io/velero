/*
Copyright 2018 the Velero contributors.

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

// This code renders the IssueTemplate string in pkg/cmd/cli/bug/bug.go to
// .github/ISSUE_TEMPLATE/bug_report.md via the hack/update-generated-issue-template.sh script.

package main

import (
	"log"
	"os"
	"text/template"

	"github.com/vmware-tanzu/velero/pkg/cmd/cli/bug"
)

func main() {
	outTemplateFilename := os.Args[1]
	// #nosec G304,G703 -- outTemplateFilename is generated from internal logic and not user-controllable
	outFile, err := os.OpenFile(outTemplateFilename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()
	tmpl, err := template.New("ghissue").Parse(bug.IssueTemplate)
	if err != nil {
		log.Fatal(err)
	}
	err = tmpl.Execute(outFile, bug.VeleroBugInfo{})
	if err != nil {
		log.Fatal(err)
	}
}
