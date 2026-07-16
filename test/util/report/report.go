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

package report

import (
	"os"

	"github.com/cockroachdb/errors"
	"go.yaml.in/yaml/v3"

	"github.com/vmware-tanzu/velero/test"
)

func GenerateYamlReport() error {
	yamlData, err := yaml.Marshal(test.ReportData)
	if err != nil {
		return errors.Wrap(err, "error marshal data into yaml")
	}

	// Open the file in append mode. If the file does not exist, it will be created.
	filePath := "perf-report.yaml"
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errors.Wrap(err, "error opening file")
	}
	defer file.Close()

	// Write the YAML data to the file
	_, err = file.Write(yamlData)
	if err != nil {
		return errors.Wrap(err, "Error writing YAML to file:")
	}
	return nil
}

func AddTestSuitData(dataMap map[string]any, testSuitDesc string) {
	test.ReportData.OtherFields[testSuitDesc] = dataMap
}
