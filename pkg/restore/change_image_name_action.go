/*
Copyright 2022 the Velero contributors.

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

package restore

import (
	"context"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/vmware-tanzu/velero/pkg/plugin/framework/common"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

const (
	delimiterValue = ","
)

// ChangeImageNameAction updates a deployment or Pod's image name
// if a mapping is found in the plugin's config map.
type ChangeImageNameAction struct {
	logger          logrus.FieldLogger
	configMapClient corev1client.ConfigMapInterface
}

// NewChangeImageNameAction is the constructor for ChangeImageNameAction.
func NewChangeImageNameAction(
	logger logrus.FieldLogger,
	configMapClient corev1client.ConfigMapInterface,
) *ChangeImageNameAction {
	return &ChangeImageNameAction{
		logger:          logger,
		configMapClient: configMapClient,
	}
}

// AppliesTo returns the resources that ChangeImageNameAction should
// be run for.
func (a *ChangeImageNameAction) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{
		IncludedResources: []string{"deployments", "statefulsets", "daemonsets", "replicasets", "replicationcontrollers", "jobs", "cronjobs", "pods"},
	}, nil
}

// Execute updates the item's spec.containers' image if a mapping is found
// in the config map for the plugin.
func (a *ChangeImageNameAction) Execute(input *velero.RestoreItemActionExecuteInput) (*velero.RestoreItemActionExecuteOutput, error) {
	a.logger.Info("Executing ChangeImageNameAction")
	defer a.logger.Info("Done executing ChangeImageNameAction")

	opts := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("velero.io/plugin-config,%s=%s", "velero.io/change-image-name", common.PluginKindRestoreItemAction),
	}

	list, err := a.configMapClient.List(context.TODO(), opts)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if len(list.Items) == 0 {
		return &velero.RestoreItemActionExecuteOutput{
			UpdatedItem: input.Item,
		}, nil
	}

	if len(list.Items) > 1 {
		var items []string
		for _, item := range list.Items {
			items = append(items, item.Name)
		}
		return nil, errors.Errorf("found more than one ConfigMap matching label selector %q: %v", opts.LabelSelector, items)
	}

	config := &list.Items[0]
	if len(config.Data) == 0 {
		a.logger.Info("No image name mappings found")
		return velero.NewRestoreItemActionExecuteOutput(input.Item), nil
	}

	obj, ok := input.Item.(*unstructured.Unstructured)
	if !ok {
		return nil, errors.Errorf("object was of unexpected type %T", input.Item)
	}
	if obj.GetKind() == "Pod" {
		err = a.replaceImageName(obj, config, "spec", "containers")
		if err != nil {
			a.logger.Infof("replace image name meet error: %v", err)
			return nil, errors.Wrap(err, "error getting item's spec.containers")
		}

		err = a.replaceImageName(obj, config, "spec", "initContainers")
		if err != nil {
			a.logger.Infof("replace image name meet error: %v", err)
			return nil, errors.Wrap(err, "error getting item's spec.containers")
		}
	} else if obj.GetKind() == "CronJob" {
		//handle containers
		err = a.replaceImageName(obj, config, "spec", "jobTemplate", "spec", "template", "spec", "containers")
		if err != nil {
			a.logger.Infof("replace image name meet error: %v", err)
			return nil, errors.Wrap(err, "error getting item's spec.containers")
		}
		//handle initContainers
		err = a.replaceImageName(obj, config, "spec", "jobTemplate", "spec", "template", "spec", "initContainers")
		if err != nil {
			a.logger.Infof("replace image name meet error: %v", err)
			return nil, errors.Wrap(err, "error getting item's spec.containers")
		}
	} else {
		//handle containers
		err = a.replaceImageName(obj, config, "spec", "template", "spec", "containers")
		if err != nil {
			a.logger.Infof("replace image name meet error: %v", err)
			return nil, errors.Wrap(err, "error getting item's spec.containers")
		}

		//handle initContainers
		err = a.replaceImageName(obj, config, "spec", "template", "spec", "initContainers")
		if err != nil {
			a.logger.Infof("replace image name meet error: %v", err)
			return nil, errors.Wrap(err, "error getting item's spec.containers")
		}
	}
	return velero.NewRestoreItemActionExecuteOutput(obj), nil
}

func (a *ChangeImageNameAction) replaceImageName(obj *unstructured.Unstructured, config *corev1.ConfigMap, filed ...string) error {
	log := a.logger.WithFields(map[string]interface{}{
		"kind":      obj.GetKind(),
		"namespace": obj.GetNamespace(),
		"name":      obj.GetName(),
	})
	needUpdateObj := false
	containers, _, err := unstructured.NestedSlice(obj.UnstructuredContent(), filed...)
	if err != nil {
		log.Infof("UnstructuredConverter meet error: %v", err)
		return errors.Wrap(err, "error getting item's spec.containers")
	}
	if len(containers) == 0 {
		return nil
	}
	for i, container := range containers {
		log.Infoln("container:", container)
		if image, ok := container.(map[string]interface{})["image"]; ok {
			imageName := image.(string)
			if exists, newImageName, err := a.isImageReplaceRuleExist(log, imageName, config); exists && err == nil {
				needUpdateObj = true
				log.Infof("Updating item's image from %s to %s", imageName, newImageName)
				container.(map[string]interface{})["image"] = newImageName
				containers[i] = container
			}
		}
	}
	if needUpdateObj {
		if err := unstructured.SetNestedField(obj.UnstructuredContent(), containers, filed...); err != nil {
			return errors.Wrap(err, "unable to set item's initContainer image")
		}
	}
	return nil
}

func (a *ChangeImageNameAction) isImageReplaceRuleExist(log *logrus.Entry, oldImageName string, cm *corev1.ConfigMap) (exists bool, newImageName string, err error) {
	if oldImageName == "" {
		log.Infoln("Item has no old image name specified")
		return false, "", nil
	}
	log.Debug("oldImageName: ", oldImageName)

	//how to use: "<old_image_name_sub_part><delimiter><new_image_name_sub_part>"
	//for current implementation the <delimiter> value can only be ","
	//e.x: in case your old image name is 1.1.1.1:5000/abc:test
	//"case1":"1.1.1.1:5000,2.2.2.2:3000"
	//"case2":"5000,3000"
	//"case3":"abc:test,edf:test"
	//"case4":"1.1.1.1:5000/abc:test,2.2.2.2:3000/edf:test"
	for _, row := range cm.Data {
		if !strings.Contains(row, delimiterValue) {
			continue
		}
		if strings.Contains(oldImageName, strings.TrimSpace(row[0:strings.Index(row, delimiterValue)])) && len(row[strings.Index(row, delimiterValue):]) > len(delimiterValue) {
			log.Infoln("match specific case:", row)
			oldImagePart := strings.TrimSpace(row[0:strings.Index(row, delimiterValue)])
			newImagePart := strings.TrimSpace(row[strings.Index(row, delimiterValue)+len(delimiterValue):])
			newImageName = strings.ReplaceAll(oldImageName, oldImagePart, newImagePart)
			return true, newImageName, nil
		}
	}
	return false, "", errors.Errorf("No mapping rule found for image: %s", oldImageName)
}
