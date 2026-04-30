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

package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/pager"

	"github.com/vmware-tanzu/velero/pkg/client"
	"github.com/vmware-tanzu/velero/pkg/discovery"
	"github.com/vmware-tanzu/velero/pkg/kuberesource"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
	"github.com/vmware-tanzu/velero/pkg/util/collections"
)

// itemCollector collects items from the Kubernetes API according to
// the backup spec and writes them to files inside dir.
type itemCollector struct {
	log                   logrus.FieldLogger
	backupRequest         *Request
	discoveryHelper       discovery.Helper
	dynamicFactory        client.DynamicFactory
	cohabitatingResources map[string]*cohabitatingResource
	dir                   string
	pageSize              int
}

type kubernetesResource struct {
	groupResource         schema.GroupResource
	preferredGVR          schema.GroupVersionResource
	namespace, name, path string
}

// getItemsFromResourceIdentifiers converts ResourceIdentifiers to
// kubernetesResources
func (r *itemCollector) getItemsFromResourceIdentifiers(resourceIDs []velero.ResourceIdentifier) []*kubernetesResource {
	grResourceIDsMap := make(map[schema.GroupResource][]velero.ResourceIdentifier)
	for _, resourceID := range resourceIDs {
		grResourceIDsMap[resourceID.GroupResource] = append(grResourceIDsMap[resourceID.GroupResource], resourceID)
	}
	return r.getItems(grResourceIDsMap)
}

// getAllItems gets all relevant items from all API groups.
func (r *itemCollector) getAllItems() []*kubernetesResource {
	return r.getItems(nil)
}

// getItems gets all relevant items from all API groups.
// If resourceIDsMap is nil, then all items from the cluster are
// pulled for each API group, subject to include/exclude rules.
// If resourceIDsMap is supplied, then only those resources are
// returned, with the appropriate APIGroup information filled in. In
// this case, include/exclude rules are not invoked, since we already
// have the list of items, we just need the item collector/discovery
// helper to fill in the missing GVR, etc. context.
func (r *itemCollector) getItems(resourceIDsMap map[schema.GroupResource][]velero.ResourceIdentifier) []*kubernetesResource {
	var resources []*kubernetesResource
	for _, group := range r.discoveryHelper.Resources() {
		groupItems, err := r.getGroupItems(r.log, group, resourceIDsMap)
		if err != nil {
			r.log.WithError(err).WithField("apiGroup", group.String()).Error("Error collecting resources from API group")
			continue
		}

		resources = append(resources, groupItems...)
	}

	return resources
}

// getGroupItems collects all relevant items from a single API group.
// If resourceIDsMap is supplied, then only those items are returned,
// with GVR/APIResource metadata supplied.
func (r *itemCollector) getGroupItems(log logrus.FieldLogger, group *metav1.APIResourceList, resourceIDsMap map[schema.GroupResource][]velero.ResourceIdentifier) ([]*kubernetesResource, error) {
	log = log.WithField("group", group.GroupVersion)

	log.Infof("Getting items for group")

	// Parse so we can check if this is the core group
	gv, err := schema.ParseGroupVersion(group.GroupVersion)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing GroupVersion %q", group.GroupVersion)
	}
	if gv.Group == "" {
		// This is the core group, so make sure we process in the following order: pods, pvcs, pvs,
		// everything else.
		sortCoreGroup(group)
	}

	var items []*kubernetesResource
	for _, resource := range group.APIResources {
		resourceItems, err := r.getResourceItems(log, gv, resource, resourceIDsMap)
		if err != nil {
			log.WithError(err).WithField("resource", resource.String()).Error("Error getting items for resource")
			continue
		}

		items = append(items, resourceItems...)
	}

	return items, nil
}

// sortResourcesByOrder sorts items by the names specified in "order".  Items are not in order will be put at the end in original order.
func sortResourcesByOrder(log logrus.FieldLogger, items []*kubernetesResource, order []string) []*kubernetesResource {
	if len(order) == 0 {
		return items
	}
	log.Debugf("Sorting resources using the following order %v...", order)
	itemMap := make(map[string]*kubernetesResource)
	for _, item := range items {
		var fullname string
		if item.namespace != "" {
			fullname = fmt.Sprintf("%s/%s", item.namespace, item.name)
		} else {
			fullname = item.name
		}
		itemMap[fullname] = item
	}
	var sortedItems []*kubernetesResource
	// First select items from the order
	for _, name := range order {
		if item, ok := itemMap[name]; ok {
			sortedItems = append(sortedItems, item)
			log.Debugf("%s added to sorted resource list.", item.name)
			delete(itemMap, name)
		} else {
			log.Warnf("Cannot find resource '%s'.", name)
		}
	}
	// Now append the rest in sortedGroupItems, maintain the original order
	for _, item := range items {
		var fullname string
		if item.namespace != "" {
			fullname = fmt.Sprintf("%s/%s", item.namespace, item.name)
		} else {
			fullname = item.name
		}
		if _, ok := itemMap[fullname]; !ok {
			//This item has been inserted in the result
			continue
		}
		sortedItems = append(sortedItems, item)
		log.Debugf("%s added to sorted resource list.", item.name)
	}
	return sortedItems
}

// getOrderedResourcesForType gets order of resourceType from orderResources.
func getOrderedResourcesForType(orderedResources map[string]string, resourceType string) []string {
	if orderedResources == nil {
		return nil
	}
	orderStr, ok := orderedResources[resourceType]
	if !ok || len(orderStr) == 0 {
		return nil
	}
	orders := strings.Split(orderStr, ",")
	return orders
}

// getResourceItems collects all relevant items for a given group-version-resource.
// If resourceIDsMap is supplied, the items will be pulled from here
// rather than from the cluster and applying include/exclude rules.
func (r *itemCollector) getResourceItems(log logrus.FieldLogger, gv schema.GroupVersion, resource metav1.APIResource, resourceIDsMap map[schema.GroupResource][]velero.ResourceIdentifier) ([]*kubernetesResource, error) {
	log = log.WithField("resource", resource.Name)

	log.Info("Getting items for resource")

	var (
		gvr = gv.WithResource(resource.Name)
		gr  = gvr.GroupResource()
	)

	orders := getOrderedResourcesForType(r.backupRequest.Spec.OrderedResources, resource.Name)
	// Getting the preferred group version of this resource
	preferredGVR, _, err := r.discoveryHelper.ResourceFor(gr.WithVersion(""))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// If we have a resourceIDs map, then only return items listed in it
	if resourceIDsMap != nil {
		resourceIDs, ok := resourceIDsMap[gr]
		if !ok {
			log.Info("Skipping resource because no items found in supplied ResourceIdentifier list")
			return nil, nil
		}
		var items []*kubernetesResource
		for _, resourceID := range resourceIDs {
			log.WithFields(
				logrus.Fields{
					"namespace": resourceID.Namespace,
					"name":      resourceID.Name,
				},
			).Infof("Getting item")
			resourceClient, err := r.dynamicFactory.ClientForGroupVersionResource(gv, resource, resourceID.Namespace)
			if err != nil {
				log.WithError(errors.WithStack(err)).Error("Error getting client for resource")
				continue
			}
			unstructured, err := resourceClient.Get(resourceID.Name, metav1.GetOptions{})
			if err != nil {
				log.WithError(errors.WithStack(err)).Error("Error getting item")
				continue
			}

			path, err := r.writeToFile(unstructured)
			if err != nil {
				log.WithError(err).Error("Error writing item to file")
				continue
			}

			items = append(items, &kubernetesResource{
				groupResource: gr,
				preferredGVR:  preferredGVR,
				namespace:     resourceID.Namespace,
				name:          resourceID.Name,
				path:          path,
			})
		}

		return items, nil
	}

	if !r.backupRequest.ResourceIncludesExcludes.ShouldInclude(gr.String()) {
		log.Infof("Skipping resource because it's excluded")
		return nil, nil
	}

	if cohabitator, found := r.cohabitatingResources[resource.Name]; found {
		if gv.Group == cohabitator.groupResource1.Group || gv.Group == cohabitator.groupResource2.Group {
			if cohabitator.seen {
				log.WithFields(
					logrus.Fields{
						"cohabitatingResource1": cohabitator.groupResource1.String(),
						"cohabitatingResource2": cohabitator.groupResource2.String(),
					},
				).Infof("Skipping resource because it cohabitates and we've already processed it")
				return nil, nil
			}
			cohabitator.seen = true
		}
	}

	// Handle namespace resource here.
	// Namespace are only filtered by namespace include/exclude filters.
	// Label selectors are not checked.
	if gr == kuberesource.Namespaces {
		resourceClient, err := r.dynamicFactory.ClientForGroupVersionResource(gv, resource, "")
		if err != nil {
			log.WithError(err).Error("Error getting dynamic client")
			return nil, errors.WithStack(err)
		}
		unstructuredList, err := resourceClient.List(metav1.ListOptions{})
		if err != nil {
			log.WithError(errors.WithStack(err)).Error("error list namespaces")
			return nil, errors.WithStack(err)
		}

		items := r.backupNamespaces(unstructuredList, r.backupRequest.NamespaceIncludesExcludes, gr, preferredGVR, log)

		return items, nil
	}
	clusterScoped := !resource.Namespaced
	namespacesToList := getNamespacesToList(r.backupRequest.NamespaceIncludesExcludes)

	// If we get here, we're backing up something other than namespaces
	if clusterScoped {
		namespacesToList = []string{""}
	}

	var items []*kubernetesResource

	for _, namespace := range namespacesToList {
		// List items from Kubernetes API
		log = log.WithField("namespace", namespace)

		resourceClient, err := r.dynamicFactory.ClientForGroupVersionResource(gv, resource, namespace)
		if err != nil {
			log.WithError(err).Error("Error getting dynamic client")
			continue
		}

		var orLabelSelectors []string
		if r.backupRequest.Spec.OrLabelSelectors != nil {
			for _, s := range r.backupRequest.Spec.OrLabelSelectors {
				orLabelSelectors = append(orLabelSelectors, metav1.FormatLabelSelector(s))
			}
		} else {
			orLabelSelectors = []string{}
		}

		log.Info("Listing items")
		unstructuredItems := make([]unstructured.Unstructured, 0)

		// Listing items for orLabelSelectors
		errListingForNS := false
		for _, label := range orLabelSelectors {
			unstructuredItems, err = r.listItemsForLabel(unstructuredItems, gr, label, resourceClient)
			if err != nil {
				errListingForNS = true
			}
		}

		if errListingForNS {
			log.WithError(err).Error("Error listing items")
			continue
		}

		var labelSelector string
		if selector := r.backupRequest.Spec.LabelSelector; selector != nil {
			labelSelector = metav1.FormatLabelSelector(selector)
		}

		// Listing items for labelSelector (singular)
		if len(orLabelSelectors) == 0 {
			unstructuredItems, err = r.listItemsForLabel(unstructuredItems, gr, labelSelector, resourceClient)
			if err != nil {
				log.WithError(err).Error("Error listing items")
				continue
			}
		}

		log.Infof("Retrieved %d items", len(unstructuredItems))

		// Collect items in included Namespaces
		for i := range unstructuredItems {
			item := &unstructuredItems[i]

			path, err := r.writeToFile(item)
			if err != nil {
				log.WithError(err).Error("Error writing item to file")
				continue
			}

			items = append(items, &kubernetesResource{
				groupResource: gr,
				preferredGVR:  preferredGVR,
				namespace:     item.GetNamespace(),
				name:          item.GetName(),
				path:          path,
			})
		}
	}
	if len(orders) > 0 {
		items = sortResourcesByOrder(r.log, items, orders)
	}

	return items, nil
}

func (r *itemCollector) writeToFile(item *unstructured.Unstructured) (string, error) {
	f, err := os.CreateTemp(r.dir, "")
	if err != nil {
		return "", errors.Wrap(err, "error creating temp file")
	}
	defer f.Close()

	jsonBytes, err := json.Marshal(item)
	if err != nil {
		return "", errors.Wrap(err, "error converting item to JSON")
	}

	if _, err := f.Write(jsonBytes); err != nil {
		return "", errors.Wrap(err, "error writing JSON to file")
	}

	if err := f.Close(); err != nil {
		return "", errors.Wrap(err, "error closing file")
	}

	return f.Name(), nil
}

// sortCoreGroup sorts the core API group.
func sortCoreGroup(group *metav1.APIResourceList) {
	sort.SliceStable(group.APIResources, func(i, j int) bool {
		return coreGroupResourcePriority(group.APIResources[i].Name) < coreGroupResourcePriority(group.APIResources[j].Name)
	})
}

// These constants represent the relative priorities for resources in the core API group. We want to
// ensure that we process pods, then pvcs, then pvs, then anything else. This ensures that when a
// pod is backed up, we can perform a pre hook, then process pvcs and pvs (including taking a
// snapshot), then perform a post hook on the pod.
const (
	pod = iota
	pvc
	pv
	other
)

// coreGroupResourcePriority returns the relative priority of the resource, in the following order:
// pods, pvcs, pvs, everything else.
func coreGroupResourcePriority(resource string) int {
	switch strings.ToLower(resource) {
	case "pods":
		return pod
	case "persistentvolumeclaims":
		return pvc
	case "persistentvolumes":
		return pv
	}

	return other
}

// getNamespacesToList examines ie and resolves the includes and excludes to a full list of
// namespaces to list. If ie is nil or it includes *, the result is just "" (list across all
// namespaces). Otherwise, the result is a list of every included namespace minus all excluded ones.
func getNamespacesToList(ie *collections.IncludesExcludes) []string {
	if ie == nil {
		return []string{""}
	}

	if ie.ShouldInclude("*") {
		// "" means all namespaces
		return []string{""}
	}

	var list []string
	for _, i := range ie.GetIncludes() {
		if ie.ShouldInclude(i) {
			list = append(list, i)
		}
	}

	return list
}

type cohabitatingResource struct {
	resource       string
	groupResource1 schema.GroupResource
	groupResource2 schema.GroupResource
	seen           bool
}

func newCohabitatingResource(resource, group1, group2 string) *cohabitatingResource {
	return &cohabitatingResource{
		resource:       resource,
		groupResource1: schema.GroupResource{Group: group1, Resource: resource},
		groupResource2: schema.GroupResource{Group: group2, Resource: resource},
		seen:           false,
	}
}

// function to process pager client calls when the pageSize is specified
func (r *itemCollector) processPagerClientCalls(gr schema.GroupResource, label string, resourceClient client.Dynamic) (runtime.Object, error) {
	// If limit is positive, use a pager to split list over multiple requests
	// Use Velero's dynamic list function instead of the default
	listPager := pager.New(pager.SimplePageFunc(func(opts metav1.ListOptions) (runtime.Object, error) {
		return resourceClient.List(opts)
	}))
	// Use the page size defined in the server config
	// TODO allow configuration of page buffer size
	listPager.PageSize = int64(r.pageSize)
	// Add each item to temporary slice
	list, paginated, err := listPager.List(context.Background(), metav1.ListOptions{LabelSelector: label})

	if err != nil {
		r.log.WithError(errors.WithStack(err)).Error("Error listing resources")
		return list, err
	}

	if !paginated {
		r.log.Infof("list for groupResource %s was not paginated", gr)
	}

	return list, nil
}

func (r *itemCollector) listItemsForLabel(unstructuredItems []unstructured.Unstructured, gr schema.GroupResource, label string, resourceClient client.Dynamic) ([]unstructured.Unstructured, error) {
	if r.pageSize > 0 {
		// process pager client calls
		list, err := r.processPagerClientCalls(gr, label, resourceClient)
		if err != nil {
			return unstructuredItems, err
		}

		err = meta.EachListItem(list, func(object runtime.Object) error {
			u, ok := object.(*unstructured.Unstructured)
			if !ok {
				r.log.WithError(errors.WithStack(fmt.Errorf("expected *unstructured.Unstructured but got %T", u))).Error("unable to understand entry in the list")
				return fmt.Errorf("expected *unstructured.Unstructured but got %T", u)
			}
			unstructuredItems = append(unstructuredItems, *u)
			return nil
		})
		if err != nil {
			r.log.WithError(errors.WithStack(err)).Error("unable to understand paginated list")
			return unstructuredItems, err
		}
	} else {
		unstructuredList, err := resourceClient.List(metav1.ListOptions{LabelSelector: label})
		if err != nil {
			r.log.WithError(errors.WithStack(err)).Error("Error listing items")
			return unstructuredItems, err
		}
		unstructuredItems = append(unstructuredItems, unstructuredList.Items...)
	}
	return unstructuredItems, nil
}

// backupNamespaces process namespace resource according to namespace filters.
func (r *itemCollector) backupNamespaces(unstructuredList *unstructured.UnstructuredList,
	ie *collections.IncludesExcludes, gr schema.GroupResource, preferredGVR schema.GroupVersionResource,
	log logrus.FieldLogger) []*kubernetesResource {
	var items []*kubernetesResource
	for index, unstructured := range unstructuredList.Items {
		if ie.ShouldInclude(unstructured.GetName()) {
			log.Debugf("Backup namespace %s due to namespace filters setting.", unstructured.GetName())

			path, err := r.writeToFile(&unstructuredList.Items[index])
			if err != nil {
				log.WithError(err).Error("Error writing item to file")
				continue
			}

			items = append(items, &kubernetesResource{
				groupResource: gr,
				preferredGVR:  preferredGVR,
				name:          unstructured.GetName(),
				path:          path,
			})
		}
	}

	return items
}
