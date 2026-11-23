/*
Copyright 2017 the Velero contributors.

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

package test

import (
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic/dynamicinformer"

	"github.com/velero-io/velero/pkg/client"
)

type FakeDynamicFactory struct {
	mock.Mock
}

var _ client.DynamicFactory = &FakeDynamicFactory{}

func (df *FakeDynamicFactory) ClientForGroupVersionResource(gv schema.GroupVersion, resource metav1.APIResource, namespace string) (client.Dynamic, error) {
	args := df.Called(gv, resource, namespace)
	return args.Get(0).(client.Dynamic), args.Error(1)
}

func (df *FakeDynamicFactory) DynamicSharedInformerFactory() dynamicinformer.DynamicSharedInformerFactory {
	args := df.Called()
	return args.Get(0).(dynamicinformer.DynamicSharedInformerFactory)
}

type FakeDynamicClient struct {
	mock.Mock
}

var _ client.Dynamic = &FakeDynamicClient{}

func (c *FakeDynamicClient) List(options metav1.ListOptions) (*unstructured.UnstructuredList, error) {
	args := c.Called(options)
	return args.Get(0).(*unstructured.UnstructuredList), args.Error(1)
}

func (c *FakeDynamicClient) Create(obj *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	args := c.Called(obj)
	return args.Get(0).(*unstructured.Unstructured), args.Error(1)
}

func (c *FakeDynamicClient) Watch(options metav1.ListOptions) (watch.Interface, error) {
	args := c.Called(options)
	return args.Get(0).(watch.Interface), args.Error(1)
}

func (c *FakeDynamicClient) Get(name string, opts metav1.GetOptions) (*unstructured.Unstructured, error) {
	args := c.Called(name, opts)
	return args.Get(0).(*unstructured.Unstructured), args.Error(1)
}

func (c *FakeDynamicClient) Patch(name string, data []byte) (*unstructured.Unstructured, error) {
	args := c.Called(name, data)
	return args.Get(0).(*unstructured.Unstructured), args.Error(1)
}

func (c *FakeDynamicClient) Delete(name string, opts metav1.DeleteOptions) error {
	args := c.Called(name, opts)
	return args.Error(1)
}

func (c *FakeDynamicClient) UpdateStatus(obj *unstructured.Unstructured, opts metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	args := c.Called(obj, opts)
	return args.Get(0).(*unstructured.Unstructured), args.Error(1)
}

func (c *FakeDynamicClient) Apply(name string, obj *unstructured.Unstructured, opts metav1.ApplyOptions) (*unstructured.Unstructured, error) {
	args := c.Called(name, obj, opts)
	return args.Get(0).(*unstructured.Unstructured), args.Error(1)
}
