#!/bin/bash -e
#
# Copyright 2017, 2019 the Velero contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

HACK_DIR=$(dirname "${BASH_SOURCE}")

echo "Updating plugin proto"

echo protoc --version
protoc \
  -I pkg/plugin/proto/ \
  -I /usr/include \
  --go_out=pkg/plugin/generated/ \
  --go_opt=module=github.com/velero-io/velero/pkg/plugin/generated \
  --go-grpc_out=pkg/plugin/generated \
  --go-grpc_opt=paths=source_relative \
  --go-grpc_opt=require_unimplemented_servers=false \
  $(find pkg/plugin/proto -name '*.proto')

echo "Updating plugin proto - done!"
