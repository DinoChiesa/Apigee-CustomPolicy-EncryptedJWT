#!/bin/bash

# Copyright 2023-2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PROXY_NAME=encrypted-jwt-java

import_and_deploy_apiproxy() {
    local proxy_name=$1
    REV=$(apigeecli apis create bundle -f "./bundle/apiproxy" -n "$proxy_name" --org "$PROJECT" --token "$TOKEN" --disable-check | jq ."revision" -r)
    apigeecli apis deploy --wait --name "$proxy_name" --ovr --rev "$REV" --org "$PROJECT" --env "$APIGEE_ENV" --token "$TOKEN" --disable-check
}

[[ -z "$PROJECT" ]] && echo "No PROJECT variable set" && exit 1
[[ -z "$APIGEE_ENV" ]] && echo "No APIGEE_ENV variable set" && exit 1
[[ -z "$APIGEE_HOST" ]] && echo "No APIGEE_HOST variable set" && exit 1

TOKEN=$(gcloud auth print-access-token)

echo "Importing and Deploying the Apigee proxy..."
import_and_deploy_apiproxy "$PROXY_NAME"

# Must export. These vars are all expected by the integration tests (apickli).
export SAMPLE_PROXY_BASEPATH="/encrypted-jwt-java"

echo " "
echo "The Apigee proxy is successfully deployed."
echo " "
echo "To call the API manually, use commands like the following:"
echo " "
echo "curl -i -X POST https://${APIGEE_HOST}${SAMPLE_PROXY_BASEPATH}/generate_jwt_rsa"
echo "curl -i -X POST https://${APIGEE_HOST}${SAMPLE_PROXY_BASEPATH}/generate_jwt_ec"
echo "curl -i -X POST https://${APIGEE_HOST}${SAMPLE_PROXY_BASEPATH}/generate_jwe_rsa"
echo "curl -i -X POST https://${APIGEE_HOST}${SAMPLE_PROXY_BASEPATH}/generate_jwe_ec"
echo "curl -i -X POST https://${APIGEE_HOST}${SAMPLE_PROXY_BASEPATH}/generate_jwt_via_jwks_rsa"
echo "curl -i -X POST https://${APIGEE_HOST}${SAMPLE_PROXY_BASEPATH}/generate_jwt_via_jwks_ec"
echo "curl -i -X POST https://${APIGEE_HOST}${SAMPLE_PROXY_BASEPATH}/generate_jwe_via_jwks_rsa"
echo "curl -i -X POST https://${APIGEE_HOST}${SAMPLE_PROXY_BASEPATH}/generate_jwe_via_jwks_ec"
echo "curl -i -X POST https://${APIGEE_HOST}${SAMPLE_PROXY_BASEPATH}/generate_signed_jwt_wrapped_in_jwe_rsa"
