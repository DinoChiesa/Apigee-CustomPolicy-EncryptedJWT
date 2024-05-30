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

delete_apiproxy() {
    local proxy_name=$1
    printf "Checking Proxy %s\n" "${proxy_name}"
    if apigeecli apis get --name "$proxy_name" --org "$PROJECT" --token "$TOKEN" --disable-check >/dev/null 2>&1; then
        OUTFILE=$(mktemp /tmp/apigee-samples.apigeecli.out.XXXXXX)
        if apigeecli apis listdeploy --name "$proxy_name" --org "$PROJECT" --token "$TOKEN" --disable-check >"$OUTFILE" 2>&1; then
            NUM_DEPLOYS=$(jq -r '.deployments | length' "$OUTFILE")
            if [[ $NUM_DEPLOYS -ne 0 ]]; then
                echo "Undeploying ${proxy_name}"
                for ((i = 0; i < NUM_DEPLOYS; i++)); do
                    ENVNAME=$(jq -r ".deployments[$i].environment" "$OUTFILE")
                    REV=$(jq -r ".deployments[$i].revision" "$OUTFILE")
                    apigeecli apis undeploy --name "${proxy_name}" --env "$ENVNAME" --rev "$REV" --org "$PROJECT" --token "$TOKEN" --disable-check
                done
            else
                printf "  There are no deployments of %s to remove.\n" "${proxy_name}"
            fi
        fi
        [[ -f "$OUTFILE" ]] && rm "$OUTFILE"

        echo "Deleting proxy ${proxy_name}"
        apigeecli apis delete --name "${proxy_name}" --org "$PROJECT" --token "$TOKEN" --disable-check

    else
        printf "  The proxy %s does not exist.\n" "${proxy_name}"
    fi
}

[[ -z "$PROJECT" ]] && echo "No PROJECT variable set" && exit 1
[[ -z "$APIGEE_ENV" ]] && echo "No APIGEE_ENV variable set" && exit 1
[[ -z "$APIGEE_HOST" ]] && echo "No APIGEE_HOST variable set" && exit 1

TOKEN=$(gcloud auth print-access-token)

delete_apiproxy "${PROXY_NAME}"

echo " "
echo "the Apigee proxy should now be removed."
echo " "
