#!/usr/bin/env bash

set -xeuo pipefail

for function in Notary Operator; do
  gcloud functions deploy "${function}" \
    --runtime go113 \
    --memory 128 \
    --trigger-http \
    --allow-unauthenticated \
    --vpc-connector default \
    --env-vars-file env.yaml
done
