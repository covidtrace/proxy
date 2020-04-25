#!/usr/bin/env bash

set -euo pipefail

for function in Notary ElevatedNotary Operator Emails; do
  gcloud functions deploy "${function}" \
    --runtime go113 \
    --memory 128 \
    --trigger-http \
    --allow-unauthenticated
done
