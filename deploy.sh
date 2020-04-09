#!/usr/bin/env bash

set -euo pipefail

for function in Notary Operator Emails; do
  gcloud functions deploy "${function}" \
    --runtime go113 \
    --memory 128 \
    --trigger-http \
    --allow-unauthenticated \
    --vpc-connector "${VPC_CONNECTOR}" \
    --set-env-vars JWT_SIGNING_KEY="${JWT_SIGNING_KEY}",NOTARY_BACKEND="${NOTARY_BACKEND}",NOTARY_QPH="${NOTARY_QPH}",OPERATOR_BACKEND="${OPERATOR_BACKEND}",OPERATOR_QPH="${OPERATOR_QPH}",EMAILS_BACKEND="${EMAILS_BACKEND}",EMAILS_QPH="${EMAILS_QPH}",REDIS_HOST="${REDIS_HOST}"
done
