#!/usr/bin/env bash

set -euo pipefail

for function in Notary Operator Emails; do
  gcloud functions deploy "${function}" \
    --runtime go113 \
    --memory 128 \
    --trigger-http \
    --allow-unauthenticated \
    --vpc-connector default \
    --set-env-vars JWT_SIGNING_KEY=${JWT_SIGNING_KEY},NOTARY_BACKEND="https://notary-k3cimrd2pq-uc.a.run.app",NOTARY_QPH="50",OPERATOR_BACKEND="https://operator-k3cimrd2pq-uc.a.run.app",OPERATOR_QPH="5",EMAILS_BACKEND="https://mails-k3cimrd2pq-uc.a.run.app",EMAILS_QPH="5",REDIS_HOST="10.72.126.123:6379"
done
