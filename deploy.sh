#!/usr/bin/env bash

set -xeuo pipefail

gcloud functions deploy Proxy \
  --runtime go113 \
  --trigger-http \
  --allow-unauthenticated \
  --vpc-connector default \
  --set-env-vars BACKEND_SERVICE=https://notary-k3cimrd2pq-uc.a.run.app,REDIS_HOST=10.72.126.123:6379,REQUESTS_PER_HOUR=100
