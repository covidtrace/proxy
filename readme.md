# covidtrace/proxy

Proxy is a rate limiting Google Cloud Function that knows how to proxy
authenticated traffic to Google Cloud Run backend services.

Proxy interacts with a Redis instance which, on Google Cloud Platform, is a
private VPC service. At the time of writing, Cloud Run services have no
ability to connect to private VPC services, hence the need for a Cloud
Function.

Proxy is pretty tightly coupled with COVID Trace services so it's really only
useful in the context of deploying a COVID Trace stack. The code is pretty
simple to follow, check out [proxy.go](proxy.go) to better understand how it
works and [deploy.sh](deploy.sh) to see how it is deployed.