package proxy

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/covidtrace/jwt"
	"github.com/go-redis/redis/v7"
	redisrate "github.com/go-redis/redis_rate/v8"
)

type backend struct {
	qph   int
	proxy httputil.ReverseProxy
}

func buildDirector(b string) func(r *http.Request) {
	bu, err := url.Parse(b)
	if err != nil {
		panic(err)
	}

	return func(r *http.Request) {
		r.URL.Scheme = bu.Scheme
		r.URL.Host = bu.Host
		r.Host = bu.Host

		if jwt, err := getGoogleJWT(b); err == nil {
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))
		}
	}
}

func newBackend(prefix string) backend {
	endpoint := getEnv(fmt.Sprintf("%s_BACKEND", prefix))
	qph := getEnvInt(fmt.Sprintf("%s_QPH", prefix))

	return backend{
		qph: qph,
		proxy: httputil.ReverseProxy{
			Director: buildDirector(endpoint),
		},
	}
}

var issuer *jwt.Issuer
var notary backend
var elevatedNotary backend
var operator backend
var emails backend
var limiter *redisrate.Limiter

func getEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		panic(fmt.Errorf("%s is a required env var", key))
	}

	return val
}

func getEnvInt(key string) int {
	val, err := strconv.Atoi(getEnv(key))
	if err != nil {
		panic(err)
	}

	return val
}

func getGoogleJWT(audience string) (string, error) {
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf(
			"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=%s",
			url.QueryEscape(audience),
		),
		nil,
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func init() {
	dur, err := time.ParseDuration("1h")
	if err != nil {
		panic(err)
	}

	issuer = jwt.NewIssuer([]byte(getEnv("JWT_SIGNING_KEY")), "covidtrace/operator", "covidtrace/token", dur)
	notary = newBackend("NOTARY")
	elevatedNotary = newBackend("ELEVATED_NOTARY")
	operator = newBackend("OPERATOR")
	emails = newBackend("EMAILS")

	rc := redis.NewClient(&redis.Options{
		Addr: getEnv("REDIS_HOST"),
	})
	limiter = redisrate.NewLimiter(rc)
}

func checkAllow(key string, qph int) (bool, error) {
	res, err := limiter.Allow(key, redisrate.PerHour(qph))
	if err != nil {
		return false, err
	}

	return res.Allowed, nil
}

func checkAllowReq(prefix string, qph int, r *http.Request) (bool, error) {
	return checkAllow(fmt.Sprintf("%s/%s", prefix, r.Header.Get("X-Forwarded-For")), qph)
}

// Notary is the cloud function that handles requests to the notary service, rate limiting
// using the JWT hash key
func Notary(w http.ResponseWriter, r *http.Request) {
	authorization := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(authorization) != 2 {
		http.Error(w, "Missing `Authorization` header", http.StatusUnauthorized)
		return
	}

	if !strings.EqualFold(authorization[0], "bearer") {
		http.Error(w, "Only `Bearer` authorization type supported", http.StatusUnauthorized)
		return
	}

	claims, err := issuer.Validate(authorization[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	allowed, err := checkAllow(fmt.Sprintf("%s/%s", "notary", claims.Hash), notary.qph)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !allowed {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	notary.proxy.ServeHTTP(w, r)
}

// ElevatedNotary is the cloud function that handles requests to the elevated notary
// service, ensuring the token is elevated and rate limiting using the JWT hash key
func ElevatedNotary(w http.ResponseWriter, r *http.Request) {
	authorization := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(authorization) != 2 {
		http.Error(w, "Missing `Authorization` header", http.StatusUnauthorized)
		return
	}

	if !strings.EqualFold(authorization[0], "bearer") {
		http.Error(w, "Only `Bearer` authorization type supported", http.StatusUnauthorized)
		return
	}

	claims, err := issuer.WithAud("covidtrace/elevated").Validate(authorization[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	allowed, err := checkAllow(fmt.Sprintf("%s/%s", "elevatedNotary", claims.Hash), elevatedNotary.qph)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !allowed {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	elevatedNotary.proxy.ServeHTTP(w, r)
}

// Operator handles proxying requests to the Operator service, rate limiting by X-Forwarded-For
func Operator(w http.ResponseWriter, r *http.Request) {
	allowed, err := checkAllowReq("operator", operator.qph, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !allowed {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	operator.proxy.ServeHTTP(w, r)
}

// Emails proxies requests to the internal email service
func Emails(w http.ResponseWriter, r *http.Request) {
	allowed, err := checkAllowReq("emails", emails.qph, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !allowed {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	emails.proxy.ServeHTTP(w, r)
}
