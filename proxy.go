package proxy

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"

	"github.com/go-redis/redis/v7"
	redisrate "github.com/go-redis/redis_rate/v8"
)

func getJwtToken(audience string) (string, error) {
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

var notaryBackend string
var notaryQph int
var notaryProxy httputil.ReverseProxy

var operatorBackend string
var operatorQph int
var operatorProxy httputil.ReverseProxy

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

func buildDirector(b string) func(r *http.Request) {
	bu, err := url.Parse(b)
	if err != nil {
		panic(err)
	}

	return func(r *http.Request) {
		r.URL.Scheme = bu.Scheme
		r.URL.Host = bu.Host
		r.Host = bu.Host

		if jwt, err := getJwtToken(b); err == nil {
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))
		}
	}
}

func init() {
	notaryBackend = getEnv("NOTARY_BACKEND")
	notaryQph = getEnvInt("NOTARY_QPH")
	notaryProxy = httputil.ReverseProxy{Director: buildDirector(notaryBackend)}

	operatorBackend = getEnv("OPERATOR_BACKEND")
	operatorQph = getEnvInt("OPERATOR_QPH")
	operatorProxy = httputil.ReverseProxy{Director: buildDirector(operatorBackend)}

	redisHost := getEnv("REDIS_HOST")
	rdb := redis.NewClient(&redis.Options{
		Addr: redisHost,
	})
	limiter = redisrate.NewLimiter(rdb)
}

func checkAllowed(prefix string, qph int, r *http.Request) (bool, error) {
	key := fmt.Sprintf("%s/%s", prefix, r.Header.Get("X-Forwarded-For"))
	res, err := limiter.Allow(key, redisrate.PerHour(qph))
	if err != nil {
		return false, err
	}

	return res.Allowed, nil
}

func Notary(w http.ResponseWriter, r *http.Request) {
	allowed, err := checkAllowed("notary", notaryQph, r)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}

	if !allowed {
		w.Header().Set("x-ratelimit-allowed", "false")
		// http.Error(w, "Rate limit exceeded", 429)
		// return
	}

	notaryProxy.ServeHTTP(w, r)
}

func Operator(w http.ResponseWriter, r *http.Request) {
	allowed, err := checkAllowed("operator", operatorQph, r)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}

	if !allowed {
		w.Header().Set("x-ratelimit-allowed", "false")
		// http.Error(w, "Rate limit exceeded", 429)
		// return
	}

	operatorProxy.ServeHTTP(w, r)
}
