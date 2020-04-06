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

var issuer *jwt.Issuer

var notaryBackend string
var notaryQph int
var notaryProxy httputil.ReverseProxy

var operatorBackend string
var operatorQph int
var operatorProxy httputil.ReverseProxy

var emailsBackend string
var emailsQph int
var emailsProxy httputil.ReverseProxy

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

func init() {
	dur, err := time.ParseDuration("1h")
	if err != nil {
		panic(err)
	}

	issuer = jwt.NewIssuer([]byte(getEnv("JWT_SIGNING_KEY")), "covidtrace/operator", "covidtrace/token", dur)

	notaryBackend = getEnv("NOTARY_BACKEND")
	notaryQph = getEnvInt("NOTARY_QPH")
	notaryProxy = httputil.ReverseProxy{Director: buildDirector(notaryBackend)}

	operatorBackend = getEnv("OPERATOR_BACKEND")
	operatorQph = getEnvInt("OPERATOR_QPH")
	operatorProxy = httputil.ReverseProxy{Director: buildDirector(operatorBackend)}

	emailsBackend = getEnv("EMAILS_BACKEND")
	emailsQph = getEnvInt("EMAILS_QPH")
	emailsProxy = httputil.ReverseProxy{Director: buildDirector(emailsBackend)}

	redisHost := getEnv("REDIS_HOST")
	rdb := redis.NewClient(&redis.Options{
		Addr: redisHost,
	})
	limiter = redisrate.NewLimiter(rdb)
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

	hash, err := issuer.Validate(authorization[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	allowed, err := checkAllow(fmt.Sprintf("%s/%s", "notary", hash), notaryQph)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !allowed {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	notaryProxy.ServeHTTP(w, r)
}

func Operator(w http.ResponseWriter, r *http.Request) {
	allowed, err := checkAllowReq("operator", operatorQph, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !allowed {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	operatorProxy.ServeHTTP(w, r)
}

func Emails(w http.ResponseWriter, r *http.Request) {
	allowed, err := checkAllowReq("emails", emailsQph, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !allowed {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	emailsProxy.ServeHTTP(w, r)
}
