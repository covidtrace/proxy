package proxy

import (
	"errors"
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

var backendService string
var limiter *redisrate.Limiter
var limit int
var reverseProxy *httputil.ReverseProxy

func init() {
	backendService = os.Getenv("BACKEND_SERVICE")
	if backendService == "" {
		panic(errors.New("BACKEND_SERVICE environment variable is required"))
	}

	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		panic(errors.New("REDIS_HOST environment variable is required"))
	}

	requestsPerHour := os.Getenv("REQUESTS_PER_MINUTE")
	if requestsPerHour == "" {
		requestsPerHour = "5"
	}

	var err error
	limit, err = strconv.Atoi(requestsPerHour)
	if err != nil {
		panic(err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: redisHost,
	})
	limiter = redisrate.NewLimiter(rdb)

	backendURL, err := url.Parse(backendService)
	if err != nil {
		panic(err)
	}

	reverseProxy = &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = backendURL.Scheme
			r.URL.Host = backendURL.Host
			r.Host = backendURL.Host
			if jwt, err := getJwtToken(backendService); err == nil {
				r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))
			}
		},
	}
}

func Proxy(w http.ResponseWriter, r *http.Request) {
	res, err := limiter.Allow(r.Header.Get("X-Forwarded-For"), redisrate.PerHour(limit))
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}

	if !res.Allowed {
		w.Header().Set("x-ratelimit-allowed", "false")
		// http.Error(w, "Rate limit exceeded", 429)
		// return
	}

	reverseProxy.ServeHTTP(w, r)
}
