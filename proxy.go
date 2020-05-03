package proxy

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/covidtrace/jwt"
	"github.com/covidtrace/utils/env"
	httputils "github.com/covidtrace/utils/http"
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
	endpoint := env.MustGet(fmt.Sprintf("%s_BACKEND", prefix))

	qph, err := strconv.Atoi(env.MustGet(fmt.Sprintf("%s_QPH", prefix)))
	if err != nil {
		panic(err)
	}

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

	issuer = jwt.NewIssuer([]byte(env.MustGet("JWT_SIGNING_KEY")), "covidtrace/operator", "covidtrace/token", dur)
	notary = newBackend("NOTARY")
	elevatedNotary = newBackend("ELEVATED_NOTARY")
	operator = newBackend("OPERATOR")
	emails = newBackend("EMAILS")

	rc := redis.NewClient(&redis.Options{
		Addr: env.MustGet("REDIS_HOST"),
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
	authorization, err := httputils.GetAuthorization(r, "bearer")
	if err != nil {
		httputils.ReplyError(w, err, http.StatusUnauthorized)
		return
	}

	claims, err := issuer.Validate(authorization)
	if err != nil {
		httputils.ReplyError(w, err, http.StatusUnauthorized)
		return
	}

	hash := claims.Hash
	if hash == "" {
		httputils.ReplyError(w, errors.New("Missing hash"), http.StatusUnauthorized)
		return
	}

	allowed, err := checkAllow(fmt.Sprintf("%s/%s", "notary", hash), notary.qph)
	if err != nil {
		httputils.ReplyInternalServerError(w, err)
		return
	}

	if !allowed {
		httputils.ReplyError(w, errors.New("Rate limit exceeded"), http.StatusTooManyRequests)
		return
	}

	notary.proxy.ServeHTTP(w, r)
}

// ElevatedNotary is the cloud function that handles requests to the elevated notary
// service, ensuring the token is elevated and rate limiting using the JWT hash key
func ElevatedNotary(w http.ResponseWriter, r *http.Request) {
	authorization, err := httputils.GetAuthorization(r, "bearer")
	if err != nil {
		httputils.ReplyError(w, err, http.StatusUnauthorized)
		return
	}

	claims, err := issuer.WithAud("covidtrace/elevated").Validate(authorization)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if claims.Role != "elevated_user" {
		httputils.ReplyError(w, errors.New("role is not `elevated_user`"), http.StatusUnauthorized)
		return
	}

	allowed, err := checkAllow(fmt.Sprintf("%s/%s", "elevatedNotary", claims.Identifier), elevatedNotary.qph)
	if err != nil {
		httputils.ReplyInternalServerError(w, err)
		return
	}

	if !allowed {
		httputils.ReplyError(w, errors.New("Rate limit exceeded"), http.StatusTooManyRequests)
		return
	}

	elevatedNotary.proxy.ServeHTTP(w, r)
}

// Operator handles proxying requests to the Operator service, rate limiting by X-Forwarded-For
func Operator(w http.ResponseWriter, r *http.Request) {
	allowed, err := checkAllowReq("operator", operator.qph, r)
	if err != nil {
		httputils.ReplyInternalServerError(w, err)
		return
	}

	if !allowed {
		httputils.ReplyError(w, errors.New("Rate limit exceeded"), http.StatusTooManyRequests)
		return
	}

	operator.proxy.ServeHTTP(w, r)
}

// Emails proxies requests to the internal email service
func Emails(w http.ResponseWriter, r *http.Request) {
	allowed, err := checkAllowReq("emails", emails.qph, r)
	if err != nil {
		httputils.ReplyInternalServerError(w, err)
		return
	}

	if !allowed {
		httputils.ReplyError(w, errors.New("Rate limit exceeded"), http.StatusTooManyRequests)
		return
	}

	emails.proxy.ServeHTTP(w, r)
}
