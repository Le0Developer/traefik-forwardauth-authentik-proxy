package internal

import (
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	BaseURL          *url.URL
	AuthentikBaseURL *url.URL
	ClientID         string
	ClientSecret     string
	BackchannelURL   *url.URL

	HeaderPrefix   string
	DelegationPath string

	SessionDuration time.Duration

	CookieName     string
	CSRFCookieName string
}

func NewConfigFromEnv() *Config {
	return &Config{
		BaseURL:          getEnvUrl("ACCESS_BASE_URL"),
		AuthentikBaseURL: getEnvUrl("AUTHENTIK_BASE_URL"),
		ClientID:         getEnv("AUTHENTIK_CLIENT_ID"),
		ClientSecret:     getEnv("AUTHENTIK_CLIENT_SECRET"),
		BackchannelURL:   getEnvUrl("AUTHENTIK_BACKCHANNEL_URL", true),
		HeaderPrefix:     getEnv("HEADER_PREFIX", "X-authentik-"),
		DelegationPath:   getEnv("DELEGATION_PATH", "/.well-known/traefik-forwardauth-authentik-proxy/"),
		SessionDuration:  getEnvDuration("SESSION_DURATION", "1h"),
		CookieName:       getEnv("COOKIE_NAME", "A7K_SESSION"),
		CSRFCookieName:   getEnv("CSRF_COOKIE_NAME", "A7K_CSRF_TOKEN"),
	}
}

func getEnv(key string, defaults ...string) string {
	value := os.Getenv(key)
	if value == "" {
		if len(defaults) > 0 {
			return defaults[0]
		}
		panic("Environment variable " + key + " is required but not set")
	}

	if strings.HasPrefix(value, "/") {
		if data, err := os.ReadFile(value); err == nil {
			return strings.TrimSpace(string(data))
		}
	}

	return value
}

func getEnvUrl(key string, nilok ...bool) *url.URL {
	value := getEnv(key, "")
	if value == "" {
		if len(nilok) > 0 && nilok[0] {
			return nil
		}
		panic("Environment variable " + key + " is required but not set")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		panic("Environment variable " + key + " is not a valid URL: " + err.Error())
	}
	return parsed
}

func getEnvDuration(key string, defaults ...string) time.Duration {
	value := getEnv(key, defaults...)
	dur, err := time.ParseDuration(value)
	if err != nil {
		panic("Environment variable " + key + " is not a valid duration: " + err.Error())
	}
	return dur
}
