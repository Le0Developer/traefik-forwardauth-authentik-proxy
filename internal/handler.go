package internal

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
)

type Instance struct {
	secret []byte
	config *Config
}

func (i *Instance) Mux() *http.ServeMux {
	mux := http.NewServeMux()

	host := i.config.BaseURL.Hostname()

	mux.HandleFunc(host+"/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc(host+"/authorize", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, i.handleAuthorize(w, r))
	})

	mux.HandleFunc(host+"/{$}", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, i.handleDelegateAccess(w, r))
	})

	mux.HandleFunc(host+"/whoami", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, i.handleWhoami(w, r))
	})

	mux.HandleFunc(host+"/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	mux.HandleFunc(i.config.DelegationPath, func(w http.ResponseWriter, r *http.Request) {
		writeError(w, i.handleFinalizeAccessDelegation(w, r))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if uri := r.Header.Get("X-Forwarded-Uri"); uri != "" {
			uri := r.Header.Get("X-Forwarded-Uri")
			parsed, err := url.Parse(uri)
			if err != nil {
				fmt.Printf("failed to parse X-Forwarded-Uri: %v\n", err)
			} else {
				r.URL.Path = parsed.Path
				r.URL.RawQuery = parsed.RawQuery
			}
		}
		writeError(w, i.handleVerifyDelegatedAccess(w, r))
	})

	fixmux := http.NewServeMux()
	fixmux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Host") != "" {
			host := r.Header.Get("X-Forwarded-Host")
			r.Host = host
			r.URL.Host = host
		} else if r.Host != "" {
			r.URL.Host = r.Host
		}
		if r.Header.Get("X-Forwarded-Proto") != "" {
			r.URL.Scheme = r.Header.Get("X-Forwarded-Proto")
		} else {
			if r.TLS != nil {
				r.URL.Scheme = "https"
			} else {
				r.URL.Scheme = "http"
			}
		}

		mux.ServeHTTP(w, r)
	})

	return fixmux
}

func writeError(w http.ResponseWriter, err error) {
	if err != nil {
		fmt.Println("request failed:", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func New(cfg *Config) Instance {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret) // no longer errors since Go 1.20

	return Instance{
		secret: secret,
		config: cfg,
	}
}
