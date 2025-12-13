package internal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type urlstate struct {
	returnURL *url.URL
	nonce     string
}

func (s *urlstate) signature(secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(s.returnURL.String()))
	h.Write([]byte(s.nonce))
	return h.Sum(nil)
}

func (s *urlstate) sign(secret []byte) string {
	signature := base64.RawURLEncoding.EncodeToString(s.signature(secret))
	encodedURL := base64.RawURLEncoding.EncodeToString([]byte(s.returnURL.String()))
	return "1." + encodedURL + "." + s.nonce + "." + signature
}

var errInvalidState = errors.New("invalid state")

func decodeURLState(signedState string, secret []byte) (*urlstate, error) {
	parts := strings.SplitN(signedState, ".", 4)
	if len(parts) != 4 {
		return nil, fmt.Errorf("%w: expected 4 parts, got %d", errInvalidState, len(parts))
	} else if parts[0] != "1" {
		return nil, fmt.Errorf("%w: unsupported version %q", errInvalidState, parts[0])
	}

	encodedURL := parts[1]
	nonce := parts[2]

	urlBytes, err := base64.RawURLEncoding.DecodeString(encodedURL)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode return URL: %v", errInvalidState, err)
	}
	returnURL, err := url.Parse(string(urlBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse return URL: %v", errInvalidState, err)
	}

	expectedSignature, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode signature: %v", errInvalidState, err)
	}

	s := &urlstate{
		returnURL: returnURL,
		nonce:     nonce,
	}
	actualSignature := s.signature(secret)
	if !hmac.Equal(expectedSignature, actualSignature) {
		return nil, fmt.Errorf("%w: signature mismatch", errInvalidState)
	}

	return s, nil
}

func newURLState(r *http.Request) *urlstate {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce) // no longer errors since Go 1.20

	return &urlstate{
		returnURL: r.URL,
		nonce:     base64.RawURLEncoding.EncodeToString(nonce),
	}
}
