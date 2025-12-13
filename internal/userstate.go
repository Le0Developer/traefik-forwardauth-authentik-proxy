package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type userState struct {
	Username     string   `json:"preferred_username"`
	Groups       []string `json:"groups"`
	Entitlements string   `json:"entitlements"`
	Email        string   `json:"email"`
	Name         string   `json:"name"`
	UID          string   `json:"sub"`

	Expiration time.Time `json:"exp,omitempty"`
}

func (s *userState) ToHeaders(prefix string) map[string]string {
	return map[string]string{
		prefix + "username":     s.Username,
		prefix + "groups":       strings.Join(s.Groups, ","),
		prefix + "entitlements": s.Entitlements,
		prefix + "email":        s.Email,
		prefix + "name":         s.Name,
		prefix + "uid":          s.UID,
	}
}

func (s *userState) HasGroups(requiredGroups []string) bool {
	groupSet := make(map[string]struct{}, len(s.Groups))
	for _, g := range s.Groups {
		groupSet[g] = struct{}{}
	}

	for _, rg := range requiredGroups {
		rg = strings.TrimSpace(rg)
		if _, ok := groupSet[rg]; !ok {
			return false
		}
	}
	return true
}

func (s *userState) signature(secret []byte) ([]byte, error) {
	h := hmac.New(sha256.New, secret)
	m, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	h.Write(m)
	return h.Sum(nil), nil
}

func (s *userState) sign(secret []byte) (string, error) {
	m, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	signature, err := s.signature(secret)
	if err != nil {
		return "", err
	}
	encodedState := base64.RawURLEncoding.EncodeToString(m)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return "1." + encodedState + "." + encodedSignature, nil
}

func decodeUserState(signedState string, secret []byte) (*userState, error) {
	parts := strings.SplitN(signedState, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 parts, got %d", errInvalidState, len(parts))
	} else if parts[0] != "1" {
		return nil, fmt.Errorf("%w: unsupported version %q", errInvalidState, parts[0])
	}

	encodedState := parts[1]
	encodedSignature := parts[2]

	stateBytes, err := base64.RawURLEncoding.DecodeString(encodedState)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode state: %v", errInvalidState, err)
	}

	var s userState
	if err := json.Unmarshal(stateBytes, &s); err != nil {
		return nil, fmt.Errorf("%w: failed to unmarshal state: %v", errInvalidState, err)
	}

	expectedSignature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode signature: %v", errInvalidState, err)
	}

	actualSignature, err := s.signature(secret)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to compute signature: %v", errInvalidState, err)
	}

	if !hmac.Equal(expectedSignature, actualSignature) {
		return nil, fmt.Errorf("%w: signature mismatch", errInvalidState)
	}

	if time.Now().After(s.Expiration) {
		return nil, fmt.Errorf("%w: state has expired", errInvalidState)
	}

	return &s, nil
}
