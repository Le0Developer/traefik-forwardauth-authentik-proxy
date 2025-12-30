package internal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (i *Instance) handleAuthorize(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	r.URL.RawQuery = ""
	if code == "" || state == "" {
		return fmt.Errorf("missing code or state parameter")
	}

	csrf, err := r.Cookie(i.config.CSRFCookieName)
	if err != nil {
		return fmt.Errorf("failed to retrieve CSRF cookie: %w", err)
	}

	secretForMe := i.secretFor(r.Host)

	urlState, err := decodeURLState(csrf.Value, secretForMe)
	if err != nil {
		return fmt.Errorf("failed to decode URL state: %w", err)
	} else if urlState.nonce != state {
		return fmt.Errorf("CSRF token mismatch")
	}

	// exchange code
	burl := *i.config.AuthentikBaseURL
	if i.config.BackchannelURL != nil {
		burl = *i.config.BackchannelURL
	}
	burl.Path = "/application/o/token/"

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", r.URL.String())
	form.Set("client_id", i.config.ClientID)
	form.Set("client_secret", i.config.ClientSecret)

	req, err := http.NewRequest("POST", burl.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform token request: %w", err)
	}
	//nolint:errcheck // ignore close error
	defer resp.Body.Close()

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	accessToken, ok := body["access_token"].(string)
	if !ok || accessToken == "" {
		fmt.Println("token response body:", body)
		return fmt.Errorf("missing access_token in token response")
	}

	// fetch user info
	burl.Path = "/application/o/userinfo/"

	req, err = http.NewRequest("GET", burl.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err = http.DefaultClient.Do(req)

	if err != nil {
		return fmt.Errorf("failed to perform userinfo request: %w", err)
	}
	//nolint:errcheck // ignore close error
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("userinfo request returned status %d", resp.StatusCode)
	}

	var userInfo userState
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	userInfo.Expiration = time.Now().Add(i.config.SessionDuration)

	signedUserState, err := userInfo.sign(secretForMe)
	if err != nil {
		return fmt.Errorf("failed to sign user state: %w", err)
	}

	// set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     i.config.CookieName,
		Value:    signedUserState,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     i.config.CSRFCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	return i.redirectToAccess(w, r, urlState)
}

func (i *Instance) redirectToAuthorize(w http.ResponseWriter, r *http.Request, urlState *urlstate) error {
	url := *i.config.AuthentikBaseURL
	url.Path = "/application/o/authorize/"
	redirectURL := *i.config.BaseURL
	redirectURL.Path = "/authorize"
	redirectURL.RawQuery = ""

	q := url.Query()
	q.Set("client_id", i.config.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile groups entitlements")
	q.Set("redirect_uri", redirectURL.String())
	q.Set("state", urlState.nonce)
	url.RawQuery = q.Encode()

	stateStr := urlState.sign(i.secretFor(r.Host))
	http.SetCookie(w, &http.Cookie{
		Name:     i.config.CSRFCookieName,
		Value:    stateStr,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})

	http.Redirect(w, r, url.String(), http.StatusFound)
	return nil
}
