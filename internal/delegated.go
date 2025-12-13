package internal

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func (i *Instance) handleDelegateAccess(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	signedState := q.Get("s")
	if signedState == "" {
		return fmt.Errorf("missing state parameter")
	}

	urlState, err := decodeURLState(signedState, i.secret)
	if err != nil {
		return fmt.Errorf("failed to decode URL state: %w", err)
	}

	cookie, err := r.Cookie(i.config.CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return i.redirectToAuthorize(w, r, urlState)
	} else if err != nil {
		return fmt.Errorf("failed to retrieve cookie: %w", err)
	}

	_, err = decodeUserState(cookie.Value, i.secret)
	if errors.Is(err, errInvalidState) {
		fmt.Println("invalid user state, redirecting to authorize", err)
		return i.redirectToAuthorize(w, r, urlState)
	} else if err != nil {
		return fmt.Errorf("failed to decode user state: %w", err)
	}

	delegateUrl, err := url.Parse(fmt.Sprintf("%s://%s%s", urlState.returnURL.Scheme, urlState.returnURL.Host, i.config.DelegationPath))
	if err != nil {
		return fmt.Errorf("failed to parse delegation URL: %w", err)
	}
	q = delegateUrl.Query()
	q.Set("s", signedState)
	q.Set("u", cookie.Value)
	delegateUrl.RawQuery = q.Encode()

	http.Redirect(w, r, delegateUrl.String(), http.StatusFound)
	return nil
}

func (i *Instance) handleFinalizeAccessDelegation(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	if q.Has("whoami") {
		return i.handleWhoami(w, r)
	}

	signedState := q.Get("s")
	if signedState == "" {
		return fmt.Errorf("missing state parameter")
	}

	urlState, err := decodeURLState(signedState, i.secret)
	if err != nil {
		return fmt.Errorf("failed to decode URL state: %w", err)
	}

	if urlState.returnURL.Host != r.Host {
		return fmt.Errorf("return URL host %q does not match request host %q", urlState.returnURL.Host, r.Host)
	}

	csrf, err := r.Cookie(i.config.CSRFCookieName)
	if err != nil {
		return fmt.Errorf("failed to retrieve CSRF cookie: %w", err)
	} else if csrf.Value != urlState.nonce {
		return fmt.Errorf("CSRF token mismatch")
	}

	signedUserState := q.Get("u")
	if signedUserState == "" {
		return fmt.Errorf("missing user state parameter")
	}

	_, err = decodeUserState(signedUserState, i.secret)
	if err != nil {
		return fmt.Errorf("failed to decode user state: %w", err)
	}

	// set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     i.config.CookieName,
		Value:    signedUserState,
		Path:     "/",
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     i.config.CSRFCookieName,
		Value:    "",
		HttpOnly: true,
		MaxAge:   -1,
	})

	http.Redirect(w, r, urlState.returnURL.String(), http.StatusFound)
	return nil
}

func (i *Instance) handleVerifyDelegatedAccess(w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie(i.config.CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return i.redirectToAccess(w, r)
	} else if err != nil {
		return fmt.Errorf("failed to retrieve cookie: %w", err)
	}

	userState, err := decodeUserState(cookie.Value, i.secret)
	if errors.Is(err, errInvalidState) {
		fmt.Println("invalid user state, redirecting to access", err)
		return i.redirectToAccess(w, r)
	} else if err != nil {
		return fmt.Errorf("failed to decode user state: %w", err)
	}

	// has restricted groups
	header := r.Header.Get(i.config.HeaderPrefix + "Expected-Groups")
	if header != "" {
		expectedGroups := strings.Split(header, ",")
		if !userState.HasGroups(expectedGroups) {
			return fmt.Errorf("user %q missing required groups: %v", userState.Name, expectedGroups)
		}
	}

	// set headers
	for k, v := range userState.ToHeaders(i.config.HeaderPrefix) {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusNoContent)

	return nil
}

func (i *Instance) redirectToAccess(w http.ResponseWriter, r *http.Request, state ...*urlstate) error {
	if len(state) == 0 {
		state = append(state, newURLState(r))
	}

	url := i.config.BaseURL
	q := url.Query()
	// we need to sign it, to avoid open redirect vulnerabilities
	q.Set("s", state[0].sign(i.secret))
	url.RawQuery = q.Encode()

	http.SetCookie(w, &http.Cookie{
		Name:     i.config.CSRFCookieName,
		Value:    state[0].nonce,
		HttpOnly: true,
	})

	http.Redirect(w, r, url.String(), http.StatusFound)
	return nil
}
