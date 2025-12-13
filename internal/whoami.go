package internal

import (
	"encoding/json"
	"errors"
	"net/http"
)

func (i *Instance) handleWhoami(w http.ResponseWriter, r *http.Request) error {
	userState, err := r.Cookie(i.config.CookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nobody(w)
	} else if err != nil {
		return err
	}

	state, err := decodeUserState(userState.Value, i.secret)
	if errors.Is(err, errInvalidState) {
		return nobody(w)
	} else if err != nil {
		return err
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
	return nil
}

func nobody(w http.ResponseWriter) error {
	_, _ = w.Write([]byte("nobody"))
	return nil
}
