package internal

import (
	"crypto/hmac"
	"crypto/sha256"
)

func mixSecret(secret []byte, domain string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(domain))
	return h.Sum(nil)
}

func (i *Instance) secretFor(domain string) []byte {
	return mixSecret(i.secret, domain)
}
