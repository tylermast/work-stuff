package cookies

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
)

type Store struct {
	Cookies    map[string]http.Cookie
	SigningKey []byte
}

func (jar *Store) ReadSigned(r *http.Request, name string) (string, error) {
	signedVal, err := jar.Read(r, name)
	if err != nil {
		return "", err
	}
	log.Printf("Reading signed cookie: %s", name)

	if len(signedVal) < sha256.New().Size() {
		return "", errors.New("Cookie not signed correctly")
	}

	signature := signedVal[:sha256.Size]
	value := signedVal[sha256.Size:]

	mac := hmac.New(sha256.New, jar.SigningKey)
	mac.Write([]byte(name))
	mac.Write([]byte(value))
	expectedSig := mac.Sum(nil)

	if !hmac.Equal([]byte(signature), expectedSig) {
		return "", errors.New("Cookie signature mismatch")
	}

	return value, nil
}

func (jar *Store) Read(r *http.Request, name string) (string, error) {
	log.Printf("Reading raw cookie: %s", name)
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", errors.New("Invalid cookie value")
	}

	return string(value), nil
}

func (jar *Store) WriteSigned(w http.ResponseWriter, cookie http.Cookie) error {
	log.Printf("Writing signed cookie")
	mac := hmac.New(sha256.New, jar.SigningKey)
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))
	signature := mac.Sum(nil)

	cookie.Value = string(signature) + cookie.Value

	return jar.Write(w, cookie)
}

func (jar *Store) Write(w http.ResponseWriter, cookie http.Cookie) error {
	log.Printf("Writing raw cookie")
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))
	if len(cookie.String()) > 4096 {
		return errors.New("Cookie value too long")
	}

	http.SetCookie(w, &cookie)
	return nil
}
