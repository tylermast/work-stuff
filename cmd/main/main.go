package main

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"log"
	"net/http"

	"tylerdmast/work/pkg/authenticator"
	"tylerdmast/work/pkg/cookies"
	"tylerdmast/work/pkg/errors"

	"github.com/joho/godotenv"
)

func main() {
	key := make([]byte, 64)
	_, err := rand.Read(key)
	errors.HandleFatalError(err, "Main: Issue generating 64 byte secret key")
	if len(key) != 64 {
		errors.HandleFatalError(err, "Main: Key not of length 64 bytes")
	}
	log.Printf("Main: Generated secret key")

	err = godotenv.Load("configs/.env")
	errors.HandleFatalError(err, "Main: Issue reading .env file")
	log.Printf("Main: Loaded env file")

	gob.Register(&cookies.Session{})
	gob.Register(&authenticator.User{})

	log.Printf("Main: Initiating auth client...")
	auth := authenticator.Authorization{}
	err = auth.New()
	auth.SecretKey = key
	errors.HandleFatalError(err, "Main: Issue initiating authorization struct")
	log.Printf("Main: Initiated auth client %v", auth)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		for name, headers := range r.Header {
			for _, h := range headers {
				fmt.Fprintf(w, "%v: %v\n", name, h)
			}
		}
	})
	http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		value, err := cookies.ReadSigned(r, "ex", key)
		errors.LogError(err, "/GET: Problem reading cookie")
		w.Write([]byte(value))
	})
	http.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		cookie := http.Cookie{
			Name:     "ex",
			Value:    "foo",
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}

		err := cookies.WriteSigned(w, cookie, key)
		errors.LogError(err, "/SET: Problem setting cookie")
		if err != nil {
			http.Error(w, "cookie setting error", http.StatusInternalServerError)
			return
		}

		w.Write([]byte("cookie set"))
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		auth.LoginHandler(w, r)
	})
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		auth.CallbackHandler(w, r)
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		auth.LogoutHandler(w, r)
	})
	http.ListenAndServe(":8080", nil)
}
