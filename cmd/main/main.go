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
	http.HandleFunc("/login", auth.LoginHandler)
	http.HandleFunc("/callback", auth.CallbackHandler)
	http.HandleFunc("/logout", auth.LogoutHandler)
	http.ListenAndServe(":8080", nil)
}
