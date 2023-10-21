package main

import (
	"crypto/rand"
	"encoding/gob"
	"log"
	"net/http"

	"tylerdmast/work/pkg/authenticator"
	"tylerdmast/work/pkg/errors"
	"tylerdmast/work/web/components"
	"tylerdmast/work/web/state"

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

	gob.Register(&authenticator.User{})

	log.Printf("Main: Initiating auth client...")
	auth := authenticator.Authorization{}
	err = auth.New(key)
	errors.HandleFatalError(err, "Main: Issue initiating authorization struct")
	log.Printf("Main: Initiated auth client")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pageState := state.IsLoggedIn(r, auth)
		components.Home(pageState).Render(r.Context(), w)
	})
	http.HandleFunc("/login", auth.LoginHandler)
	http.HandleFunc("/callback", auth.CallbackHandler)
	http.HandleFunc("/logout", auth.LogoutHandler)
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "assets/favicon.ico")
	})
	http.ListenAndServe(":8080", nil)
}
