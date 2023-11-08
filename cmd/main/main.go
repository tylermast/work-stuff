package main

import (
	"crypto/rand"
	"encoding/gob"
	"net/http"
	"os"
	"time"

	"tylerdmast/work/pkg/authenticator"
	"tylerdmast/work/web/components"
	"tylerdmast/work/web/state"

	"github.com/charmbracelet/log"
	"github.com/joho/godotenv"
)

func main() {
	logger := log.NewWithOptions(os.Stderr, log.Options{
		Level:           log.DebugLevel,
		ReportTimestamp: true,
		ReportCaller:    true,
	})

	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		logger.Fatal("Issue generating 64 byte secret key", "err", err)
	}
	if len(key) != 64 {
		logger.Fatal("Key is not of appropriate length", "len", len(key))
	}
	logger.Debug("Generated secret key")

	err = godotenv.Load("configs/.env")
	if err != nil {
		logger.Fatal("Issue reading .env file", "err", err)
	}
	logger.Debug("Loaded env file")

	gob.Register(&authenticator.User{})

	logger.Debug("Initiating auth client...")
	auth := authenticator.Authorization{
		Log: *logger.WithPrefix("AUTH"),
	}
	err = auth.New(key)
	if err != nil {
		logger.Fatal("Issue initiating auth struct", "err", err)
	}
	logger.Debug("Auth client successfully initiated")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		pageState := state.IsLoggedIn(r, auth, *logger)
		components.Home(pageState).Render(r.Context(), w)
	})
	http.HandleFunc("/login", auth.LoginHandler)
	http.HandleFunc("/callback", auth.CallbackHandler)
	http.HandleFunc("/logout", auth.LogoutHandler)
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "assets/favicon.ico")
	})
	http.HandleFunc("/time", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().Format("15:04")
		logger.Debug("Called /time", "time", now)
		w.Write([]byte(now))
	})
	http.ListenAndServe(":8080", nil)
}
