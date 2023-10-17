package authenticator

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	"tylerdmast/work/pkg/cookies"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Authorization struct {
	OidcProvider *oidc.Provider
	OauthConfig  oauth2.Config
	SecretKey    []byte
}

type User struct {
	Name      string
	AvatarURL string
}

func (a *Authorization) New() error {
	provider, err := oidc.NewProvider(
		context.Background(),
		"https://"+os.Getenv("AUTH0_DOMAIN")+"/",
	)
	if err != nil {
		return err
	}

	conf := oauth2.Config{
		ClientID:     os.Getenv("AUTH0_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH0_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH0_CALLBACK_URL"),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	a.OidcProvider = provider
	a.OauthConfig = conf
	return nil
}

func (a *Authorization) VerifyIDToken(
	ctx context.Context,
	token *oauth2.Token,
) (*oidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	oidcConfig := &oidc.Config{
		ClientID: a.OauthConfig.ClientID,
	}
	return a.OidcProvider.Verifier(oidcConfig).Verify(ctx, rawIDToken)
}

func (a *Authorization) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	log.Printf("Login Handler: state = %s", state)
	if err != nil {
		http.Error(w, "Error generating state", http.StatusInternalServerError)
	}

	sess := cookies.Session{
		Values: make(map[string]interface{}),
	}
	sess.Values["state"] = state
	log.Printf("Login Handler: session values = %s", sess.Values)

	var buf bytes.Buffer
	err = gob.NewEncoder(&buf).Encode(sess)
	if err != nil {
		log.Printf("Issue encoding session cookie")
		http.Error(w, "Issue encoding session cookie", http.StatusInternalServerError)
		return
	}
	sessionCookie := http.Cookie{
		Name:     "session",
		Value:    buf.String(),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	err = cookies.WriteSigned(w, sessionCookie, a.SecretKey)
	if err != nil {
		log.Printf("Login Handler: issue writing session cookie - %s", err)
		http.Error(w, "Error writing session cookie", http.StatusInternalServerError)
		return
	}

	audienceURI := oauth2.SetAuthURLParam("audience", "https://work-stuff/")
	http.Redirect(w, r, a.OauthConfig.AuthCodeURL(state, audienceURI), http.StatusTemporaryRedirect)
}

func (a *Authorization) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	sessionGob, err := cookies.ReadSigned(r, "session", a.SecretKey)
	if err != nil {
		log.Printf("Callback Handler: issue retrieving session cookie gob - %s", err)
		http.Error(w, "Problem retrieving session cookie", http.StatusInternalServerError)
		return
	}

	var sessionCookie cookies.Session
	reader := strings.NewReader(sessionGob)
	err = gob.NewDecoder(reader).Decode(&sessionCookie)
	if err != nil {
		log.Printf("Callback Handler: issue decoding session cookie - %s", err)
		http.Error(w, "decoding error", http.StatusInternalServerError)
		return
	}
	log.Printf("Callback Handler: Expected state from callback - %s", sessionCookie.Values["state"])

	err = r.ParseForm()
	if err != nil {
		log.Printf("Callback Handler: issue parse request form", err)
		http.Error(w, "parse error", http.StatusInternalServerError)
		return
	}

	callbackState := r.FormValue("state")
	log.Printf("Callback Handler: Callback response state - %s", callbackState)
	if sessionCookie.Values["state"] != callbackState {
		log.Printf("Callback Handler: state from callback does not match expected state")
		http.Error(w, "state error", http.StatusUnauthorized)
		return
	}

	accToken, err := a.OauthConfig.Exchange(r.Context(), r.FormValue("code"))
	if err != nil {
		log.Printf("Callback Handler: could not exchange token %s", err)
		http.Error(w, "exchange error", http.StatusInternalServerError)
		return
	}
	log.Printf("Callback Handler: token - %s", accToken.AccessToken)
	idToken, err := a.VerifyIDToken(r.Context(), accToken)
	if err != nil {
		log.Printf("Callback Handler: could not verify ID Token %s", err)
		http.Error(w, "verification error", http.StatusInternalServerError)
		return
	}
	log.Printf("Callback Handler: ID token - %s", idToken)

	var profile map[string]interface{}
	err = idToken.Claims(&profile)
	if err != nil {
		log.Printf("Callback Handler: Error unmarshalling profile from id token - %s", err)
		http.Error(w, "parsing error", http.StatusInternalServerError)
		return
	}
	log.Printf("Callback Handler: user profile - %s", profile)

	user := User{
		Name:      profile["name"].(string),
		AvatarURL: profile["picture"].(string),
	}
	var buf bytes.Buffer
	err = gob.NewEncoder(&buf).Encode(user)
	if err != nil {
		log.Printf("Issue encoding user object - %s", err)
		http.Error(w, "encoding error", http.StatusInternalServerError)
		return
	}
	profileCookie := http.Cookie{
		Name:     "profile",
		Value:    buf.String(),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	err = cookies.WriteSigned(w, profileCookie, a.SecretKey)
	if err != nil {
		log.Printf("Login Handler: issue writing profile cookie - %s", err)
		http.Error(w, "Error writing profile cookie", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("<a href='login' target='_self'>Login</a>"))
}

func generateState() (string, error) {
	rawState := make([]byte, 32)
	_, err := rand.Read(rawState)
	if err != nil {
		return "", err
	}
	encodedState := base64.StdEncoding.EncodeToString(rawState)
	return encodedState, nil
}
