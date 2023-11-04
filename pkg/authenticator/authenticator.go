package authenticator

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"

	"tylerdmast/work/pkg/cookies"

	"github.com/charmbracelet/log"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Authorization struct {
	OidcProvider *oidc.Provider
	OauthConfig  oauth2.Config
	SessionStore cookies.Store
	Log          log.Logger
}

type Session struct {
	Values map[string]interface{}
}

type User struct {
	Issuer      string  `json:"iss"`
	Subject     string  `json:"sub"`
	Audience    string  `json:"aud"`
	Expiration  float64 `json:"exp"`
	SubjectID   string  `json:"sid"`
	FirstName   string  `json:"given_name"`
	LastName    string  `json:"family_name"`
	NickName    string  `json:"nickname"`
	UpdatedTime string  `json:"updated_at"`
	Name        string  `json:"name"`
	AvatarURL   string  `json:"picture"`
	AccessToken string  `json:"-"`
}

func (a *Authorization) New(signingKey []byte) error {
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

	a.SessionStore = cookies.Store{
		SigningKey: signingKey,
		Log:        *a.Log.WithPrefix("COOK"),
	}
	return nil
}

func (a *Authorization) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
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
	a.Log.Debugf("Login Handler: state = %s", state)
	if err != nil {
		http.Error(w, "Error generating state", http.StatusInternalServerError)
	}

	sess := Session{
		Values: make(map[string]interface{}),
	}
	sess.Values["state"] = state
	a.Log.Debugf("Login Handler: session values = %s", sess.Values)

	var buf bytes.Buffer
	err = gob.NewEncoder(&buf).Encode(sess)
	if err != nil {
		a.Log.Debugf("Issue encoding session cookie")
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
	err = a.SessionStore.WriteSigned(w, sessionCookie)
	if err != nil {
		log.Printf("Login Handler: issue writing session cookie - %s", err)
		http.Error(w, "Error writing session cookie", http.StatusInternalServerError)
		return
	}

	audienceURI := oauth2.SetAuthURLParam("audience", "https://work-stuff/")
	http.Redirect(w, r, a.OauthConfig.AuthCodeURL(state, audienceURI), http.StatusTemporaryRedirect)
}

func (a *Authorization) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	sessionGob, err := a.SessionStore.ReadSigned(r, "session")
	if err != nil {
		log.Printf("Callback Handler: issue retrieving session cookie gob - %s", err)
		http.Error(w, "Problem retrieving session cookie", http.StatusInternalServerError)
		return
	}

	var sessionCookie Session
	reader := strings.NewReader(sessionGob)
	err = gob.NewDecoder(reader).Decode(&sessionCookie)
	if err != nil {
		log.Printf("Callback Handler: issue decoding session cookie - %s", err)
		http.Error(w, "decoding error", http.StatusInternalServerError)
		return
	}
	a.Log.Debugf("Callback Handler: Expected state from callback - %s", sessionCookie.Values["state"])

	err = r.ParseForm()
	if err != nil {
		a.Log.Debugf("Callback Handler: issue parse request form - %s", err)
		http.Error(w, "parse error", http.StatusInternalServerError)
		return
	}

	callbackState := r.FormValue("state")
	a.Log.Debugf("Callback Handler: Callback response state - %s", callbackState)
	if sessionCookie.Values["state"] != callbackState {
		a.Log.Debugf("Callback Handler: state from callback does not match expected state")
		http.Error(w, "state error", http.StatusUnauthorized)
		return
	}

	accToken, err := a.OauthConfig.Exchange(r.Context(), r.FormValue("code"))
	if err != nil {
		a.Log.Debugf("Callback Handler: could not exchange token %s", err)
		http.Error(w, "exchange error", http.StatusInternalServerError)
		return
	}
	a.Log.Debugf("Callback Handler: token - %s", accToken.AccessToken)
	idToken, err := a.VerifyIDToken(r.Context(), accToken)
	if err != nil {
		a.Log.Debugf("Callback Handler: could not verify ID Token %s", err)
		http.Error(w, "verification error", http.StatusInternalServerError)
		return
	}
	a.Log.Debugf("Callback Handler: ID token - %s", idToken)

	profile := User{
		AccessToken: accToken.AccessToken,
	}
	err = idToken.Claims(&profile)
	if err != nil {
		a.Log.Debugf("Callback Handler: Error unmarshalling profile from id token - %s", err)
		http.Error(w, "parsing error", http.StatusInternalServerError)
		return
	}
	a.Log.Debugf("Callback Handler: user profile - %v", profile)

	var buf bytes.Buffer
	err = gob.NewEncoder(&buf).Encode(profile)
	if err != nil {
		a.Log.Debugf("Issue encoding user object - %s", err)
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
	err = a.SessionStore.WriteSigned(w, profileCookie)
	if err != nil {
		a.Log.Debugf("Login Handler: issue writing profile cookie - %s", err)
		http.Error(w, "Error writing profile cookie", http.StatusInternalServerError)
		return
	}
	callbackRedirect, err := url.Parse("https://" + r.Host + "/")
	if err != nil {
		a.Log.Debugf("Callback Handler: issue parsing callback redirect url - %s", err)
		http.Error(w, "Error parsing callback url", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, callbackRedirect.String(), http.StatusTemporaryRedirect)
}

func (a *Authorization) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	logoutUrl, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/v2/logout")
	if err != nil {
		a.Log.Debugf("Logout Handler: Issue parsing logout url - %s", err)
		http.Error(w, "parsing error", http.StatusInternalServerError)
		return
	}
	a.Log.Debugf("Logout Handler: Setting logout url - %s", logoutUrl)

	returnTo, err := url.Parse("https://" + r.Host)
	if err != nil {
		a.Log.Debugf("Logout Handler: Issue parsing redirect url - %s", err)
		http.Error(w, "parsing error", http.StatusInternalServerError)
		return
	}
	a.Log.Debugf("Logout Handler: Setting returnTo url - %s", returnTo)

	parameters := url.Values{}
	parameters.Add("returnTo", returnTo.String())
	parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	logoutUrl.RawQuery = parameters.Encode()
	a.Log.Debugf("Logout Handler: constructed logout url - %s", logoutUrl)

	negatedSessionCookie := http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	}
	a.SessionStore.Write(w, negatedSessionCookie)
	negatedProfileCookie := http.Cookie{
		Name:     "profile",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	}
	a.SessionStore.Write(w, negatedProfileCookie)

	http.Redirect(w, r, logoutUrl.String(), http.StatusTemporaryRedirect)
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
