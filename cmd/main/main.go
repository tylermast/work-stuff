package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"tylerdmast/work/pkg/authenticator"
	"tylerdmast/work/pkg/cookies"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

// Exmple of how to handle cookies
// https://www.alexedwards.net/blog/working-with-cookies-in-go

var secretKey []byte

func setCookieHandler(c echo.Context) error {
	cookie := http.Cookie{
		Name:     "auth-session",
		Value:    "PLACEHOLDERVALUE",
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	err := cookies.WriteSigned(c, cookie, secretKey)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error setting cookie")
	}

	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(time.Minute) * 10,
		HttpOnly: true,
	}
	sess.Values["auth-session-mw"] = ("MIDDLEWARE IS GREAT")
	sess.Save(c.Request(), c.Response())
	log.Println(sess.Values["auth-session-mw"])
	return c.String(http.StatusOK, "Cookie set successfully")
}

func getCookieHandler(c echo.Context) error {
	value, err := cookies.ReadSigned(c, "auth-session", secretKey)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error reading cookie")
	}
	sess, _ := session.Get("session", c)
	return c.String(http.StatusOK, fmt.Sprintf("Cookie value: %s | Middleware cookie: %s", value, sess.Values["auth-session-mw"]))
}

type Film struct {
	Title    string
	Director string
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {
	h1 := func(c echo.Context) error {
		films := map[string][]Film{
			"Films": {
				{Title: "The Godfather", Director: "Francis Ford Coppola"},
				{Title: "Blade Runner", Director: "Ridley Scott"},
				{Title: "The Thing", Director: "John Carpenter"},
			},
		}
		log.Println(films)
		return c.Render(http.StatusOK, "index", films)
	}

	secretKeyFlag := flag.String("key", "", "64 char random hex string for generating secret key")
	flag.Parse()

	if err := godotenv.Load("configs/.env"); err != nil {
		log.Fatal("Could not load .env file")
	}

	if len(*secretKeyFlag) != 64 {
		log.Fatal("secret key not 64 chars - key: ", *secretKeyFlag)
	}

	var err error
	secretKey, err = hex.DecodeString(*secretKeyFlag)
	if err != nil {
		log.Fatal("Could not decode secret key")
	}

	auth := authenticator.Authorization{}
	err = auth.New()
	if err != nil {
		log.Fatal("Unable to initate authorization client, error: ", err)
	}

	gob.Register(map[string]interface{}{})

	t := &Template{
		templates: template.Must(template.ParseGlob("web/template/*.html")),
	}
	server := echo.New()
	server.Use(session.Middleware(sessions.NewCookieStore(secretKey)))
	server.Renderer = t
	server.GET("/", h1)
	server.GET("/login", func(c echo.Context) error {
		return loginHandler(c, &auth)
	})
	server.GET("/callback", func(c echo.Context) error {
		return callbackHandler(c, &auth)
	})
	server.GET("/tokens", getTokens)
	server.GET("/cookie/set", setCookieHandler)
	server.GET("/cookie/get", getCookieHandler)
	server.Logger.Fatal(server.Start(":8080"))
}

func loginHandler(
	c echo.Context,
	auth *authenticator.Authorization,
) error {
	state, err := generateRandomState()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error authenticating")
	}
	sess, _ := session.Get("session", c)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(time.Minute) * 10,
		HttpOnly: true,
	}
	sess.Values["state"] = (state)
	log.Println("Setting state...", state)
	sess.Save(c.Request(), c.Response())
	log.Println(sess.Name(), len(sess.Values))
	audienceURI := oauth2.SetAuthURLParam("audience", "https://work-stuff/")
	log.Println("/login : sending user to", auth.OauthConfig.AuthCodeURL(state, audienceURI))
	return c.Redirect(http.StatusTemporaryRedirect, auth.OauthConfig.AuthCodeURL(state, audienceURI))
}

func callbackHandler(
	c echo.Context,
	auth *authenticator.Authorization,
) error {
	sess, err := session.Get("session", c)
	if err != nil {
		// return c.String(http.StatusInternalServerError, fmt.Sprintf("Retrieving session failed %s", err))
	}

	state := sess.Values["state"]
	if c.QueryParam("state") != state {
		return c.String(http.StatusBadRequest, fmt.Sprintf("Invalid state got %s expected %s", c.QueryParam("state"), state))
	}
	log.Println("Retrieved state...", state)

	log.Println("Request Context", c.Request().Context())
	token, err := auth.OauthConfig.Exchange(c.Request().Context(), c.QueryParam("code"))
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Error getting auth code %s", err))
	}
	idToken, err := auth.VerifyIDToken(c.Request().Context(), token)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Error validating ID token %s", err))
	}
	log.Println(idToken)
	var profile map[string]interface{}
	if err := idToken.Claims(&profile); err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	sess.Values["profile"] = profile
	sess.Values["access_token"] = token.AccessToken
	err = sess.Save(c.Request(), c.Response())
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("Unable to save session %s", err))
	}
	log.Println("/callback\t", sess.Name(), len(sess.Values), sess.Options)
	return c.Redirect(http.StatusTemporaryRedirect, "/tokens")
	// return c.String(http.StatusOK, fmt.Sprintf("Logged In? %s %s", sess.Values["id_token"], sess.Values["access_token"]))
}

type tokens struct {
	IDToken     map[string]interface{}
	AccessToken string
}

func getTokens(c echo.Context) error {
	sess, err := session.Get("session", c)
	if err != nil {
		return c.String(http.StatusInternalServerError, "No session found")
	}
	log.Println("/tokens\t", sess.Name(), len(sess.Values), sess.Options)

	if sess.Values["profile"] == nil {
		return c.String(http.StatusInternalServerError, "No profile found")
	}
	if sess.Values["access_token"] == nil {
		return c.String(http.StatusInternalServerError, "No access token found")
	}
	// token, err := base64.RawURLEncoding.DecodeString(sess.Values["access_token"].(string))
	encodedToken := sess.Values["access_token"].(string)
	result, err := EnsureValidToken(c.Request().Context(), encodedToken)
	if err != nil {
		log.Println(err)
	}
	log.Println("Original token: ", encodedToken, "result: ", result)
	rawJson, err := json.Marshal(result)
	if err != nil {
		log.Println(err)
	}
	log.Printf("JSON Marshalled Version: %s", rawJson)

	// alternative just raw decode the token
	tokenSegments := strings.Split(encodedToken, ".")
	rawPayload, err := base64.URLEncoding.DecodeString(tokenSegments[1])
	if err != nil {
		log.Println(err)
	}
	log.Println(fmt.Sprintf("%s", rawPayload))
	payloadJson, _ := json.Marshal(fmt.Sprintf("%s", rawPayload))

	tokens := tokens{
		IDToken:     sess.Values["profile"].(map[string]interface{}),
		AccessToken: fmt.Sprintf("%s", payloadJson),
	}
	return c.Render(http.StatusOK, "tokens", tokens)
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	state := base64.StdEncoding.EncodeToString(b)
	return state, nil
}

type CustomClaims struct {
	Scope string `json:"scope"`
	Foo   string `json:"https://work-stuff/foo"`
}

func (c CustomClaims) Validate(ctx context.Context) error { return nil }

func EnsureValidToken(ctx context.Context, tokenString string) (interface{}, error) {
	issuerURL, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/")
	if err != nil {
		log.Fatalf("EnsureValidToken : Failed to parse the issuer url: %v", err)
	}
	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)
	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{("https://work-stuff/")},
		validator.WithCustomClaims(
			func() validator.CustomClaims {
				return &CustomClaims{}
			},
		),
		validator.WithAllowedClockSkew(time.Minute),
	)
	if err != nil {
		log.Fatalf("Failed to set up the jwt validator")
	}

	return jwtValidator.ValidateToken(ctx, tokenString)
}
