package state

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"tylerdmast/work/pkg/authenticator"
)

type State struct {
	LoggedIn    bool
	UserName    string
	UserAvatar  string
	IDToken     string
	AccessToken string
}

func IsLoggedIn(r *http.Request, auth authenticator.Authorization) State {
	s := State{}
	sess, err := auth.SessionStore.ReadSigned(r, "profile")
	if err != nil {
		log.Printf("User is not logged in: %s", err)
		return s
	}
	var user authenticator.User
	reader := strings.NewReader(sess)
	err = gob.NewDecoder(reader).Decode(&user)
	if err != nil {
		log.Printf("Error parsing use object: %s", err)
		return s
	}
	s.LoggedIn = true
	s.UserName = user.Name
	s.UserAvatar = user.AvatarURL

	buf, err := base64.URLEncoding.DecodeString(strings.Split(user.AccessToken, ".")[1])
	if err != nil {
		log.Printf("IsLoggedIn: Issue decoding access token %s", err)
	}
	var dst bytes.Buffer
	err = json.Indent(&dst, buf, "", "    ")
	s.AccessToken = dst.String()

	buf, err = json.MarshalIndent(user, "", "    ")
	if err != nil {
		log.Printf("IsLoggedIn: Issue marshalling id token %s", err)
	}
	s.IDToken = string(buf)
	log.Println(string(buf))
	return s
}
