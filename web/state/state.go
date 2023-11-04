package state

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"net/http"
	"strings"

	"tylerdmast/work/pkg/authenticator"

	"github.com/charmbracelet/log"
)

type State struct {
	LoggedIn    bool
	UserName    string
	UserAvatar  string
	IDToken     string
	AccessToken string
}

func IsLoggedIn(r *http.Request, auth authenticator.Authorization, log log.Logger) State {
	s := State{}
	sess, err := auth.SessionStore.ReadSigned(r, "profile")
	if err != nil {
		log.Debugf("User is not logged in: %s", err)
		return s
	}
	var user authenticator.User
	reader := strings.NewReader(sess)
	err = gob.NewDecoder(reader).Decode(&user)
	if err != nil {
		log.Debugf("Error parsing use object: %s", err)
		return s
	}
	s.LoggedIn = true
	s.UserName = user.Name
	s.UserAvatar = user.AvatarURL

	buf, err := base64.URLEncoding.DecodeString(strings.Split(user.AccessToken, ".")[1])
	if err != nil {
		log.Debugf("IsLoggedIn: Issue decoding access token %s", err)
	}
	var dst bytes.Buffer
	err = json.Indent(&dst, buf, "", "    ")
	s.AccessToken = dst.String()

	buf, err = json.MarshalIndent(user, "", "    ")
	if err != nil {
		log.Debugf("IsLoggedIn: Issue marshalling id token %s", err)
	}
	s.IDToken = string(buf)
	log.Debug(string(buf))
	return s
}
