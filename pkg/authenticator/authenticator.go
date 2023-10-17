package authenticator

import (
	"context"
	"errors"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Authorization struct {
	OidcProvider *oidc.Provider
	OauthConfig  oauth2.Config
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
