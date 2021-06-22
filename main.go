package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/ory/fosite"
	"github.com/parkour-vienna/distrust/auth"
	"github.com/parkour-vienna/distrust/discourse"
	"github.com/parkour-vienna/distrust/requestlog"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

type clientConfig struct {
	Secret       string
	RedirectURIs []string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "genkey" {
		genkey()
		return
	}

	viper.SetConfigName("distrust")
	viper.AddConfigPath("/etc/distrust")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println(err)
		fmt.Printf("failed to load config file.\n" +
			"A config file is required to run distrust. It should be located in `/etc/distrust` or the current working directory\n")
		os.Exit(1)
	}
	viper.SetEnvPrefix("distrust")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	lvl, err := zerolog.ParseLevel(viper.GetString("log.level"))
	if err != nil {
		log.Fatal().Str("level", viper.GetString("log.level")).Msg("invalid log level")
	}
	zerolog.SetGlobalLevel(lvl)

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	dsettings := discourse.SSOConfig{
		Server: viper.GetString("discourse.server"),
		Secret: viper.GetString("discourse.secret"),
	}

	r := chi.NewRouter()
	r.Use(requestlog.Zerologger)
	r.Get("/", func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, dsettings.Server, http.StatusTemporaryRedirect)
	})

	// oauth2 setup
	clients := map[string]clientConfig{}
	err = viper.UnmarshalKey("clients", &clients)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse clients")
	}
	log.Info().Int("numClients", len(clients)).Msg("clients loaded")
	options := []auth.OIDCOption{}
	if viper.GetString("oidc.privatekey") != "" {
		priv, err := parsePrivateKey(viper.GetString("oidc.privatekey"))
		if err != nil {
			log.Warn().Err(err).Msg("failed to load private key")
		} else {
			options = append(options, auth.WithPrivateKey(priv))
		}
	}
	if viper.GetString("oidc.secret") != "" {
		options = append(options, auth.WithSecret([]byte(viper.GetString("oidc.secret"))))
	}
	oidc := auth.NewOIDC("/oauth2", dsettings, toFositeClients(clients), options...)
	r.Route("/oauth2", oidc.RegisterHandlers)

	log.Info().Str("url", "http://"+viper.GetString("listenAddr")).Msg("Starting server")
	log.Fatal().Err(http.ListenAndServe(viper.GetString("listenAddr"), r))
}

func toFositeClients(clients map[string]clientConfig) map[string]fosite.Client {
	r := make(map[string]fosite.Client)
	for k, v := range clients {

		hs := []byte(v.Secret)

		_, err := bcrypt.Cost(hs)
		if err != nil {
			hs, _ = bcrypt.GenerateFromPassword(hs, bcrypt.DefaultCost)
		}

		r[k] = &fosite.DefaultClient{
			Secret:        hs,
			RedirectURIs:  v.RedirectURIs,
			ResponseTypes: []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
			GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
			Scopes:        []string{"openid", "profile", "email"},
		}
	}
	return r
}

func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("no pem block found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parsing private key")
	}
	return key, nil
}
