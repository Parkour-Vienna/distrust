package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/parkour-vienna/distrust/cryptutils"
	"github.com/parkour-vienna/distrust/discourse"
	"github.com/rs/zerolog/log"
)

type OIDCProvider struct {
	oauth2          fosite.OAuth2Provider
	inflight        map[uuid.UUID]*InFlightRequest
	root            string
	discourseServer string
	discourseSecret string
	privateKey      *rsa.PrivateKey
}

type DistrustClient struct {
	fosite.DefaultClient
	AllowGroups []string
	DenyGroups  []string
}

type InFlightRequest struct {
	Nonce int
	Ar    fosite.AuthorizeRequester
}

type oidcOptions struct {
	privateKey *rsa.PrivateKey
	secret     []byte
}

type funcOIDCOption struct {
	f func(*oidcOptions)
}

func (fo *funcOIDCOption) apply(oo *oidcOptions) {
	fo.f(oo)
}

type OIDCOption interface {
	apply(do *oidcOptions)
}

func NewOIDC(path string, disc discourse.SSOConfig, clients map[string]fosite.Client, opts ...OIDCOption) *OIDCProvider {
	s := storage.NewMemoryStore()
	s.Clients = clients
	config := &compose.Config{
		AccessTokenLifespan: time.Minute * 30,
	}
	oopts := oidcOptions{}
	for _, opt := range opts {
		opt.apply(&oopts)
	}

	if oopts.secret == nil {
		log.Warn().Msg("no secret specified in oidc provider. When running multiple instances, make sure this secret is the same on all instances")
		var secret = make([]byte, 32)
		_, _ = rand.Read(secret)
		oopts.secret = secret
	}
	if oopts.privateKey == nil {
		log.Warn().Msg("no private key specified in oidc provider. Your tokens will be invalid on restart")
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		oopts.privateKey = priv
	}
	return &OIDCProvider{
		oauth2:          compose.ComposeAllEnabled(config, s, oopts.secret, oopts.privateKey),
		inflight:        map[uuid.UUID]*InFlightRequest{},
		root:            path,
		privateKey:      oopts.privateKey,
		discourseServer: disc.Server,
		discourseSecret: disc.Secret,
	}
}

func WithPrivateKey(p *rsa.PrivateKey) OIDCOption {
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.privateKey = p
		},
	}
}

func WithSecret(s []byte) OIDCOption {
	if len(s) != 32 {
		log.Err(errors.New("invalid secret length")).Str("secret", string(s)).Msg("secrets must be exactly 32 bytes long. OIDC might not work")
	}
	return &funcOIDCOption{
		func(o *oidcOptions) {
			o.secret = s
		},
	}
}

func (o *OIDCProvider) RegisterHandlers(r chi.Router) {
	// Set up oauth2 endpoints. You could also use gorilla/mux or any other router.
	r.HandleFunc("/auth", o.authEndpoint)
	r.HandleFunc("/callback", o.callbackEndpoint)
	r.HandleFunc("/token", o.tokenEndpoint)
	r.HandleFunc("/introspect", o.introspectionEndpoint)
	r.HandleFunc("/userinfo", o.userInfoEndpoint)

	// revoke tokens
	r.HandleFunc("/revoke", o.revokeEndpoint)

	r.Get("/.well-known/openid-configuration", o.informationEndpoint)
	r.HandleFunc("/certs", o.certsEndpoint)
}

func (o *OIDCProvider) newSession(aroot string, values url.Values) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      aroot,
			Subject:     values.Get("username"),
			Audience:    []string{},
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
			Extra: map[string]interface{}{
				"email":          values.Get("email"),
				"email_verified": true,
				"picture":        values.Get("avatar_url"),
				"name":           values.Get("name"),
				"groups":         strings.Split(values.Get("groups"), ","),
				"external_id":    values.Get("external_id"),
			},
		},
		Headers: &jwt.Headers{
			Extra: map[string]interface{}{
				"kid": cryptutils.KeyID(o.privateKey.PublicKey),
			},
		},
	}
}
