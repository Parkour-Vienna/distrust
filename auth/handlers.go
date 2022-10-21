package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/parkour-vienna/distrust/cryptutils"
	"github.com/parkour-vienna/distrust/discourse"
	"github.com/rs/zerolog/log"
	jose "gopkg.in/square/go-jose.v2"
)

func (o *OIDCProvider) authEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := o.oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Warn().Err(err).Msg("parsing authorize request")
		o.oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	aroot := o.getAuthRoot(req)
	callback := aroot + "/callback"
	nonce := rand.Int()
	url := discourse.GenerateURL(o.discourseServer, callback, o.discourseSecret, nonce)

	sessionId := uuid.New()

	log.Debug().Str("sessionId", sessionId.String()).Msg("registering in flight request")
	o.inflight[sessionId] = &InFlightRequest{
		Nonce: nonce,
		Ar:    ar,
	}
	expiration := time.Now().Add(time.Minute * 10)
	http.SetCookie(rw, &http.Cookie{
		Name:    "oidc_session",
		Value:   sessionId.String(),
		Expires: time.Now().Add(time.Minute * 10),
	})
	go func() {
		time.Sleep(time.Until(expiration))
		log.Debug().Str("sessionId", sessionId.String()).Msg("deleting expired session id")
		delete(o.inflight, sessionId)
	}()
	http.Redirect(rw, req, url, http.StatusTemporaryRedirect)
}

func (o *OIDCProvider) callbackEndpoint(rw http.ResponseWriter, req *http.Request) {
	log.Trace().Msg("got a discourse callback")
	cookie, err := req.Cookie("oidc_session")
	if err != nil {
		log.Warn().Err(err).Msg("fetching cookie")
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid session, please try again"})
		return
	}

	session, ok := o.inflight[uuid.MustParse(cookie.Value)]
	if !ok {
		_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid session, please try again"})
		return
	}
	delete(o.inflight, uuid.MustParse(cookie.Value))

	values, err := discourse.ValidateResponse(req.URL.Query().Get("sso"), req.URL.Query().Get("sig"), o.discourseSecret, session.Nonce)
	if err != nil {
		o.oauth2.WriteAuthorizeError(rw, session.Ar, err)
		return
	}

	nonce, _ := strconv.Atoi(values.Get("nonce"))

	log.Debug().
		Str("username", values.Get("username")).
		Str("groups", values.Get("groups")).
		Int("nonce", nonce).
		Msg("parsed user data")

	switch client := session.Ar.GetClient().(type) {
	case *DistrustClient:
		log.Debug().Str("client", client.GetID()).Msg("distrust client found, performing additonal validation")
		err := validateGroups(client, values)
		if err != nil {
			log.Warn().Err(err).Msg("group validation failed")
			fmt.Fprintf(rw, "You are not allowed to access this application: %s", err.Error())
			return
		}
	}

	// since scopes do not work with discourse, we simply grant the openid scope
	session.Ar.GrantScope("openid")

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.

	aroot := o.getAuthRoot(req)
	mySessionData := o.newSession(aroot, values)
	response, err := o.oauth2.NewAuthorizeResponse(req.Context(), session.Ar, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Warn().Err(err).Msg("building authorize response")
		o.oauth2.WriteAuthorizeError(rw, session.Ar, err)
		return
	}

	// Last but not least, send the response!
	o.oauth2.WriteAuthorizeResponse(rw, session.Ar, response)
}

func (o *OIDCProvider) introspectionEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	aroot := o.getAuthRoot(req)
	mySessionData := o.newSession(aroot, nil)
	ir, err := o.oauth2.NewIntrospectionRequest(ctx, req, mySessionData)
	if err != nil {
		log.Warn().Err(err)
		o.oauth2.WriteIntrospectionError(rw, err)
		return
	}

	o.oauth2.WriteIntrospectionResponse(rw, ir)
}

func (o *OIDCProvider) revokeEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()

	// This will accept the token revocation request and validate various parameters.
	err := o.oauth2.NewRevocationRequest(ctx, req)

	// All done, send the response.
	o.oauth2.WriteRevocationResponse(rw, err)
}

func (o *OIDCProvider) tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := req.Context()

	// Create an empty session object which will be passed to the request handlers
	aroot := o.getAuthRoot(req)
	mySessionData := o.newSession(aroot, nil)

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	accessRequest, err := o.oauth2.NewAccessRequest(ctx, req, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Warn().Err(err).Msg("parsing access request")
		o.oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	// If this is a client_credentials grant, grant all requested scopes
	// NewAccessRequest validated that all requested scopes the client is allowed to perform
	// based on configured scope matching strategy.
	if accessRequest.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range accessRequest.GetRequestedScopes() {
			accessRequest.GrantScope(scope)
		}
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := o.oauth2.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		log.Warn().Err(err).Msg("building access response")
		o.oauth2.WriteAccessError(rw, accessRequest, err)
		return
	}

	log.Info().Str("username", accessRequest.GetSession().(*openid.DefaultSession).Claims.Subject).Msg("user successfully authenticated")

	// All done, send the response.
	o.oauth2.WriteAccessResponse(rw, accessRequest, response)

	// The client now has a valid access token
}

func (o *OIDCProvider) informationEndpoint(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Add("Content-Type", "application/json")

	aroot := o.getAuthRoot(req)

	_ = json.NewEncoder(rw).Encode(map[string]interface{}{
		"issuer":                 aroot,
		"authorization_endpoint": aroot + "/auth",
		"token_endpoint":         aroot + "/token",
		"userinfo_endpoint":      aroot + "/userinfo",
		"jwks_uri":               aroot + "/certs",
		"response_types_supported": []string{
			"code",
			"none",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"code id_token token",
		},
		"subject_types_supported":               []string{"public", "pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (o *OIDCProvider) certsEndpoint(rw http.ResponseWriter, req *http.Request) {
	jwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Algorithm: "RS256",
				KeyID: cryptutils.KeyID(o.privateKey.PublicKey),
				Use:   "sig",
				Key:   &o.privateKey.PublicKey,
			},
		},
	}
	rw.Header().Add("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(jwks)
}

func (o *OIDCProvider) userInfoEndpoint(rw http.ResponseWriter, req *http.Request) {
	aroot := o.getAuthRoot(req)
	session := o.newSession(aroot, nil)
	tokenType, ar, err := o.oauth2.IntrospectToken(req.Context(), fosite.AccessTokenFromRequest(req), fosite.AccessToken, session)
	if err != nil {
		rfcerr := fosite.ErrorToRFC6749Error(err)
		if rfcerr.StatusCode() == http.StatusUnauthorized {
			rw.Header().Set("WWW-Authenticate", fmt.Sprintf("error=%s,error_description=%s", rfcerr.ErrorField, rfcerr.GetDescription()))
		}
		_, _ = rw.Write([]byte(err.Error()))
		return
	}

	if tokenType != fosite.AccessToken {
		err := errors.New("Only Access tokens can be used to fetch user information")
		rw.Header().Set("WWW-Authenticate", fmt.Sprintf("error_description=%s", err.Error()))
		_, _ = rw.Write([]byte(err.Error()))
		return
	}

	info := ar.GetSession().(*openid.DefaultSession).Claims.ToMap()
	delete(info, "rat")
	delete(info, "exp")
	delete(info, "at_hash")
	_ = json.NewEncoder(rw).Encode(info)
}

func (o *OIDCProvider) getAuthRoot(req *http.Request) string {

	scheme := req.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		scheme = "http"
	}

	aroot := scheme + "://" + req.Host + o.root
	return aroot
}

func validateGroups(client *DistrustClient, values url.Values) error {
	userGroups := values.Get("groups")
	groupMap := make(map[string]bool)
	for _, g := range strings.Split(userGroups, ",") {
		groupMap[g] = true
	}
	for _, allowed := range client.AllowGroups {
		if groupMap[allowed] {
			return nil
		}
	}
	if len(client.AllowGroups) != 0 {
		return errors.New("user is not in allowed groups for this client")
	}
	for _, denied := range client.DenyGroups {
		if groupMap[denied] {
			return errors.New("access is denied for user in group " + denied)
		}
	}
	return nil
}
