/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v12"
	oidc3 "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	configcore "github.com/gogatekeeper/gatekeeper/pkg/config/core"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/session"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// revokeProxy is responsible for stopping middleware from proxying the request
func revokeProxy(logger *zap.Logger, req *http.Request) context.Context {
	var scope *models.RequestScope
	ctxVal := req.Context().Value(constant.ContextScopeName)

	switch ctxVal {
	case nil:
		scope = &models.RequestScope{AccessDenied: true}
	default:
		var assertOk bool
		scope, assertOk = ctxVal.(*models.RequestScope)
		if !assertOk {
			logger.Error(apperrors.ErrAssertionFailed.Error())
			scope = &models.RequestScope{AccessDenied: true}
		}
	}

	scope.AccessDenied = true

	return context.WithValue(req.Context(), constant.ContextScopeName, scope)
}

// accessForbidden redirects the user to the forbidden page
func accessForbidden(
	logger *zap.Logger,
	httpStatus int,
	page string,
	tags map[string]string,
	tmpl *template.Template,
) func(wrt http.ResponseWriter, req *http.Request) context.Context {
	return func(wrt http.ResponseWriter, req *http.Request) context.Context {
		wrt.WriteHeader(httpStatus)
		// are we using a custom http template for 403?
		if page != "" {
			name := path.Base(page)

			if err := tmpl.ExecuteTemplate(wrt, name, tags); err != nil {
				logger.Error(
					"failed to render the template",
					zap.Error(err),
					zap.String("template", name),
				)
			}
		}

		return revokeProxy(logger, req)
	}
}

// renders customSignInPage
func customSignInPage(
	logger *zap.Logger,
	page string,
	tags map[string]string,
	tmpl *template.Template,
) func(wrt http.ResponseWriter, authURL string) {
	return func(wrt http.ResponseWriter, authURL string) {
		wrt.WriteHeader(http.StatusOK)
		name := path.Base(page)
		model := make(map[string]string)
		model["redirect"] = authURL
		mTags := utils.MergeMaps(model, tags)

		if err := tmpl.ExecuteTemplate(wrt, name, mTags); err != nil {
			logger.Error(
				"failed to render the template",
				zap.Error(err),
				zap.String("template", name),
			)
		}
	}
}

// redirectToURL redirects the user and aborts the context
func redirectToURL(
	logger *zap.Logger,
	url string,
	wrt http.ResponseWriter,
	req *http.Request,
	statusCode int,
) context.Context {
	wrt.Header().Add(
		"Cache-Control",
		"no-cache, no-store, must-revalidate, max-age=0",
	)

	http.Redirect(wrt, req, url, statusCode)
	return revokeProxy(logger, req)
}

// WithOAuthURI returns the oauth uri
func WithOAuthURI(baseURI string, oauthURI string) func(uri string) string {
	return func(uri string) string {
		uri = strings.TrimPrefix(uri, "/")
		if baseURI != "" {
			return fmt.Sprintf("%s/%s/%s", baseURI, oauthURI, uri)
		}
		return fmt.Sprintf("%s/%s", oauthURI, uri)
	}
}

// redirectToAuthorization redirects the user to authorization handler
//
//nolint:cyclop
func redirectToAuthorization(
	logger *zap.Logger,
	noRedirects bool,
	cookManager *cookie.Manager,
	skipTokenVerification bool,
	noProxy bool,
	baseURI string,
	oAuthURI string,
	allowedQueryParams map[string]string,
	defaultAllowedQueryParams map[string]string,
) func(wrt http.ResponseWriter, req *http.Request) context.Context {
	return func(wrt http.ResponseWriter, req *http.Request) context.Context {
		if noRedirects {
			wrt.WriteHeader(http.StatusUnauthorized)
			return revokeProxy(logger, req)
		}

		// step: add a state referrer to the authorization page
		uuid := cookManager.DropStateParameterCookie(req, wrt)
		authQuery := fmt.Sprintf("?state=%s", uuid)

		if len(allowedQueryParams) > 0 {
			query := ""
			for key, val := range allowedQueryParams {
				if param := req.URL.Query().Get(key); param != "" {
					if val != "" {
						if val != param {
							wrt.WriteHeader(http.StatusForbidden)
							return revokeProxy(logger, req)
						}
					}
					query += fmt.Sprintf("&%s=%s", key, param)
				} else {
					if val, ok := defaultAllowedQueryParams[key]; ok {
						query += fmt.Sprintf("&%s=%s", key, val)
					}
				}
			}
			authQuery += query
		}

		// step: if verification is switched off, we can't authorization
		if skipTokenVerification {
			logger.Error(
				"refusing to redirection to authorization endpoint, " +
					"skip token verification switched on",
			)

			wrt.WriteHeader(http.StatusForbidden)
			return revokeProxy(logger, req)
		}

		url := WithOAuthURI(baseURI, oAuthURI)(constant.AuthorizationURL + authQuery)

		if noProxy && !noRedirects {
			xForwardedHost := req.Header.Get("X-Forwarded-Host")
			xProto := req.Header.Get("X-Forwarded-Proto")

			if xForwardedHost == "" || xProto == "" {
				logger.Error(apperrors.ErrForwardAuthMissingHeaders.Error())

				wrt.WriteHeader(http.StatusForbidden)
				return revokeProxy(logger, req)
			}

			url = fmt.Sprintf(
				"%s://%s%s",
				xProto,
				xForwardedHost,
				url,
			)
		}

		logger.Debug("redirecting to url", zap.String("url", url))

		redirectToURL(
			logger,
			url,
			wrt,
			req,
			http.StatusSeeOther,
		)

		return revokeProxy(logger, req)
	}
}

//nolint:cyclop
func getPAT(
	logger *zap.Logger,
	pat *PAT,
	clientID string,
	clientSecret string,
	realm string,
	openIDProviderTimeout time.Duration,
	patRetryCount int,
	patRetryInterval time.Duration,
	enableForwarding bool,
	forwardingGrantType string,
	idpClient *gocloak.GoCloak,
	forwardingUsername string,
	forwardingPassword string,
	done chan bool,
) {
	retry := 0
	initialized := false
	grantType := configcore.GrantTypeClientCreds

	if enableForwarding && forwardingGrantType == configcore.GrantTypeUserCreds {
		grantType = configcore.GrantTypeUserCreds
	}

	for {
		if retry > 0 {
			logger.Info(
				"retrying fetching PAT token",
				zap.Int("retry", retry),
			)
		}

		ctx, cancel := context.WithTimeout(
			context.Background(),
			openIDProviderTimeout,
		)

		var token *gocloak.JWT
		var err error

		switch grantType {
		case configcore.GrantTypeClientCreds:
			token, err = idpClient.LoginClient(
				ctx,
				clientID,
				clientSecret,
				realm,
			)
		case configcore.GrantTypeUserCreds:
			token, err = idpClient.Login(
				ctx,
				clientID,
				clientSecret,
				realm,
				forwardingUsername,
				forwardingPassword,
			)
		default:
			logger.Error(
				"Chosen grant type is not supported",
				zap.String("grant_type", grantType),
			)
			os.Exit(11)
		}

		if err != nil {
			retry++
			logger.Error("problem getting PAT token", zap.Error(err))

			if retry >= patRetryCount {
				cancel()
				os.Exit(10)
			}

			<-time.After(patRetryInterval)
			continue
		}

		pat.m.Lock()
		pat.Token = token
		pat.m.Unlock()

		if !initialized {
			done <- true
		}

		initialized = true

		parsedToken, err := jwt.ParseSigned(token.AccessToken)
		if err != nil {
			retry++
			logger.Error("failed to parse the access token", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		stdClaims := &jwt.Claims{}
		err = parsedToken.UnsafeClaimsWithoutVerification(stdClaims)
		if err != nil {
			retry++
			logger.Error("unable to parse access token for claims", zap.Error(err))
			<-time.After(patRetryInterval)
			continue
		}

		retry = 0
		expiration := stdClaims.Expiry.Time()
		refreshIn := utils.GetWithin(expiration, 0.85)

		logger.Info(
			"waiting for expiration of access token",
			zap.Float64("refresh_in", refreshIn.Seconds()),
		)

		<-time.After(refreshIn)
	}
}

func WithUMAIdentity(
	req *http.Request,
	targetPath string,
	user *models.UserContext,
	cookieUMAName string,
	provider *oidc3.Provider,
	clientID string,
	skipClientIDCheck bool,
	skipIssuerCheck bool,
	getIdentity func(req *http.Request, tokenCookie string, tokenHeader string) (*models.UserContext, error),
	authzFunc func(targetPath string, userPerms models.Permissions) (authorization.AuthzDecision, error),
) (authorization.AuthzDecision, error) {
	umaUser, err := getIdentity(req, cookieUMAName, constant.UMAHeader)
	if err != nil {
		return authorization.DeniedAuthz, err
	}

	// make sure somebody doesn't sent one user access token
	// and others user valid uma token in one request
	if umaUser.ID != user.ID {
		return authorization.DeniedAuthz, apperrors.ErrAccessMismatchUmaToken
	}

	_, err = utils.VerifyToken(
		req.Context(),
		provider,
		umaUser.RawToken,
		clientID,
		skipClientIDCheck,
		skipIssuerCheck,
	)
	if err != nil {
		if strings.Contains(err.Error(), "token is expired") {
			return authorization.DeniedAuthz, apperrors.ErrUMATokenExpired
		}
		return authorization.DeniedAuthz, err
	}

	return authzFunc(targetPath, umaUser.Permissions)
}

// getRPT retrieves relaying party token
func getRPT(
	ctx context.Context,
	pat *PAT,
	idpClient *gocloak.GoCloak,
	realm string,
	targetPath string,
	userToken string,
	methodScope *string,
) (*gocloak.JWT, error) {
	matchingURI := true
	resourceParam := gocloak.GetResourceParams{
		URI:         &targetPath,
		MatchingURI: &matchingURI,
		Scope:       methodScope,
	}

	pat.m.RLock()
	patTok := pat.Token.AccessToken
	pat.m.RUnlock()

	resources, err := idpClient.GetResourcesClient(
		ctx,
		patTok,
		realm,
		resourceParam,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s %s",
			apperrors.ErrNoIDPResourceForPath.Error(),
			err,
		)
	}

	if len(resources) == 0 {
		return nil, apperrors.ErrNoIDPResourceForPath
	}
	if len(resources) > 1 {
		return nil, apperrors.ErrTooManyResources
	}

	resourceID := resources[0].ID
	resourceScopes := make([]string, 0)
	if len(*resources[0].ResourceScopes) == 0 {
		return nil, fmt.Errorf(
			"%w, resource: %s",
			apperrors.ErrMissingScopesForResource,
			*resourceID,
		)
	}

	if methodScope != nil {
		resourceScopes = append(resourceScopes, *methodScope)
	} else {
		for _, scope := range *resources[0].ResourceScopes {
			resourceScopes = append(resourceScopes, *scope.Name)
		}
	}

	permissions := []gocloak.CreatePermissionTicketParams{
		{
			ResourceID:     resourceID,
			ResourceScopes: &resourceScopes,
		},
	}

	permTicket, err := idpClient.CreatePermissionTicket(
		ctx,
		patTok,
		realm,
		permissions,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrPermissionTicketForResourceID.Error(),
			*resourceID,
			err,
		)
	}

	grantType := configcore.GrantTypeUmaTicket

	rptOptions := gocloak.RequestingPartyTokenOptions{
		GrantType: &grantType,
		Ticket:    permTicket.Ticket,
	}

	if userToken == "" {
		userToken = patTok
	}

	rpt, err := idpClient.GetRequestingPartyToken(ctx, userToken, realm, rptOptions)
	if err != nil {
		return nil, fmt.Errorf(
			"%s resource: %s %w",
			apperrors.ErrRetrieveRPT.Error(),
			*resourceID,
			err,
		)
	}

	return rpt, nil
}

func getCodeFlowTokens(
	scope *models.RequestScope,
	writer http.ResponseWriter,
	req *http.Request,
	enablePKCE bool,
	cookiePKCEName string,
	idpClient *gocloak.GoCloak,
	accessForbidden func(wrt http.ResponseWriter, req *http.Request) context.Context,
	accessError func(wrt http.ResponseWriter, req *http.Request) context.Context,
	newOAuth2Config func(redirectionURL string) *oauth2.Config,
	getRedirectionURL func(wrt http.ResponseWriter, req *http.Request) string,
) (string, string, string, error) {
	// step: ensure we have a authorization code
	code := req.URL.Query().Get("code")

	if code == "" {
		accessError(writer, req)
		return "", "", "", fmt.Errorf("missing auth code")
	}

	conf := newOAuth2Config(getRedirectionURL(writer, req))

	var codeVerifier *http.Cookie

	if enablePKCE {
		var err error
		codeVerifier, err = req.Cookie(cookiePKCEName)
		if err != nil {
			scope.Logger.Error("problem getting pkce cookie", zap.Error(err))
			accessForbidden(writer, req)
			return "", "", "", err
		}
	}

	resp, err := exchangeAuthenticationCode(
		req.Context(),
		conf,
		code,
		codeVerifier,
		idpClient.RestyClient().GetClient(),
	)
	if err != nil {
		scope.Logger.Error("unable to exchange code for access token", zap.Error(err))
		accessForbidden(writer, req)
		return "", "", "", err
	}

	idToken, assertOk := resp.Extra("id_token").(string)
	if !assertOk {
		scope.Logger.Error("unable to obtain id token", zap.Error(err))
		accessForbidden(writer, req)
		return "", "", "", err
	}

	return resp.AccessToken, idToken, resp.RefreshToken, nil
}

// verifyOIDCTokens
func verifyOIDCTokens(
	ctx context.Context,
	provider *oidc3.Provider,
	clientID string,
	rawAccessToken string,
	rawIDToken string,
	skipClientIDCheck bool,
	skipIssuerCheck bool,
) (*oidc3.IDToken, *oidc3.IDToken, error) {
	var oIDToken *oidc3.IDToken
	var oAccToken *oidc3.IDToken
	var err error

	oIDToken, err = utils.VerifyToken(ctx, provider, rawIDToken, clientID, false, false)
	if err != nil {
		return nil, nil, errors.Join(apperrors.ErrVerifyIDToken, err)
	}

	// check https://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken - at_hash
	// keycloak seems doesnt support yet at_hash
	// https://stackoverflow.com/questions/60818373/configure-keycloak-to-include-an-at-hash-claim-in-the-id-token
	if oIDToken.AccessTokenHash != "" {
		err = oIDToken.VerifyAccessToken(rawAccessToken)
		if err != nil {
			return nil, nil, errors.Join(apperrors.ErrAccTokenVerifyFailure, err)
		}
	}

	oAccToken, err = utils.VerifyToken(
		ctx,
		provider,
		rawAccessToken,
		clientID,
		skipClientIDCheck,
		skipIssuerCheck,
	)
	if err != nil {
		return nil, nil, errors.Join(apperrors.ErrAccTokenVerifyFailure, err)
	}

	return oAccToken, oIDToken, nil
}

func encryptToken(
	scope *models.RequestScope,
	rawToken string,
	encKey string,
	tokenType string,
	writer http.ResponseWriter,
) (string, error) {
	var err error
	var encrypted string
	if encrypted, err = encryption.EncodeText(rawToken, encKey); err != nil {
		scope.Logger.Error(
			"failed to encrypt token",
			zap.Error(err),
			zap.String("type", tokenType),
		)
		writer.WriteHeader(http.StatusInternalServerError)
		return "", err
	}
	return encrypted, nil
}

func getRequestURIFromCookie(
	scope *models.RequestScope,
	encodedRequestURI *http.Cookie,
) string {
	// some clients URL-escape padding characters
	unescapedValue, err := url.PathUnescape(encodedRequestURI.Value)
	if err != nil {
		scope.Logger.Warn(
			"app did send a corrupted redirectURI in cookie: invalid url escaping",
			zap.Error(err),
		)
	}
	// Since the value is passed with a cookie, we do not expect the client to use base64url (but the
	// base64-encoded value may itself be url-encoded).
	// This is safe for browsers using atob() but needs to be treated with care for nodeJS clients,
	// which natively use base64url encoding, and url-escape padding '=' characters.
	decoded, err := base64.StdEncoding.DecodeString(unescapedValue)
	if err != nil {
		scope.Logger.Warn(
			"app did send a corrupted redirectURI in cookie: invalid base64url encoding",
			zap.Error(err),
			zap.String("encoded_value", unescapedValue))
	}

	return string(decoded)
}

func refreshUmaToken(
	ctx context.Context,
	pat *PAT,
	idpClient *gocloak.GoCloak,
	realm string,
	targetPath string,
	user *models.UserContext,
	methodScope *string,
) (*models.UserContext, error) {
	tok, err := getRPT(
		ctx,
		pat,
		idpClient,
		realm,
		targetPath,
		user.RawToken,
		methodScope,
	)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseSigned(tok.AccessToken)
	if err != nil {
		return nil, err
	}

	umaUser, err := session.ExtractIdentity(token)
	if err != nil {
		return nil, err
	}

	umaUser.RawToken = tok.AccessToken
	return umaUser, nil
}
