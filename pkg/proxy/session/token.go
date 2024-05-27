package session

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/cookie"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"github.com/gogatekeeper/gatekeeper/pkg/storage"
	"go.uber.org/zap"
)

// GetRefreshTokenFromCookie returns the refresh token from the cookie if any
func GetRefreshTokenFromCookie(req *http.Request, cookieName string) (string, error) {
	token, err := GetTokenInCookie(req, cookieName)
	if err != nil {
		return "", err
	}

	return token, nil
}

// getTokenInRequest returns the token from the http request
//
//nolint:cyclop
func GetTokenInRequest(
	req *http.Request,
	name string,
	skipAuthorizationHeaderIdentity bool,
	tokenHeader string,
) (string, bool, error) {
	bearer := true
	token := ""
	var err error

	if tokenHeader == "" && !skipAuthorizationHeaderIdentity {
		token, err = GetTokenInBearer(req)
		if err != nil && err != apperrors.ErrSessionNotFound {
			return "", false, err
		}
	}

	if tokenHeader != "" {
		token, err = GetTokenInHeader(req, tokenHeader)
		if err != nil && err != apperrors.ErrSessionNotFound {
			return "", false, err
		}
	}

	// step: check for a token in the authorization header
	if err != nil || (err == nil && skipAuthorizationHeaderIdentity) {
		if token, err = GetTokenInCookie(req, name); err != nil {
			return token, false, err
		}
		bearer = false
	}

	return token, bearer, nil
}

// getTokenInBearer retrieves a access token from the authorization header
func GetTokenInBearer(req *http.Request) (string, error) {
	token := req.Header.Get(constant.AuthorizationHeader)
	if token == "" {
		return "", apperrors.ErrSessionNotFound
	}

	items := strings.Split(token, " ")
	if len(items) != 2 {
		return "", apperrors.ErrInvalidSession
	}

	if items[0] != constant.AuthorizationType {
		return "", apperrors.ErrSessionNotFound
	}
	return items[1], nil
}

// getTokenInHeader retrieves a token from the header
func GetTokenInHeader(req *http.Request, headerName string) (string, error) {
	token := req.Header.Get(headerName)
	if token == "" {
		return "", apperrors.ErrSessionNotFound
	}
	return token, nil
}

// getTokenInCookie retrieves the access token from the request cookies
func GetTokenInCookie(req *http.Request, name string) (string, error) {
	var token bytes.Buffer

	if cookie := cookie.FindCookie(name, req.Cookies()); cookie != nil {
		token.WriteString(cookie.Value)
	}

	// add also divided cookies
	for i := 1; i < 600; i++ {
		cookie := cookie.FindCookie(name+"-"+strconv.Itoa(i), req.Cookies())
		if cookie == nil {
			break
		}
		token.WriteString(cookie.Value)
	}

	if token.Len() == 0 {
		return "", apperrors.ErrSessionNotFound
	}

	return token.String(), nil
}

// GetIdentity retrieves the user identity from a request, either from a session cookie or a bearer token
func GetIdentity(
	logger *zap.Logger,
	skipAuthorizationHeaderIdentity bool,
	enableEncryptedToken bool,
	forceEncryptedCookie bool,
	encKey string,
) func(req *http.Request, tokenCookie string, tokenHeader string) (*models.UserContext, error) {
	return func(req *http.Request, tokenCookie string, tokenHeader string) (*models.UserContext, error) {
		var isBearer bool
		// step: check for a bearer token or cookie with jwt token
		access, isBearer, err := GetTokenInRequest(
			req,
			tokenCookie,
			skipAuthorizationHeaderIdentity,
			tokenHeader,
		)
		if err != nil {
			return nil, err
		}

		if enableEncryptedToken || forceEncryptedCookie && !isBearer {
			if access, err = encryption.DecodeText(access, encKey); err != nil {
				return nil, apperrors.ErrDecryption
			}
		}

		rawToken := access
		token, err := jwt.ParseSigned(access)
		if err != nil {
			return nil, err
		}

		user, err := ExtractIdentity(token)
		if err != nil {
			return nil, err
		}

		user.BearerToken = isBearer
		user.RawToken = rawToken

		logger.Debug("found the user identity",
			zap.String("id", user.ID),
			zap.String("name", user.Name),
			zap.String("email", user.Email),
			zap.String("roles", strings.Join(user.Roles, ",")),
			zap.String("groups", strings.Join(user.Groups, ",")))

		return user, nil
	}
}

// ExtractIdentity parse the jwt token and extracts the various elements is order to construct
func ExtractIdentity(token *jwt.JSONWebToken) (*models.UserContext, error) {
	stdClaims := &jwt.Claims{}
	customClaims := models.CustClaims{}

	err := token.UnsafeClaimsWithoutVerification(stdClaims, &customClaims)

	if err != nil {
		return nil, err
	}

	jsonMap := make(map[string]interface{})
	err = token.UnsafeClaimsWithoutVerification(&jsonMap)

	if err != nil {
		return nil, err
	}

	// @step: ensure we have and can extract the preferred name of the user, if not, we set to the ID
	preferredName := customClaims.PrefName
	if preferredName == "" {
		preferredName = customClaims.Email
	}

	audiences := stdClaims.Audience

	// @step: extract the realm roles
	roleList := make([]string, 0)
	roleList = append(roleList, customClaims.RealmAccess.Roles...)

	// @step: extract the client roles from the access token
	for name, list := range customClaims.ResourceAccess {
		scopes, assertOk := list.(map[string]interface{})

		if !assertOk {
			return nil, apperrors.ErrAssertionFailed
		}

		if roles, found := scopes[constant.ClaimResourceRoles]; found {
			rolesVal, assertOk := roles.([]interface{})

			if !assertOk {
				return nil, apperrors.ErrAssertionFailed
			}

			for _, r := range rolesVal {
				roleList = append(roleList, fmt.Sprintf("%s:%s", name, r))
			}
		}
	}

	return &models.UserContext{
		Audiences:     audiences,
		Email:         customClaims.Email,
		ExpiresAt:     stdClaims.Expiry.Time(),
		Groups:        customClaims.Groups,
		ID:            stdClaims.Subject,
		Name:          preferredName,
		PreferredName: preferredName,
		Roles:         roleList,
		Claims:        jsonMap,
		Permissions:   customClaims.Authorization,
	}, nil
}

// retrieveRefreshToken retrieves the refresh token from store or cookie
func RetrieveRefreshToken(
	store storage.Storage,
	cookieRefreshName string,
	encryptionKey string,
	req *http.Request,
	user *models.UserContext,
) (string, string, error) {
	var token string
	var err error

	switch store != nil {
	case true:
		token, err = store.GetRefreshTokenFromStore(req.Context(), user.RawToken)
	default:
		token, err = GetRefreshTokenFromCookie(req, cookieRefreshName)
	}

	if err != nil {
		return token, "", err
	}

	encrypted := token // returns encrypted, avoids encoding twice
	token, err = encryption.DecodeText(token, encryptionKey)
	return token, encrypted, err
}

// GetAccessCookieExpiration calculates the expiration of the access token cookie
func GetAccessCookieExpiration(
	logger *zap.Logger,
	accessTokenDuration time.Duration,
	refresh string,
) time.Duration {
	// notes: by default the duration of the access token will be the configuration option, if
	// however we can decode the refresh token, we will set the duration to the duration of the
	// refresh token
	duration := accessTokenDuration

	webToken, err := jwt.ParseSigned(refresh)
	if err != nil {
		logger.Error("unable to parse token")
	}

	if ident, err := ExtractIdentity(webToken); err == nil {
		delta := time.Until(ident.ExpiresAt)

		if delta > 0 {
			duration = delta
		}

		logger.Debug(
			"parsed refresh token with new duration",
			zap.Duration("new duration", delta),
		)
	} else {
		logger.Debug("refresh token is opaque and cannot be used to extend calculated duration")
	}

	return duration
}
