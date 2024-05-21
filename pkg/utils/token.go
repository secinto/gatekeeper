package utils

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
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

	if cookie := FindCookie(name, req.Cookies()); cookie != nil {
		token.WriteString(cookie.Value)
	}

	// add also divided cookies
	for i := 1; i < 600; i++ {
		cookie := FindCookie(name+"-"+strconv.Itoa(i), req.Cookies())
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
