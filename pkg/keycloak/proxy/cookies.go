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
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
)

// DropCookie drops a cookie into the response
func (r *OauthProxy) DropCookie(wrt http.ResponseWriter, host, name, value string, duration time.Duration) {
	// step: default to the host header, else the config domain
	domain := ""

	if r.Config.CookieDomain != "" {
		domain = r.Config.CookieDomain
	}

	path := r.Config.BaseURI

	if path == "" {
		path = "/"
	}

	cookie := &http.Cookie{
		Domain:   domain,
		HttpOnly: r.Config.HTTPOnlyCookie,
		Name:     name,
		Path:     path,
		Secure:   r.Config.SecureCookie,
		Value:    value,
	}

	if !r.Config.EnableSessionCookies && duration != 0 {
		cookie.Expires = time.Now().Add(duration)
	}

	switch r.Config.SameSiteCookie {
	case constant.SameSiteStrict:
		cookie.SameSite = http.SameSiteStrictMode
	case constant.SameSiteLax:
		cookie.SameSite = http.SameSiteLaxMode
	}

	http.SetCookie(wrt, cookie)
}

// maxCookieChunkSize calculates max cookie chunk size, which can be used for cookie value
func (r *OauthProxy) GetMaxCookieChunkLength(req *http.Request, cookieName string) int {
	maxCookieChunkLength := 4069 - len(cookieName)

	if r.Config.CookieDomain != "" {
		maxCookieChunkLength -= len(r.Config.CookieDomain)
	} else {
		maxCookieChunkLength -= len(strings.Split(req.Host, ":")[0])
	}

	if r.Config.HTTPOnlyCookie {
		maxCookieChunkLength -= len("HttpOnly; ")
	}

	if !r.Config.EnableSessionCookies {
		maxCookieChunkLength -= len("Expires=Mon, 02 Jan 2006 03:04:05 MST; ")
	}

	switch r.Config.SameSiteCookie {
	case constant.SameSiteStrict:
		maxCookieChunkLength -= len("SameSite=Strict ")
	case constant.SameSiteLax:
		maxCookieChunkLength -= len("SameSite=Lax ")
	}

	if r.Config.SecureCookie {
		maxCookieChunkLength -= len("Secure")
	}

	return maxCookieChunkLength
}

// dropCookieWithChunks drops a cookie from the response, taking into account possible chunks
func (r *OauthProxy) dropCookieWithChunks(req *http.Request, wrt http.ResponseWriter, name, value string, duration time.Duration) {
	maxCookieChunkLength := r.GetMaxCookieChunkLength(req, name)

	if len(value) <= maxCookieChunkLength {
		r.DropCookie(wrt, req.Host, name, value, duration)
	} else {
		// write divided cookies because payload is too long for single cookie
		r.DropCookie(wrt, req.Host, name, value[0:maxCookieChunkLength], duration)

		for idx := maxCookieChunkLength; idx < len(value); idx += maxCookieChunkLength {
			end := idx + maxCookieChunkLength

			if end > len(value) {
				end = len(value)
			}

			r.DropCookie(
				wrt,
				req.Host,
				name+"-"+strconv.Itoa(idx/maxCookieChunkLength),
				value[idx:end],
				duration,
			)
		}
	}
}

// dropAccessTokenCookie drops a access token cookie from the response
func (r *OauthProxy) dropAccessTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	r.dropCookieWithChunks(req, w, r.Config.CookieAccessName, value, duration)
}

// DropRefreshTokenCookie drops a refresh token cookie from the response
func (r *OauthProxy) DropRefreshTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	r.dropCookieWithChunks(req, w, r.Config.CookieRefreshName, value, duration)
}

// dropIdTokenCookie drops a id token cookie from the response
func (r *OauthProxy) dropIDTokenCookie(req *http.Request, w http.ResponseWriter, value string, duration time.Duration) {
	r.dropCookieWithChunks(req, w, r.Config.CookieIDTokenName, value, duration)
}

// writeStateParameterCookie sets a state parameter cookie into the response
func (r *OauthProxy) writeStateParameterCookie(req *http.Request, wrt http.ResponseWriter) string {
	uuid, err := uuid.NewV4()

	if err != nil {
		wrt.WriteHeader(http.StatusInternalServerError)
	}

	requestURI := req.URL.RequestURI()

	if r.Config.NoProxy && !r.Config.NoRedirects {
		xReqURI := req.Header.Get("X-Forwarded-Uri")
		requestURI = xReqURI
	}

	encRequestURI := base64.StdEncoding.EncodeToString([]byte(requestURI))

	r.DropCookie(wrt, req.Host, r.Config.CookieRequestURIName, encRequestURI, 0)
	r.DropCookie(wrt, req.Host, r.Config.CookieOAuthStateName, uuid.String(), 0)

	return uuid.String()
}

// writePKCECookie sets a code verifier cookie into the response
func (r *OauthProxy) writePKCECookie(req *http.Request, wrt http.ResponseWriter, codeVerifier string) {
	r.DropCookie(wrt, req.Host, r.Config.CookiePKCEName, codeVerifier, 0)
}

// ClearAllCookies is just a helper function for the below
func (r *OauthProxy) ClearAllCookies(req *http.Request, w http.ResponseWriter) {
	r.ClearAccessTokenCookie(req, w)
	r.ClearRefreshTokenCookie(req, w)
	r.ClearIDTokenCookie(req, w)
}

// clearRefreshSessionCookie clears the session cookie
func (r *OauthProxy) ClearRefreshTokenCookie(req *http.Request, wrt http.ResponseWriter) {
	r.DropCookie(wrt, req.Host, r.Config.CookieRefreshName, "", -10*time.Hour)

	// clear divided cookies
	for idx := 1; idx < 600; idx++ {
		var _, err = req.Cookie(r.Config.CookieRefreshName + "-" + strconv.Itoa(idx))

		if err == nil {
			r.DropCookie(
				wrt,
				req.Host,
				r.Config.CookieRefreshName+"-"+strconv.Itoa(idx),
				"",
				-10*time.Hour,
			)
		} else {
			break
		}
	}
}

// ClearAccessTokenCookie clears the session cookie
func (r *OauthProxy) ClearAccessTokenCookie(req *http.Request, wrt http.ResponseWriter) {
	r.DropCookie(wrt, req.Host, r.Config.CookieAccessName, "", -10*time.Hour)

	// clear divided cookies
	for idx := 1; idx < len(req.Cookies()); idx++ {
		var _, err = req.Cookie(r.Config.CookieAccessName + "-" + strconv.Itoa(idx))

		if err == nil {
			r.DropCookie(
				wrt,
				req.Host,
				r.Config.CookieAccessName+"-"+strconv.Itoa(idx),
				"",
				-10*time.Hour,
			)
		} else {
			break
		}
	}
}

// ClearIDTokenCookie clears the session cookie
func (r *OauthProxy) ClearIDTokenCookie(req *http.Request, wrt http.ResponseWriter) {
	r.DropCookie(wrt, req.Host, r.Config.CookieIDTokenName, "", -10*time.Hour)

	// clear divided cookies
	for idx := 1; idx < len(req.Cookies()); idx++ {
		var _, err = req.Cookie(r.Config.CookieIDTokenName + "-" + strconv.Itoa(idx))

		if err == nil {
			r.DropCookie(
				wrt,
				req.Host,
				r.Config.CookieIDTokenName+"-"+strconv.Itoa(idx),
				"",
				-10*time.Hour,
			)
		} else {
			break
		}
	}
}
