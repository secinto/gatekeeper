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
	"net/http"
	"time"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/metrics"
	"github.com/grokify/go-pkce"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// newOAuth2Config returns a oauth2 config
func newOAuth2Config(
	clientID string,
	clientSecret string,
	authURL string,
	tokenURL string,
	scopes []string,
) func(redirectionURL string) *oauth2.Config {
	return func(redirectionURL string) *oauth2.Config {
		defaultScope := []string{"openid"}

		conf := &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
			RedirectURL: redirectionURL,
			Scopes:      append(scopes, defaultScope...),
		}

		return conf
	}
}

// exchangeAuthenticationCode exchanges the authentication code with the oauth server for a access token
func exchangeAuthenticationCode(
	ctx context.Context,
	oConfig *oauth2.Config,
	code string,
	codeVerifierCookie *http.Cookie,
	httpClient *http.Client,
) (*oauth2.Token, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	start := time.Now()
	authCodeOptions := []oauth2.AuthCodeOption{}

	if codeVerifierCookie != nil {
		if codeVerifierCookie.Value == "" {
			return nil, apperrors.ErrPKCECookieEmpty
		}
		authCodeOptions = append(
			authCodeOptions,
			oauth2.SetAuthURLParam(pkce.ParamCodeVerifier, codeVerifierCookie.Value),
		)
	}

	token, err := oConfig.Exchange(ctx, code, authCodeOptions...)
	if err != nil {
		return token, err
	}

	taken := time.Since(start).Seconds()
	metrics.OauthTokensMetric.WithLabelValues("exchange").Inc()
	metrics.OauthLatencyMetric.WithLabelValues("exchange").Observe(taken)

	return token, err
}
