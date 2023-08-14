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
	"strings"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/utils"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2/jwt"
)

// GetIdentity retrieves the user identity from a request, either from a session cookie or a bearer token
func (r *OauthProxy) GetIdentity(req *http.Request) (*UserContext, error) {
	var isBearer bool
	// step: check for a bearer token or cookie with jwt token
	access, isBearer, err := utils.GetTokenInRequest(
		req,
		r.Config.CookieAccessName,
		r.Config.SkipAuthorizationHeaderIdentity,
	)

	if err != nil {
		return nil, err
	}

	if r.Config.EnableEncryptedToken || r.Config.ForceEncryptedCookie && !isBearer {
		if access, err = encryption.DecodeText(access, r.Config.EncryptionKey); err != nil {
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

	r.Log.Debug("found the user identity",
		zap.String("id", user.ID),
		zap.String("name", user.Name),
		zap.String("email", user.Email),
		zap.String("roles", strings.Join(user.Roles, ",")),
		zap.String("groups", strings.Join(user.Groups, ",")))

	return user, nil
}
