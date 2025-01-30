package core

import (
	"context"
	"encoding/base64"
	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"net/http"
	"strings"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/encryption"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy/models"
	"go.uber.org/zap"
)

// RedirectToURL redirects the user and aborts the context.
func RedirectToURL(
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
	return RevokeProxy(logger, req)
}

func EncryptToken(
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

// RevokeProxy is responsible for stopping middleware from proxying the request.
func RevokeProxy(logger *zap.Logger, req *http.Request) context.Context {
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

func CheckGITAccess(resource *authorization.Resource, req *http.Request, logger *zap.Logger) bool {
	if resource != nil {
		if resource.IsGitPath && strings.Contains(strings.ToLower(req.UserAgent()), "git/") {
			authHeader := req.Header.Get(constant.AuthorizationHeader)
			logger.Debug("Checking basic auth in IdentityHeadersMiddleware")

			if strings.Contains(authHeader, "Basic") {
				parts := strings.Split(authHeader, " ")
				logger.Debug("Auth header", zap.String("oart 1", parts[0]), zap.String("oart 2", parts[1]))

				if len(parts) == 2 {
					data, err := base64.StdEncoding.DecodeString(parts[1])
					logger.Debug("Auth header decoded", zap.String("decoded", string(data)))
					if err == nil {
						basicAuth := strings.Split(string(data), ":")
						logger.Debug("Auth header user", zap.String("user", basicAuth[0]))
						if basicAuth[0] == resource.GitUserToExpect {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
