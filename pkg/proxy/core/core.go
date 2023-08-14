package core

import (
	"fmt"
	"strconv"
	"time"
)

var (
	release  = ""
	gitsha   = "no gitsha provided"
	compiled = "0"
	Version  = ""
	Provider = "keycloak"
)

// GetVersion returns the proxy version
func GetVersion() string {
	if Version == "" {
		tm, err := strconv.ParseInt(compiled, 10, 64)
		if err != nil {
			return "unable to parse compiled time"
		}
		Version = fmt.Sprintf("%s (git+sha: %s, built: %s)", release, gitsha, time.Unix(tm, 0).Format("02-01-2006"))
	}

	return Version
}

type OauthProxies interface {
	CreateReverseProxy() error
	Run() error
}
