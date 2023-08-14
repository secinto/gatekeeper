package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gogatekeeper/gatekeeper/pkg/authorization"
	"gopkg.in/yaml.v2"
)

const (
	GrantTypeAuthCode     = "authorization_code"
	GrantTypeUserCreds    = "password"
	GrantTypeRefreshToken = "refresh_token"
	GrantTypeClientCreds  = "client_credentials"
	GrantTypeUmaTicket    = "urn:ietf:params:oauth:grant-type:uma-ticket"
)

type OpenIDProviderRetryCount int

type Configs interface {
	ReadConfigFile(string) error
	IsValid() error
	GetResources() []*authorization.Resource
	SetResources([]*authorization.Resource)
	GetHeaders() map[string]string
	GetMatchClaims() map[string]string
	GetTags() map[string]string
}

type CommonConfig struct{}

// readConfigFile reads and parses the configuration file
func (r *CommonConfig) ReadConfigFile(filename string) error {
	content, err := os.ReadFile(filename)

	if err != nil {
		return err
	}
	// step: attempt to un-marshal the data
	switch ext := filepath.Ext(filename); ext {
	case "json":
		err = json.Unmarshal(content, r)
	default:
		err = yaml.Unmarshal(content, r)
	}

	return err
}

func WriteFakeConfigFile(t *testing.T, content string) *os.File {
	file, err := os.CreateTemp("", "node_label_file")
	if err != nil {
		t.Fatalf("unexpected error creating node_label_file: %v", err)
	}
	file.Close()

	if err := os.WriteFile(file.Name(), []byte(content), 0600); err != nil {
		t.Fatalf("unexpected error writing node label file: %v", err)
	}

	return file
}
