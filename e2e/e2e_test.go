package e2e_test

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http/httptest"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy"
	"github.com/gogatekeeper/gatekeeper/pkg/testsuite"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	testRealm        = "test"
	testClient       = "test-client"
	testClientSecret = "6447d0c0-d510-42a7-b654-6e3a16b2d7e2"
	timeout          = time.Second * 300
	idpURI           = "http://localhost:8081"
)

var idpRealmURI = fmt.Sprintf("%s/realms/%s", idpURI, testRealm)

func generateRandomPort() string {
	rand.Seed(time.Now().UnixNano())
	min := 1024
	max := 65000
	return fmt.Sprintf("%d", rand.Intn(max-min+1)+min)
}

var _ = Describe("NoRedirects Simple login/logout", func() {
	var portNum string
	var proxyAddress string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum

		os.Setenv("PROXY_DISCOVERY_URL", idpRealmURI)
		os.Setenv("PROXY_OPENID_PROVIDER_TIMEOUT", "120s")
		os.Setenv("PROXY_LISTEN", "0.0.0.0:"+portNum)
		os.Setenv("PROXY_CLIENT_ID", testClient)
		os.Setenv("PROXY_CLIENT_SECRET", testClientSecret)
		os.Setenv("PROXY_UPSTREAM_URL", server.URL)
		os.Setenv("PROXY_NO_REDIRECTS", "true")
		os.Setenv("PROXY_SKIP_ACCESS_TOKEN_CLIENT_ID_CHECK", "true")
		os.Setenv("PROXY_SKIP_ACCESS_TOKEN_ISSUER_CHECK", "true")
		os.Setenv("PROXY_OPENID_PROVIDER_RETRY_COUNT", "30")

		go func() {
			defer GinkgoRecover()
			app := proxy.NewOauthProxyApp()
			os.Args = []string{os.Args[0]}
			Expect(app.Run(os.Args)).To(Succeed())
		}()

		Eventually(func(g Gomega) error {
			conn, err := net.Dial("tcp", ":"+portNum)
			if err != nil {
				return err
			}
			conn.Close()
			return nil
		}, timeout, 15*time.Second).Should(Succeed())
	})

	It("should login with service account and logout successfully", func(ctx context.Context) {
		conf := &clientcredentials.Config{
			ClientID:     testClient,
			ClientSecret: testClientSecret,
			Scopes:       []string{"email", "openid"},
			TokenURL:     idpRealmURI + constant.IdpTokenURI,
		}

		respToken, err := conf.Token(ctx)
		Expect(err).NotTo(HaveOccurred())

		request := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy()).R().SetAuthToken(respToken.AccessToken)
		resp, err := request.Execute("GET", proxyAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(200))

		request = resty.New().R().SetAuthToken(respToken.AccessToken)
		resp, err = request.Execute("GET", proxyAddress+"/oauth/logout")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(200))
	})
})
