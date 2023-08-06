package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/PuerkitoBio/goquery"
	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy"
	"github.com/gogatekeeper/gatekeeper/pkg/testsuite"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	testRealm            = "test"
	testClient           = "test-client"
	testClientSecret     = "6447d0c0-d510-42a7-b654-6e3a16b2d7e2"
	pkceTestClient       = "test-client-pkce"
	pkceTestClientSecret = "F2GqU40xwX0P2LrTvHUHqwNoSk4U4n5R"
	timeout              = time.Second * 300
	idpURI               = "http://localhost:8081"
	testUser             = "myuser"
	testPass             = "baba1234"
)

var idpRealmURI = fmt.Sprintf("%s/realms/%s", idpURI, testRealm)

func generateRandomPort() string {
	rand.Seed(time.Now().UnixNano())
	min := 1024
	max := 65000
	return fmt.Sprintf("%d", rand.Intn(max-min+1)+min)
}

func startAndWait(portNum string, osArgs []string) {
	go func() {
		defer GinkgoRecover()
		app := proxy.NewOauthProxyApp()
		Expect(app.Run(osArgs)).To(Succeed())
	}()

	Eventually(func(g Gomega) error {
		conn, err := net.Dial("tcp", ":"+portNum)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}, timeout, 15*time.Second).Should(Succeed())
}

var _ = Describe("NoRedirects Simple login/logout", func() {
	var portNum string
	var proxyAddress string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=true",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
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
		resp, err := request.Get(proxyAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))

		request = resty.New().R().SetAuthToken(respToken.AccessToken)
		resp, err = request.Get(proxyAddress + "/oauth/logout")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))
	})
})

var _ = Describe("Code Flow Simple login/logout", func() {
	var portNum string
	var proxyAddress string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum

		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + testClient,
			"--client-secret=" + testClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	It("should login with user/password and logout successfully", func(ctx context.Context) {
		rClient := resty.New().SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))
		resp, err := rClient.R().Get(proxyAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))
		Expect(err).NotTo(HaveOccurred())

		selection := doc.Find("#kc-form-login")
		Expect(selection).ToNot(BeNil())

		selection.Each(func(i int, s *goquery.Selection) {
			action, exists := s.Attr("action")
			Expect(exists).To(BeTrue())

			rClient.FormData.Add("username", testUser)
			rClient.FormData.Add("password", testPass)
			resp, err = rClient.R().Post(action)

			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
		})

		resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))

		rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
		resp, err = rClient.R().Get(proxyAddress)
		Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
	})
})

var _ = Describe("Code Flow PKCE login/logout", func() {
	var portNum string
	var proxyAddress string
	var pkceCookieName = "TESTPKCECOOKIE"

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + pkceTestClient,
			"--client-secret=" + pkceTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
			"--enable-pkce=true",
			"--cookie-pkce-name=" + pkceCookieName,
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	It("should login with user/password and logout successfully", func(ctx context.Context) {
		rClient := resty.New().SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))
		resp, err := rClient.R().Get(proxyAddress)
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))
		Expect(err).NotTo(HaveOccurred())

		selection := doc.Find("#kc-form-login")
		Expect(selection).ToNot(BeNil())

		selection.Each(func(i int, s *goquery.Selection) {
			action, exists := s.Attr("action")
			Expect(exists).To(BeTrue())

			rClient.FormData.Add("username", testUser)
			rClient.FormData.Add("password", testPass)
			resp, err = rClient.R().Post(action)

			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

			body := resp.Body()
			Expect(strings.Contains(string(body), pkceCookieName)).To(BeTrue())
		})

		resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))

		rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
		resp, err = rClient.R().Get(proxyAddress)
		Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
	})
})
