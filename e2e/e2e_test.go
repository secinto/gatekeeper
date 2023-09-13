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

	"github.com/PuerkitoBio/goquery"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2/clientcredentials"

	resty "github.com/go-resty/resty/v2"
	"github.com/gogatekeeper/gatekeeper/pkg/constant"
	"github.com/gogatekeeper/gatekeeper/pkg/proxy"
	"github.com/gogatekeeper/gatekeeper/pkg/testsuite"
)

const (
	testRealm               = "test"
	testClient              = "test-client"
	testClientSecret        = "6447d0c0-d510-42a7-b654-6e3a16b2d7e2"
	pkceTestClient          = "test-client-pkce"
	pkceTestClientSecret    = "F2GqU40xwX0P2LrTvHUHqwNoSk4U4n5R"
	umaTestClient           = "test-client-uma"
	umaTestClientSecret     = "A5vokiGdI3H2r4aXFrANbKvn4R7cbf6P"
	timeout                 = time.Second * 300
	idpURI                  = "http://localhost:8081"
	testUser                = "myuser"
	testPass                = "baba1234"
	umaAllowedPath          = "/pets"
	umaForbiddenPath        = "/pets/1"
	umaNonExistentPath      = "/cat"
	umaMethodAllowedPath    = "/horse"
	umaFwdMethodAllowedPath = "/turtle"
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

func codeFlowLogin(client *resty.Client, reqAddress string, expStatusCode int) *resty.Response {
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))
	resp, err := client.R().Get(reqAddress)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode()).To(Equal(http.StatusOK))

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))
	Expect(err).NotTo(HaveOccurred())

	selection := doc.Find("#kc-form-login")
	Expect(selection).ToNot(BeNil())

	selection.Each(func(i int, s *goquery.Selection) {
		action, exists := s.Attr("action")
		Expect(exists).To(BeTrue())

		client.FormData.Add("username", testUser)
		client.FormData.Add("password", testPass)
		resp, err = client.R().Post(action)

		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(expStatusCode))
	})

	return resp
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
		var err error
		rClient := resty.New()
		resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK)
		Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))
		resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))

		rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
		resp, _ = rClient.R().Get(proxyAddress)
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
		var err error
		rClient := resty.New()
		resp := codeFlowLogin(rClient, proxyAddress, http.StatusOK)
		Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

		body := resp.Body()
		Expect(strings.Contains(string(body), pkceCookieName)).To(BeTrue())

		resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
		Expect(err).NotTo(HaveOccurred())
		Expect(resp.StatusCode()).To(Equal(http.StatusOK))

		rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
		resp, _ = rClient.R().Get(proxyAddress)
		Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
	})
})

var _ = Describe("UMA Code Flow authorization", func() {
	var portNum string
	var proxyAddress string
	var umaCookieName = "TESTUMACOOKIE"

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--enable-uma=true",
			"--cookie-uma-name=" + umaCookieName,
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Accessing resource, where user is allowed to access", func() {
		It("should login with user/password and logout successfully", func(ctx context.Context) {
			var err error
			rClient := resty.New()
			resp := codeFlowLogin(rClient, proxyAddress+umaAllowedPath, http.StatusOK)
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeTrue())

			By("Accessing not allowed path")
			resp, err = rClient.R().Get(proxyAddress + umaForbiddenPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddress + umaAllowedPath)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
		})
	})

	When("Accessing resource, which does not exist", func() {
		It("should be forbidden without permission ticket", func(ctx context.Context) {
			rClient := resty.New()
			resp := codeFlowLogin(rClient, proxyAddress+umaNonExistentPath, http.StatusForbidden)

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())
		})
	})

	When("Accessing resource, which exists but user is not allowed and then allowed resource", func() {
		It("should be forbidden and then allowed", func(ctx context.Context) {
			var err error
			rClient := resty.New()
			resp := codeFlowLogin(rClient, proxyAddress+umaForbiddenPath, http.StatusForbidden)

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			By("Accessing allowed resource")
			resp, err = rClient.R().Get(proxyAddress + umaAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			By("Accessing allowed resource one more time, checking uma cookie set")
			resp, err = rClient.R().Get(proxyAddress + umaAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeTrue())
		})
	})
})

var _ = Describe("UMA Code Flow authorization with method scope", func() {
	var portNum string
	var proxyAddress string
	var umaCookieName = "TESTUMACOOKIE"

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		osArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=false",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--cookie-uma-name=" + umaCookieName,
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
			"--secure-cookie=false",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
	})

	When("Accessing resource, where user is allowed to access and then not allowed resource", func() {
		It("should login with user/password, don't access forbidden resource and logout successfully", func(ctx context.Context) {
			var err error
			rClient := resty.New()
			resp := codeFlowLogin(rClient, proxyAddress+umaMethodAllowedPath, http.StatusOK)
			Expect(resp.Header().Get("Proxy-Accepted")).To(Equal("true"))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaCookieName)).To(BeTrue())

			By("Accessing not allowed method")
			resp, err = rClient.R().Post(proxyAddress + umaMethodAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusForbidden))
			Expect(strings.Contains(string(body), umaCookieName)).To(BeFalse())

			resp, err = rClient.R().Get(proxyAddress + "/oauth/logout")
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			rClient.SetRedirectPolicy(resty.NoRedirectPolicy())
			resp, _ = rClient.R().Get(proxyAddress + umaAllowedPath)
			Expect(resp.StatusCode()).To(Equal(http.StatusSeeOther))
		})
	})
})

var _ = Describe("UMA no-redirects authorization with forwarding", func() {
	var portNum string
	var proxyAddress string
	var fwdPortNum string
	var fwdProxyAddress string

	BeforeEach(func() {
		server := httptest.NewServer(&testsuite.FakeUpstreamService{})
		portNum = generateRandomPort()
		fwdPortNum = generateRandomPort()
		proxyAddress = "http://localhost:" + portNum
		fwdProxyAddress = "http://localhost:" + fwdPortNum
		osArgs := []string{os.Args[0]}
		fwdOsArgs := []string{os.Args[0]}
		proxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + portNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--upstream-url=" + server.URL,
			"--no-redirects=true",
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
		}

		fwdProxyArgs := []string{
			"--discovery-url=" + idpRealmURI,
			"--openid-provider-timeout=120s",
			"--listen=" + "0.0.0.0:" + fwdPortNum,
			"--client-id=" + umaTestClient,
			"--client-secret=" + umaTestClientSecret,
			"--enable-uma=true",
			"--enable-uma-method-scope=true",
			"--enable-forwarding=true",
			"--enable-authorization-header=true",
			"--forwarding-grant-type=client_credentials",
			"--skip-access-token-clientid-check=true",
			"--skip-access-token-issuer-check=true",
			"--openid-provider-retry-count=30",
		}

		osArgs = append(osArgs, proxyArgs...)
		startAndWait(portNum, osArgs)
		fwdOsArgs = append(fwdOsArgs, fwdProxyArgs...)
		startAndWait(fwdPortNum, fwdOsArgs)
	})

	When("Accessing resource, where user is allowed to access and then not allowed resource", func() {
		It("should login with user/password, don't access forbidden resource", func(ctx context.Context) {
			rClient := resty.New().SetRedirectPolicy(resty.NoRedirectPolicy())
			rClient.SetProxy(fwdProxyAddress)
			resp, err := rClient.R().Get(proxyAddress + umaFwdMethodAllowedPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusOK))

			body := resp.Body()
			Expect(strings.Contains(string(body), umaFwdMethodAllowedPath)).To(BeTrue())

			By("Accessing resource without access for client id")
			resp, err = rClient.R().Get(proxyAddress + umaAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusUnauthorized))
			Expect(strings.Contains(string(body), umaAllowedPath)).To(BeFalse())

			By("Accessing not allowed method")
			resp, err = rClient.R().Post(proxyAddress + umaFwdMethodAllowedPath)
			body = resp.Body()
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode()).To(Equal(http.StatusUnauthorized))
			Expect(strings.Contains(string(body), umaFwdMethodAllowedPath)).To(BeFalse())
		})
	})
})
