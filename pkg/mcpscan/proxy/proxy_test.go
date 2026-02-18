package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/certs"
	gafUtils "github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-httpauth/pkg/httpauth"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/constants"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/proxy"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/utils"
)

// Constants.
const (
	ConfigurationCleanupGlobalCertAuthority = "internal_cleanup_global_cert_auth_enabled"
	ConfigurationCleanupGlobalTempDirectory = "internal_cleanup_global_temp_dir_enabled"
	snykCLIVersion                          = "0.0.0"
)

// Package-level variables.
var (
	debugLogger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	caData      proxy.CaData
	caSingleton *proxy.CaData
	caMutex     sync.Mutex
)

// Helper functions

func CLIV1Version() string {
	return strings.TrimSpace(snykCLIVersion)
}

func GetFullVersion() string {
	return CLIV1Version()
}

func GetGlobalCertAuthority(config configuration.Configuration, debugLogger *zerolog.Logger) (proxy.CaData, error) {
	caMutex.Lock()
	defer caMutex.Unlock()

	createCA := false

	if caSingleton == nil {
		createCA = true
	} else if _, existsError := os.Stat(caSingleton.CertFile); errors.Is(existsError, fs.ErrNotExist) { // certificate file does not exist
		if len(caSingleton.CertPem) > 0 && len(caSingleton.CertFile) > 0 { // try to re-create file
			debugLogger.Printf("Restoring temporary certificate file: %s", caSingleton.CertFile)
			err := utils.WriteToFile(caSingleton.CertFile, caSingleton.CertPem)
			if err != nil {
				debugLogger.Printf("Failed to write cert to file: %s", caSingleton.CertFile)
				return proxy.CaData{}, err
			}
		} else { // fail for this unexpected case
			return proxy.CaData{}, fmt.Errorf("used Certificate Authority is not existing anymore!")
		}
	}

	if createCA {
		debugLogger.Print("Creating new Certificate Authority")
		tmp, err := proxy.InitCA(config, GetFullVersion(), debugLogger)
		if err != nil {
			return proxy.CaData{}, err
		}
		caSingleton = tmp
	}

	return *caSingleton, nil
}

func CleanupGlobalCertAuthority(debugLogger *zerolog.Logger) {
	caMutex.Lock()
	defer caMutex.Unlock()

	if caSingleton != nil && caSingleton.CertFile != "" {
		debugLogger.Printf("Cleaning up certificate file: %s", caSingleton.CertFile)
		if err := os.Remove(caSingleton.CertFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			debugLogger.Printf("Failed to remove certificate file: %v", err)
		}
		caSingleton = nil
	}
}

func helper_getHttpClient(gateway *proxy.WrapperProxy, useProxyAuth bool) (*http.Client, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	proxyCertBytes, err := os.ReadFile(gateway.CertificateLocation)
	if err != nil {
		return nil, err
	}

	ok := rootCAs.AppendCertsFromPEM(proxyCertBytes)
	if !ok {
		return nil, fmt.Errorf("failed to append proxy cert")
	}

	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	var proxyUrl *url.URL
	proxyInfo := gateway.ProxyInfo()
	if useProxyAuth {
		proxyUrl, err = url.Parse(fmt.Sprintf("http://%s:%s@127.0.0.1:%d", proxy.PROXY_USERNAME, proxyInfo.Password, proxyInfo.Port))
	} else {
		proxyUrl, err = url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyInfo.Port))
	}

	if err != nil {
		return nil, err
	}

	proxiedClient := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyUrl),
		TLSClientConfig: config,
	}}

	return proxiedClient, nil
}

// Test setup and teardown

func setup(t *testing.T, baseCache, version string) configuration.Configuration {
	t.Helper()
	err := gafUtils.CreateAllDirectories(baseCache, version)
	assert.Nil(t, err)
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	config.Set(configuration.CACHE_PATH, baseCache)
	config.Set(ConfigurationCleanupGlobalTempDirectory, true)
	config.Set(ConfigurationCleanupGlobalCertAuthority, true)
	caData, err = GetGlobalCertAuthority(config, &debugLogger)
	assert.Nil(t, err)
	return config
}

func teardown(t *testing.T, baseCache string) {
	t.Helper()
	CleanupGlobalCertAuthority(&debugLogger)
	err := os.RemoveAll(baseCache)
	assert.Nil(t, err)
}

// Tests

func Test_CleanupCertFile(t *testing.T) {
	basecache := "testcache"
	version := "1.1.1"
	config := setup(t, basecache, version)
	assert.NotNil(t, config)

	defer teardown(t, basecache)

	assert.FileExistsf(t, caData.CertFile, "CertFile exist")

	CleanupGlobalCertAuthority(&debugLogger)

	assert.NoFileExists(t, caData.CertFile, "CertFile does not exist anymore")
}

func Test_canGoThroughProxy(t *testing.T) {
	basecache := "testcache"
	version := "1.1.1"

	config := setup(t, basecache, version)
	defer teardown(t, basecache)

	config.Set(configuration.INSECURE_HTTPS, false)

	wp, err := proxy.NewWrapperProxy(config, version, &debugLogger, caData)
	assert.Nil(t, err)

	err = wp.Start()
	assert.Nil(t, err)

	useProxyAuth := true
	proxiedClient, err := helper_getHttpClient(wp, useProxyAuth)
	assert.Nil(t, err)

	res, err := proxiedClient.Get("https://downloads.snyk.io/cli/latest/version")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 200, res.StatusCode)

	wp.Close()
}

func Test_proxyRejectsWithoutBasicAuthHeader(t *testing.T) {
	basecache := "testcache"
	version := "1.1.1"

	config := setup(t, basecache, version)
	defer teardown(t, basecache)

	config.Set(configuration.INSECURE_HTTPS, false)

	wp, err := proxy.NewWrapperProxy(config, version, &debugLogger, caData)
	assert.Nil(t, err)

	err = wp.Start()
	assert.Nil(t, err)

	useProxyAuth := false
	proxiedClient, err := helper_getHttpClient(wp, useProxyAuth)
	assert.Nil(t, err)

	res, err := proxiedClient.Get("https://downloads.snyk.io/cli/latest/version")
	assert.Nil(t, res)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Proxy Authentication Required")

	wp.Close()
}

func Test_SetUpstreamProxy(t *testing.T) {
	basecache := "testcache"
	version := "1.1.1"

	config := setup(t, basecache, version)
	config.Set(configuration.INSECURE_HTTPS, false)
	defer teardown(t, basecache)

	var err error
	var objectUnderTest *proxy.WrapperProxy

	testUrl, _ := url.Parse("http://www.snyk.io")
	testRequest := http.Request{URL: testUrl}

	upstreanProxyUrlAsString := "http://localhost:3128"
	expectedUpstreamProxyUrl, _ := url.Parse(upstreanProxyUrlAsString)

	// using different cases to determine whether the proxy actually switches the mode authentication mode
	testCaseList := []httpauth.AuthenticationMechanism{
		httpauth.Negotiate,
		httpauth.AnyAuth,
		httpauth.NoAuth,
		httpauth.UnknownMechanism,
	}

	objectUnderTest, err = proxy.NewWrapperProxy(config, version, &debugLogger, caData)
	assert.Nil(t, err)

	// running different cases
	for i := range testCaseList {
		currentMechanism := testCaseList[i]
		t.Logf(" - using %s", httpauth.StringFromAuthenticationMechanism(currentMechanism))

		objectUnderTest.SetUpstreamProxyAuthentication(currentMechanism)
		objectUnderTest.SetUpstreamProxyFromUrl(upstreanProxyUrlAsString)
		transport := objectUnderTest.Transport()
		proxyFunc := objectUnderTest.UpstreamProxy()

		assert.NotNil(t, proxyFunc)
		actualUrl, err := proxyFunc(&testRequest)
		assert.Nil(t, err)
		assert.Equal(t, expectedUpstreamProxyUrl, actualUrl)

		// check transport and thereby authenticator configuration
		if httpauth.IsSupportedMechanism(currentMechanism) {
			assert.NotNil(t, transport.DialContext)
			assert.Nil(t, transport.Proxy)
		} else {
			assert.Nil(t, transport.DialContext)
			assert.NotNil(t, transport.Proxy)
		}
	}
}

func Test_AddExtraCaCert(t *testing.T) {
	basecache := "testcache"
	version := "1.1.1"

	loggerWrapper := log.New(&gafUtils.ToZeroLogDebug{Logger: &debugLogger}, "", 0)
	certPem, _, err := certs.MakeSelfSignedCert("mycert", []string{"dns"}, loggerWrapper)
	assert.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "")
	assert.NoError(t, err)
	_, err = file.Write(certPem)
	assert.NoError(t, err)

	t.Setenv(constants.SNYK_CA_CERTIFICATE_LOCATION_ENV, file.Name())

	config := setup(t, basecache, version)
	config.Set(configuration.INSECURE_HTTPS, false)
	defer teardown(t, basecache)

	wp, err := proxy.NewWrapperProxy(config, version, &debugLogger, caData)
	assert.Nil(t, err)

	certsPem, err := os.ReadFile(wp.CertificateLocation)
	assert.Nil(t, err)

	certsList, err := certs.GetAllCerts(certsPem)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(certsList))

	// cleanup
	os.Remove(file.Name())
}
