package tenantsapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/helpers/tenantsapi"
)

const (
	versionQueryParam  = "version"
	contentTypeHeader  = "Content-Type"
	contentTypeJSONAPI = "application/vnd.api+json"
	defaultResponse    = `{"data":[],"jsonapi":{"version":"1.0"},"links":{}}`
	tenantsPath        = "/rest/tenants"

	errNewClientWithResponses = "NewClientWithResponses: %v"
	errListTenants            = "ListTenants: %v"
	errExpectedVersion        = "expected version %q, got %q"
	errExpectedPath           = "expected path %q, got %q"
)

func TestListTenants_DefaultVersionWhenParamsNil(t *testing.T) {
	t.Parallel()

	gotVersion := make(chan string, 1)
	gotPath := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion <- r.URL.Query().Get(versionQueryParam)
		gotPath <- r.URL.Path

		w.Header().Set(contentTypeHeader, contentTypeJSONAPI)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(defaultResponse)); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	client, err := tenantsapi.NewClientWithResponses(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf(errNewClientWithResponses, err)
	}

	resp, err := tenantsapi.ListTenants(t.Context(), client, nil)
	if err != nil {
		t.Fatalf(errListTenants, err)
	}
	if resp == nil {
		t.Fatalf("expected non-nil response")
	}
	if len(resp.Tenants) != 0 {
		t.Fatalf("expected 0 tenants, got %d", len(resp.Tenants))
	}

	if v := <-gotVersion; v != tenantsapi.DefaultAPIVersion {
		t.Fatalf(errExpectedVersion, tenantsapi.DefaultAPIVersion, v)
	}
	if p := <-gotPath; p != tenantsPath {
		t.Fatalf(errExpectedPath, tenantsPath, p)
	}
}

func TestListTenants_DefaultVersionWhenParamsVersionEmpty(t *testing.T) {
	t.Parallel()

	gotVersion := make(chan string, 1)
	gotPath := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion <- r.URL.Query().Get(versionQueryParam)
		gotPath <- r.URL.Path

		w.Header().Set(contentTypeHeader, contentTypeJSONAPI)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(defaultResponse)); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	client, err := tenantsapi.NewClientWithResponses(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf(errNewClientWithResponses, err)
	}

	params := &tenantsapi.ListTenantsParams{}
	_, err = tenantsapi.ListTenants(t.Context(), client, params)
	if err != nil {
		t.Fatalf(errListTenants, err)
	}

	if v := <-gotVersion; v != tenantsapi.DefaultAPIVersion {
		t.Fatalf(errExpectedVersion, tenantsapi.DefaultAPIVersion, v)
	}
	if p := <-gotPath; p != tenantsPath {
		t.Fatalf(errExpectedPath, tenantsPath, p)
	}
}

func TestListTenants_RespectsProvidedVersion(t *testing.T) {
	t.Parallel()

	gotVersion := make(chan string, 1)
	gotPath := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion <- r.URL.Query().Get(versionQueryParam)
		gotPath <- r.URL.Path

		w.Header().Set(contentTypeHeader, contentTypeJSONAPI)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(defaultResponse)); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	client, err := tenantsapi.NewClientWithResponses(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf(errNewClientWithResponses, err)
	}

	expected := tenantsapi.Version("2025-01-01")
	params := &tenantsapi.ListTenantsParams{Version: expected}
	_, err = tenantsapi.ListTenants(t.Context(), client, params)
	if err != nil {
		t.Fatalf(errListTenants, err)
	}

	if v := <-gotVersion; v != expected {
		t.Fatalf(errExpectedVersion, expected, v)
	}
	if p := <-gotPath; p != tenantsPath {
		t.Fatalf(errExpectedPath, tenantsPath, p)
	}
}

func TestListTenants_ServerAlreadyContainsRest(t *testing.T) {
	t.Parallel()

	gotPath := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath <- r.URL.Path

		w.Header().Set(contentTypeHeader, contentTypeJSONAPI)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(defaultResponse)); err != nil {
			t.Fatal(err)
		}
	}))
	defer srv.Close()

	client, err := tenantsapi.NewClientWithResponses(srv.URL+"/rest", srv.Client())
	if err != nil {
		t.Fatalf(errNewClientWithResponses, err)
	}

	_, err = tenantsapi.ListTenants(t.Context(), client, nil)
	if err != nil {
		t.Fatalf(errListTenants, err)
	}

	if p := <-gotPath; p != tenantsPath {
		t.Fatalf(errExpectedPath, tenantsPath, p)
	}
}
