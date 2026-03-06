package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaredpalmer/mogcli/internal/errfmt"
	"github.com/jaredpalmer/mogcli/internal/secrets"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestAcquireDelegatedTokenReusesCachedTokenWhenScopesSatisfied(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	manager := NewManager()
	manager.now = func() time.Time { return now }

	profileName := "work"
	if err := manager.saveToken(profileName, TokenCache{
		AccessToken:  "cached-token",
		RefreshToken: "refresh-token",
		Scope:        "Mail.Read Mail.Send",
		ExpiresAt:    now.Add(1 * time.Hour),
		IDToken:      idTokenFor(t, "account-1", "tenant-1"),
	}); err != nil {
		t.Fatalf("saveToken failed: %v", err)
	}

	token, err := manager.AcquireDelegatedToken(
		context.Background(),
		profileName,
		"client-id",
		"organizations",
		[]string{"Mail.Read"},
		"account-1",
		"tenant-1",
	)
	if err != nil {
		t.Fatalf("AcquireDelegatedToken failed: %v", err)
	}
	if token != "cached-token" {
		t.Fatalf("expected cached token, got %q", token)
	}
}

func TestAcquireDelegatedTokenRefreshesWhenRequiredScopeMissing(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	refreshCalls := 0

	manager := NewManager()
	manager.now = func() time.Time { return now }
	manager.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			refreshCalls++
			if req.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", req.Method)
			}
			if !strings.HasSuffix(req.URL.Path, "/oauth2/v2.0/token") {
				t.Fatalf("unexpected token endpoint path: %s", req.URL.Path)
			}

			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("parse request body: %v", err)
			}
			if got := values.Get("scope"); got != "Mail.Send" {
				t.Fatalf("expected refresh scope Mail.Send, got %q", got)
			}

			payload := `{"token_type":"Bearer","scope":"Mail.Send","expires_in":3600,"access_token":"refreshed-token","refresh_token":"new-refresh-token"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(payload)),
			}, nil
		}),
	}

	profileName := "work"
	if err := manager.saveToken(profileName, TokenCache{
		AccessToken:  "cached-token",
		RefreshToken: "refresh-token",
		Scope:        "Mail.Read",
		ExpiresAt:    now.Add(1 * time.Hour),
		IDToken:      idTokenFor(t, "account-1", "tenant-1"),
	}); err != nil {
		t.Fatalf("saveToken failed: %v", err)
	}

	token, err := manager.AcquireDelegatedToken(
		context.Background(),
		profileName,
		"client-id",
		"organizations",
		[]string{"Mail.Send"},
		"account-1",
		"tenant-1",
	)
	if err != nil {
		t.Fatalf("AcquireDelegatedToken failed: %v", err)
	}
	if token != "refreshed-token" {
		t.Fatalf("expected refreshed token, got %q", token)
	}
	if refreshCalls != 1 {
		t.Fatalf("expected one refresh call, got %d", refreshCalls)
	}
}

func TestAcquireDelegatedTokenPurgesCacheOnAccountMismatch(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	manager := NewManager()
	manager.now = func() time.Time { return now }

	profileName := "work"
	if err := manager.saveToken(profileName, TokenCache{
		AccessToken:  "cached-token",
		RefreshToken: "refresh-token",
		Scope:        "Mail.Read",
		ExpiresAt:    now.Add(1 * time.Hour),
		IDToken:      idTokenFor(t, "account-1", "tenant-1"),
	}); err != nil {
		t.Fatalf("saveToken failed: %v", err)
	}

	_, err := manager.AcquireDelegatedToken(
		context.Background(),
		profileName,
		"client-id",
		"organizations",
		[]string{"Mail.Read"},
		"different-account",
		"tenant-1",
	)
	if err == nil {
		t.Fatal("expected mismatch error")
	}

	var userErr *errfmt.UserFacingError
	if !errors.As(err, &userErr) {
		t.Fatalf("expected UserFacingError, got %T", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "does not match the saved account") {
		t.Fatalf("unexpected mismatch error: %v", err)
	}
	if _, loadErr := manager.loadToken(profileName); loadErr == nil {
		t.Fatal("expected cached token to be purged")
	}
}

func TestAcquireDelegatedTokenPurgesCacheOnTenantMismatch(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	manager := NewManager()
	manager.now = func() time.Time { return now }

	profileName := "work"
	if err := manager.saveToken(profileName, TokenCache{
		AccessToken:  "cached-token",
		RefreshToken: "refresh-token",
		Scope:        "Mail.Read",
		ExpiresAt:    now.Add(1 * time.Hour),
		IDToken:      idTokenFor(t, "account-1", "tenant-1"),
	}); err != nil {
		t.Fatalf("saveToken failed: %v", err)
	}

	_, err := manager.AcquireDelegatedToken(
		context.Background(),
		profileName,
		"client-id",
		"organizations",
		[]string{"Mail.Read"},
		"account-1",
		"different-tenant",
	)
	if err == nil {
		t.Fatal("expected mismatch error")
	}

	var userErr *errfmt.UserFacingError
	if !errors.As(err, &userErr) {
		t.Fatalf("expected UserFacingError, got %T", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "does not match the saved tenant") {
		t.Fatalf("unexpected mismatch error: %v", err)
	}
	if _, loadErr := manager.loadToken(profileName); loadErr == nil {
		t.Fatal("expected cached token to be purged")
	}
}

func TestAcquireDelegatedTokenAcceptsTenantDomainExpectation(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	manager := NewManager()
	manager.now = func() time.Time { return now }

	profileName := "work"
	if err := manager.saveToken(profileName, TokenCache{
		AccessToken:  "cached-token",
		RefreshToken: "refresh-token",
		Scope:        "Mail.Read",
		ExpiresAt:    now.Add(1 * time.Hour),
		IDToken:      idTokenFor(t, "account-1", "11111111-2222-3333-4444-555555555555"),
	}); err != nil {
		t.Fatalf("saveToken failed: %v", err)
	}

	token, err := manager.AcquireDelegatedToken(
		context.Background(),
		profileName,
		"client-id",
		"organizations",
		[]string{"Mail.Read"},
		"account-1",
		"contoso.onmicrosoft.com",
	)
	if err != nil {
		t.Fatalf("AcquireDelegatedToken failed: %v", err)
	}
	if token != "cached-token" {
		t.Fatalf("expected cached token, got %q", token)
	}
	if _, err := manager.loadToken(profileName); err != nil {
		t.Fatalf("expected cached token to remain, got %v", err)
	}
}

func setTempSecretsHome(t *testing.T) {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("MOG_KEYRING_BACKEND", "file")
}

func idTokenFor(t *testing.T, accountID string, tenantID string) string {
	t.Helper()

	headerBytes, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatalf("encode header: %v", err)
	}
	payloadBytes, err := json.Marshal(map[string]string{
		"oid": accountID,
		"tid": tenantID,
		"sub": accountID,
	})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}

	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + "."
}

func TestAcquireDelegatedTokenRefreshIncludesClientSecretWhenStored(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	var capturedSecret string

	manager := NewManager()
	manager.now = func() time.Time { return now }
	manager.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("parse request body: %v", err)
			}
			capturedSecret = values.Get("client_secret")

			payload := `{"token_type":"Bearer","scope":"Mail.Read","expires_in":3600,"access_token":"refreshed-token","refresh_token":"new-refresh-token"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(payload)),
			}, nil
		}),
	}

	profileName := "confidential"

	// Store a delegated client secret.
	secretKey, err := delegatedSecretKey(profileName)
	if err != nil {
		t.Fatalf("delegatedSecretKey: %v", err)
	}
	if err := secrets.SetSecret(secretKey, []byte("my-client-secret")); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	// Store an expired token to force a refresh.
	if err := manager.saveToken(profileName, TokenCache{
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token",
		Scope:        "Mail.Read",
		ExpiresAt:    now.Add(-1 * time.Hour),
		IDToken:      idTokenFor(t, "account-1", "tenant-1"),
	}); err != nil {
		t.Fatalf("saveToken failed: %v", err)
	}

	token, err := manager.AcquireDelegatedToken(
		context.Background(),
		profileName,
		"client-id",
		"organizations",
		[]string{"Mail.Read"},
		"account-1",
		"tenant-1",
	)
	if err != nil {
		t.Fatalf("AcquireDelegatedToken failed: %v", err)
	}
	if token != "refreshed-token" {
		t.Fatalf("expected refreshed-token, got %q", token)
	}
	if capturedSecret != "my-client-secret" {
		t.Fatalf("expected client_secret in refresh request, got %q", capturedSecret)
	}
}

func TestAcquireDelegatedTokenRefreshOmitsClientSecretWhenNotStored(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	var capturedSecret string

	manager := NewManager()
	manager.now = func() time.Time { return now }
	manager.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("parse request body: %v", err)
			}
			capturedSecret = values.Get("client_secret")

			payload := `{"token_type":"Bearer","scope":"Mail.Read","expires_in":3600,"access_token":"refreshed-token","refresh_token":"new-refresh-token"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(payload)),
			}, nil
		}),
	}

	profileName := "public"
	// No delegated secret stored — public client scenario.

	if err := manager.saveToken(profileName, TokenCache{
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token",
		Scope:        "Mail.Read",
		ExpiresAt:    now.Add(-1 * time.Hour),
		IDToken:      idTokenFor(t, "account-1", "tenant-1"),
	}); err != nil {
		t.Fatalf("saveToken failed: %v", err)
	}

	token, err := manager.AcquireDelegatedToken(
		context.Background(),
		profileName,
		"client-id",
		"organizations",
		[]string{"Mail.Read"},
		"account-1",
		"tenant-1",
	)
	if err != nil {
		t.Fatalf("AcquireDelegatedToken failed: %v", err)
	}
	if token != "refreshed-token" {
		t.Fatalf("expected refreshed-token, got %q", token)
	}
	if capturedSecret != "" {
		t.Fatalf("expected no client_secret in refresh request, got %q", capturedSecret)
	}
}

func TestLoginDelegatedStoresClientSecret(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	manager := NewManager()
	manager.now = func() time.Time { return now }
	manager.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if strings.HasSuffix(req.URL.Path, "/devicecode") {
				payload := `{"user_code":"ABC123","device_code":"dc-123","verification_uri":"https://example.com/device","expires_in":600,"interval":1}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(payload)),
				}, nil
			}
			idToken := idTokenFor(t, "account-1", "tenant-1")
			payload := `{"token_type":"Bearer","scope":"Mail.Read","expires_in":3600,"access_token":"new-token","refresh_token":"new-refresh","id_token":"` + idToken + `"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(payload)),
			}, nil
		}),
	}

	_, err := manager.LoginDelegated(context.Background(), DelegatedLoginInput{
		ProfileName: "confidential-login",
		Audience:    "enterprise",
		ClientID:    "client-id",
		Authority:   "organizations",
		Scopes:      []string{"Mail.Read"},
		Secret:      "stored-secret",
	}, nil)
	if err != nil {
		t.Fatalf("LoginDelegated failed: %v", err)
	}

	// Verify the secret was stored.
	secretKey, err := delegatedSecretKey("confidential-login")
	if err != nil {
		t.Fatalf("delegatedSecretKey: %v", err)
	}
	secret, err := secrets.GetSecret(secretKey)
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(secret) != "stored-secret" {
		t.Fatalf("expected stored secret, got %q", string(secret))
	}
}

func TestLoginDelegatedRefreshTokenSkipsDeviceCode(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	var capturedGrantType, capturedRefreshToken, capturedClientSecret string

	manager := NewManager()
	manager.now = func() time.Time { return now }
	manager.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			values, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatalf("parse request body: %v", err)
			}
			capturedGrantType = values.Get("grant_type")
			capturedRefreshToken = values.Get("refresh_token")
			capturedClientSecret = values.Get("client_secret")

			idToken := idTokenFor(t, "account-1", "tenant-1")
			payload := `{"token_type":"Bearer","scope":"Mail.Read","expires_in":3600,"access_token":"fresh-token","refresh_token":"rotated-refresh","id_token":"` + idToken + `"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(payload)),
			}, nil
		}),
	}

	account, err := manager.LoginDelegated(context.Background(), DelegatedLoginInput{
		ProfileName:  "headless",
		Audience:     "enterprise",
		ClientID:     "client-id",
		Authority:    "organizations",
		Scopes:       []string{"Mail.Read"},
		Secret:       "my-secret",
		RefreshToken: "existing-refresh-token",
	}, nil)
	if err != nil {
		t.Fatalf("LoginDelegated with refresh token failed: %v", err)
	}

	// Verify it used refresh_token grant, not device_code.
	if capturedGrantType != "refresh_token" {
		t.Fatalf("expected grant_type=refresh_token, got %q", capturedGrantType)
	}
	if capturedRefreshToken != "existing-refresh-token" {
		t.Fatalf("expected refresh_token in request, got %q", capturedRefreshToken)
	}
	if capturedClientSecret != "my-secret" {
		t.Fatalf("expected client_secret in request, got %q", capturedClientSecret)
	}

	// Verify account info was extracted from ID token.
	if account.AccountID != "account-1" {
		t.Fatalf("expected account ID account-1, got %q", account.AccountID)
	}

	// Verify token was saved.
	cache, err := manager.loadToken("headless")
	if err != nil {
		t.Fatalf("loadToken failed: %v", err)
	}
	if cache.AccessToken != "fresh-token" {
		t.Fatalf("expected access token fresh-token, got %q", cache.AccessToken)
	}
	if cache.RefreshToken != "rotated-refresh" {
		t.Fatalf("expected rotated refresh token, got %q", cache.RefreshToken)
	}
}

func TestLoginDelegatedRefreshTokenPreservesOriginalWhenNotRotated(t *testing.T) {
	setTempSecretsHome(t)

	now := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	manager := NewManager()
	manager.now = func() time.Time { return now }
	manager.HTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			idToken := idTokenFor(t, "account-1", "tenant-1")
			// Server does NOT return a new refresh token.
			payload := `{"token_type":"Bearer","scope":"Mail.Read","expires_in":3600,"access_token":"fresh-token","id_token":"` + idToken + `"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(payload)),
			}, nil
		}),
	}

	_, err := manager.LoginDelegated(context.Background(), DelegatedLoginInput{
		ProfileName:  "headless-no-rotate",
		Audience:     "enterprise",
		ClientID:     "client-id",
		Authority:    "organizations",
		Scopes:       []string{"Mail.Read"},
		RefreshToken: "original-refresh",
	}, nil)
	if err != nil {
		t.Fatalf("LoginDelegated failed: %v", err)
	}

	cache, err := manager.loadToken("headless-no-rotate")
	if err != nil {
		t.Fatalf("loadToken failed: %v", err)
	}
	if cache.RefreshToken != "original-refresh" {
		t.Fatalf("expected original refresh token preserved, got %q", cache.RefreshToken)
	}
}

func TestScopeSetContainsAllMatchesFullURLScopes(t *testing.T) {
	granted := []string{"https://graph.microsoft.com/Mail.Read", "https://graph.microsoft.com/Mail.Send"}
	required := []string{"Mail.Read"}
	if !scopeSetContainsAll(granted, required) {
		t.Fatal("expected full-URL scope to match short-form required scope")
	}
}

func TestScopeSetContainsAllDefaultCoversAll(t *testing.T) {
	granted := []string{"openid", "profile", "https://graph.microsoft.com/.default"}
	required := []string{"Mail.Read", "Calendars.ReadWrite"}
	if !scopeSetContainsAll(granted, required) {
		t.Fatal("expected .default scope to cover all required scopes")
	}
}

func TestScopeSetContainsAllShortFormStillWorks(t *testing.T) {
	granted := []string{"Mail.Read", "Mail.Send"}
	required := []string{"Mail.Read"}
	if !scopeSetContainsAll(granted, required) {
		t.Fatal("expected short-form scope match to still work")
	}
}

func TestScopeSetContainsAllMissingScope(t *testing.T) {
	granted := []string{"https://graph.microsoft.com/Mail.Read"}
	required := []string{"Mail.Read", "Calendars.ReadWrite"}
	if scopeSetContainsAll(granted, required) {
		t.Fatal("expected missing Calendars.ReadWrite to fail")
	}
}

func TestTokenCacheKeyRejectsInvalidProfileName(t *testing.T) {
	if _, err := tokenCacheKey("../bad-profile"); err == nil {
		t.Fatal("expected invalid profile name error")
	}
}

func TestSecureZero(t *testing.T) {
	value := []byte("super-secret")
	secureZero(value)

	for i, b := range value {
		if b != 0 {
			t.Fatalf("expected index %d to be zeroed, got %d", i, b)
		}
	}
}
