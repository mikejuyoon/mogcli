package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jaredpalmer/mogcli/internal/errfmt"
	"github.com/jaredpalmer/mogcli/internal/profile"
	"github.com/jaredpalmer/mogcli/internal/secrets"
)

var (
	ErrMissingClientID     = errors.New("missing client ID")
	ErrMissingAuthority    = errors.New("missing authority")
	ErrMissingRefreshToken = errors.New("missing refresh token")
	ErrMissingSecret       = errors.New("missing client secret")
)

// Manager coordinates login, token acquisition, and secure token persistence.
type Manager struct {
	HTTPClient *http.Client
	now        func() time.Time

	// WAMInvoker overrides the WAM helper subprocess invocation. Used for testing.
	// When nil, the default invokeWAMExe implementation is used.
	WAMInvoker func(ctx context.Context, req WAMRequest) (WAMResponse, error)
}

// NewManager returns an auth manager with default HTTP/time providers.
func NewManager() *Manager {
	return &Manager{
		HTTPClient: http.DefaultClient,
		now:        time.Now,
	}
}

func (m *Manager) invokeWAM(ctx context.Context, req WAMRequest) (WAMResponse, error) {
	if m.WAMInvoker != nil {
		return m.WAMInvoker(ctx, req)
	}

	return invokeWAMExe(ctx, req)
}

func (m *Manager) httpClient() *http.Client {
	if m.HTTPClient != nil {
		return m.HTTPClient
	}

	return http.DefaultClient
}

func (m *Manager) nowUTC() time.Time {
	if m.now != nil {
		return m.now().UTC()
	}

	return time.Now().UTC()
}

func tokenCacheKey(profileName string) (string, error) {
	normalized, err := profile.NormalizeName(profileName)
	if err != nil {
		return "", fmt.Errorf("invalid profile name: %w", err)
	}
	return "mog:cache:" + normalized, nil
}

func appSecretKey(profileName string) (string, error) {
	normalized, err := profile.NormalizeName(profileName)
	if err != nil {
		return "", fmt.Errorf("invalid profile name: %w", err)
	}
	return "mog:appsecret:" + normalized, nil
}

func delegatedSecretKey(profileName string) (string, error) {
	normalized, err := profile.NormalizeName(profileName)
	if err != nil {
		return "", fmt.Errorf("invalid profile name: %w", err)
	}
	return "mog:delegatedsecret:" + normalized, nil
}

func graphDefaultScope() string {
	return "https://graph.microsoft.com/.default"
}

func normalizeAuthority(authority string) string {
	authority = strings.TrimSpace(authority)
	authority = strings.TrimPrefix(authority, "https://login.microsoftonline.com/")
	authority = strings.Trim(authority, "/")
	if authority == "" {
		return "organizations"
	}

	return authority
}

func endpoint(authority string, path string) string {
	return "https://login.microsoftonline.com/" + normalizeAuthority(authority) + path
}

type deviceCodeResponse struct {
	UserCode                string `json:"user_code"`
	DeviceCode              string `json:"device_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Message                 string `json:"message"`
}

type tokenResponse struct {
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type oauthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (m *Manager) LoginDelegated(ctx context.Context, input DelegatedLoginInput, writeMessage func(string)) (AccountInfo, error) {
	if strings.TrimSpace(input.ClientID) == "" {
		return AccountInfo{}, ErrMissingClientID
	}
	if strings.TrimSpace(input.Authority) == "" {
		return AccountInfo{}, ErrMissingAuthority
	}
	if len(input.Scopes) == 0 {
		input.Scopes = BaseDelegatedScopes
	}
	input.Scopes = normalizeScopes(input.Scopes)
	if len(input.Scopes) == 0 {
		input.Scopes = BaseDelegatedScopes
	}

	// Persist client secret for confidential client delegated flows.
	if secret := strings.TrimSpace(input.Secret); secret != "" {
		secretKey, err := delegatedSecretKey(input.ProfileName)
		if err != nil {
			return AccountInfo{}, err
		}
		secretBytes := []byte(secret)
		defer secureZero(secretBytes)
		if err := secrets.SetSecret(secretKey, secretBytes); err != nil {
			return AccountInfo{}, fmt.Errorf("store client secret: %w", err)
		}
	}

	// If a refresh token is provided, skip interactive login and seed the
	// token cache directly via an immediate token refresh. This enables
	// fully headless/browserless authentication.
	if rt := strings.TrimSpace(input.RefreshToken); rt != "" {
		return m.loginDelegatedRefreshToken(ctx, input, writeMessage)
	}

	if useWAM() {
		return m.loginDelegatedWAM(ctx, input, writeMessage)
	}

	return m.loginDelegatedDeviceCode(ctx, input, writeMessage)
}

func (m *Manager) loginDelegatedWAM(ctx context.Context, input DelegatedLoginInput, writeMessage func(string)) (AccountInfo, error) {
	if writeMessage != nil {
		writeMessage("Authenticating via Windows account...")
	}

	resp, err := m.invokeWAM(ctx, WAMRequest{
		Action:    "login",
		ClientID:  input.ClientID,
		Authority: normalizeAuthority(input.Authority),
		Scopes:    input.Scopes,
	})
	if err != nil {
		return AccountInfo{}, err
	}
	if strings.TrimSpace(resp.AccessToken) == "" {
		return AccountInfo{}, errors.New("WAM login response missing access_token")
	}

	expiresIn := resp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	account := accountFromWAMResponse(resp)
	if strings.TrimSpace(account.AccountID) == "" && strings.TrimSpace(account.Username) == "" {
		return AccountInfo{}, errors.New("WAM login response missing account identity")
	}

	cache := TokenCache{
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
		Scope:       resp.Scope,
		ExpiresAt:   m.nowUTC().Add(time.Duration(expiresIn) * time.Second),
		IDToken:     resp.IDToken,
	}
	if err := m.saveToken(input.ProfileName, cache); err != nil {
		return AccountInfo{}, err
	}

	return account, nil
}

func (m *Manager) loginDelegatedDeviceCode(ctx context.Context, input DelegatedLoginInput, writeMessage func(string)) (AccountInfo, error) {
	deviceReq := url.Values{}
	deviceReq.Set("client_id", input.ClientID)
	deviceReq.Set("scope", strings.Join(input.Scopes, " "))

	body, err := m.doForm(ctx, endpoint(input.Authority, "/oauth2/v2.0/devicecode"), deviceReq)
	if err != nil {
		return AccountInfo{}, err
	}
	defer secureZero(body)

	var dcr deviceCodeResponse
	if err := json.Unmarshal(body, &dcr); err != nil {
		return AccountInfo{}, fmt.Errorf("decode device code response: %w", err)
	}

	if dcr.DeviceCode == "" {
		return AccountInfo{}, errors.New("device code response missing device_code")
	}

	if writeMessage != nil {
		msg := strings.TrimSpace(dcr.Message)
		if msg == "" {
			if dcr.VerificationURIComplete != "" {
				msg = fmt.Sprintf("Open %s", dcr.VerificationURIComplete)
			} else {
				msg = fmt.Sprintf("Open %s and enter code %s", dcr.VerificationURI, dcr.UserCode)
			}
		}
		writeMessage(msg)
	}

	interval := time.Duration(dcr.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	expires := m.nowUTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	if dcr.ExpiresIn <= 0 {
		expires = m.nowUTC().Add(15 * time.Minute)
	}

	for m.nowUTC().Before(expires) {
		select {
		case <-ctx.Done():
			return AccountInfo{}, fmt.Errorf("device code flow cancelled: %w", ctx.Err())
		default:
		}

		tokReq := url.Values{}
		tokReq.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		tokReq.Set("client_id", input.ClientID)
		tokReq.Set("device_code", dcr.DeviceCode)

		resultBody, status, err := m.doFormWithStatus(ctx, endpoint(input.Authority, "/oauth2/v2.0/token"), tokReq)
		if err != nil {
			return AccountInfo{}, err
		}

		if status == http.StatusOK {
			var tr tokenResponse
			if err := json.Unmarshal(resultBody, &tr); err != nil {
				return AccountInfo{}, fmt.Errorf("decode token response: %w", err)
			}
			cache := TokenCache{
				AccessToken:  tr.AccessToken,
				RefreshToken: tr.RefreshToken,
				TokenType:    tr.TokenType,
				Scope:        tr.Scope,
				ExpiresAt:    m.nowUTC().Add(time.Duration(tr.ExpiresIn) * time.Second),
				IDToken:      tr.IDToken,
			}
			if err := m.saveToken(input.ProfileName, cache); err != nil {
				return AccountInfo{}, err
			}

			claims, _ := parseIDClaims(tr.IDToken)
			return accountFromClaims(claims), nil
		}

		var oe oauthErrorResponse
		_ = json.Unmarshal(resultBody, &oe)
		switch oe.Error {
		case "authorization_pending":
			if err := sleepContext(ctx, interval); err != nil {
				return AccountInfo{}, err
			}
			continue
		case "slow_down":
			interval += 3 * time.Second
			if err := sleepContext(ctx, interval); err != nil {
				return AccountInfo{}, err
			}
			continue
		case "expired_token":
			return AccountInfo{}, errors.New("device code expired; retry login")
		default:
			return AccountInfo{}, fmt.Errorf("token exchange failed (%s): %s", oe.Error, strings.TrimSpace(oe.ErrorDescription))
		}
	}

	return AccountInfo{}, errors.New("device code flow timed out")
}

// loginDelegatedRefreshToken seeds the token cache from a pre-existing refresh
// token, then performs an immediate token refresh to validate the token and
// obtain an ID token for identity verification. This enables fully headless
// authentication without a browser-based device code flow.
func (m *Manager) loginDelegatedRefreshToken(ctx context.Context, input DelegatedLoginInput, writeMessage func(string)) (AccountInfo, error) {
	refreshToken := strings.TrimSpace(input.RefreshToken)
	if refreshToken == "" {
		return AccountInfo{}, ErrMissingRefreshToken
	}

	if writeMessage != nil {
		writeMessage("Authenticating with refresh token...")
	}

	// Build the token refresh request. Use .default scope so the token
	// inherits all permissions already consented on the app registration.
	// Individual scopes (Mail.Read, etc.) can fail with AADSTS65001 if
	// they weren't part of the original consent flow.
	req := url.Values{}
	req.Set("grant_type", "refresh_token")
	req.Set("client_id", input.ClientID)
	req.Set("refresh_token", refreshToken)
	req.Set("scope", "offline_access openid profile "+graphDefaultScope())

	// Include client_secret for confidential clients.
	if secret := strings.TrimSpace(input.Secret); secret != "" {
		req.Set("client_secret", secret)
	}

	body, status, err := m.doFormWithStatus(ctx, endpoint(input.Authority, "/oauth2/v2.0/token"), req)
	if err != nil {
		return AccountInfo{}, err
	}
	defer secureZero(body)

	if status != http.StatusOK {
		var oe oauthErrorResponse
		_ = json.Unmarshal(body, &oe)
		return AccountInfo{}, fmt.Errorf("refresh token login failed (%s): %s", oe.Error, strings.TrimSpace(oe.ErrorDescription))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return AccountInfo{}, fmt.Errorf("decode token response: %w", err)
	}

	// Preserve the original refresh token if the server didn't rotate it.
	if tr.RefreshToken == "" {
		tr.RefreshToken = refreshToken
	}

	cache := TokenCache{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Scope:        tr.Scope,
		ExpiresAt:    m.nowUTC().Add(time.Duration(tr.ExpiresIn) * time.Second),
		IDToken:      tr.IDToken,
	}
	if err := m.saveToken(input.ProfileName, cache); err != nil {
		return AccountInfo{}, err
	}

	claims, _ := parseIDClaims(tr.IDToken)
	return accountFromClaims(claims), nil
}

func (m *Manager) LoginAppOnly(ctx context.Context, input AppOnlyLoginInput) error {
	if strings.TrimSpace(input.ClientID) == "" {
		return ErrMissingClientID
	}
	if strings.TrimSpace(input.Authority) == "" {
		return ErrMissingAuthority
	}
	if strings.TrimSpace(input.Secret) == "" {
		return ErrMissingSecret
	}

	secretKey, err := appSecretKey(input.ProfileName)
	if err != nil {
		return err
	}

	secretBytes := []byte(input.Secret)
	defer secureZero(secretBytes)
	if err := secrets.SetSecret(secretKey, secretBytes); err != nil {
		return fmt.Errorf("store client secret: %w", err)
	}

	_, err = m.AcquireAppOnlyToken(ctx, input.ProfileName, input.ClientID, input.Authority)
	return err
}

func (m *Manager) AcquireDelegatedToken(
	ctx context.Context,
	profileName string,
	clientID string,
	authority string,
	scopes []string,
	expectedAccountID string,
	expectedTenantID string,
) (string, error) {
	cache, err := m.loadToken(profileName)
	if err != nil {
		return "", err
	}

	if err := m.validateCachedDelegatedIdentity(profileName, cache, expectedAccountID, expectedTenantID); err != nil {
		return "", err
	}

	requiredScopes := normalizeScopes(scopes)
	if len(requiredScopes) == 0 {
		requiredScopes = BaseDelegatedScopes
	}

	if cache.AccessToken != "" &&
		cache.ExpiresAt.After(m.nowUTC().Add(30*time.Second)) &&
		scopeStringCoversRequiredScopes(cache.Scope, requiredScopes) {
		return cache.AccessToken, nil
	}

	if useWAM() {
		return m.acquireDelegatedTokenWAM(ctx, profileName, clientID, authority, requiredScopes, expectedAccountID, expectedTenantID)
	}

	return m.acquireDelegatedTokenRefresh(ctx, profileName, clientID, authority, requiredScopes, cache, expectedAccountID, expectedTenantID)
}

func (m *Manager) acquireDelegatedTokenWAM(
	ctx context.Context,
	profileName string,
	clientID string,
	authority string,
	scopes []string,
	expectedAccountID string,
	expectedTenantID string,
) (string, error) {
	cache, _ := m.loadToken(profileName)
	cachedAccount := accountFromWAMResponse(WAMResponse{IDToken: cache.IDToken})
	requestAccountID := firstNonEmpty(expectedAccountID, cachedAccount.AccountID)
	requestUsername := cachedAccount.Username
	if requestAccountID == "" && requestUsername == "" {
		return "", errfmt.NewUserFacingError(
			fmt.Sprintf(
				"cached delegated login for profile %s is missing account identity. Run `mog auth login --profile %s ...` to sign in again.",
				profileName,
				profileName,
			),
			nil,
		)
	}

	resp, err := m.invokeWAM(ctx, WAMRequest{
		Action:    "acquire_silent",
		ClientID:  clientID,
		Authority: normalizeAuthority(authority),
		Scopes:    scopes,
		AccountID: requestAccountID,
		Username:  requestUsername,
	})
	if err != nil {
		return "", fmt.Errorf("WAM silent token acquisition failed: %w. Run `mog auth login` to sign in again", err)
	}
	if strings.TrimSpace(resp.AccessToken) == "" {
		return "", errors.New("WAM silent token response missing access_token")
	}
	if requestAccountID != "" && strings.TrimSpace(resp.AccountID) != "" && !strings.EqualFold(requestAccountID, strings.TrimSpace(resp.AccountID)) {
		return "", errfmt.NewUserFacingError(
			fmt.Sprintf(
				"WAM returned a different account for profile %s. Run `mog auth login --profile %s ...` to sign in again.",
				profileName,
				profileName,
			),
			nil,
		)
	}
	if requestUsername != "" && strings.TrimSpace(resp.Username) != "" && !strings.EqualFold(requestUsername, strings.TrimSpace(resp.Username)) {
		return "", errfmt.NewUserFacingError(
			fmt.Sprintf(
				"WAM returned a different user for profile %s. Run `mog auth login --profile %s ...` to sign in again.",
				profileName,
				profileName,
			),
			nil,
		)
	}
	expiresIn := resp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600
	}

	updated := TokenCache{
		AccessToken: resp.AccessToken,
		TokenType:   resp.TokenType,
		Scope:       resp.Scope,
		ExpiresAt:   m.nowUTC().Add(time.Duration(expiresIn) * time.Second),
		IDToken:     resp.IDToken,
	}
	if updated.IDToken == "" {
		updated.IDToken = cache.IDToken
	}
	if strings.TrimSpace(updated.Scope) == "" {
		updated.Scope = cache.Scope
	}

	if err := m.validateCachedDelegatedIdentity(profileName, updated, expectedAccountID, expectedTenantID); err != nil {
		return "", err
	}

	if err := m.saveToken(profileName, updated); err != nil {
		return "", err
	}

	return updated.AccessToken, nil
}

func (m *Manager) acquireDelegatedTokenRefresh(
	ctx context.Context,
	profileName string,
	clientID string,
	authority string,
	scopes []string,
	cache TokenCache,
	expectedAccountID string,
	expectedTenantID string,
) (string, error) {
	if strings.TrimSpace(cache.RefreshToken) == "" {
		return "", ErrMissingRefreshToken
	}

	// Use .default scope for refresh when the cached token was obtained via
	// .default. This avoids AADSTS65001 consent errors when the original
	// token was granted with .default but individual scopes (Mail.Read, etc.)
	// were never individually consented.
	refreshScope := strings.Join(scopes, " ")
	if strings.Contains(strings.ToLower(cache.Scope), "/.default") {
		refreshScope = "offline_access openid profile " + graphDefaultScope()
	}

	req := url.Values{}
	req.Set("grant_type", "refresh_token")
	req.Set("client_id", clientID)
	req.Set("refresh_token", cache.RefreshToken)
	req.Set("scope", refreshScope)

	// Include client_secret for confidential client apps if one is stored.
	if secretKey, err := delegatedSecretKey(profileName); err == nil {
		if secret, err := secrets.GetSecret(secretKey); err == nil && len(secret) > 0 {
			req.Set("client_secret", string(secret))
			secureZero(secret)
		}
	}

	body, status, err := m.doFormWithStatus(ctx, endpoint(authority, "/oauth2/v2.0/token"), req)
	if err != nil {
		return "", err
	}
	defer secureZero(body)
	if status != http.StatusOK {
		var oe oauthErrorResponse
		_ = json.Unmarshal(body, &oe)
		return "", fmt.Errorf("refresh token failed (%s): %s", oe.Error, strings.TrimSpace(oe.ErrorDescription))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decode refresh token response: %w", err)
	}

	if tr.RefreshToken == "" {
		tr.RefreshToken = cache.RefreshToken
	}
	if strings.TrimSpace(tr.Scope) == "" {
		tr.Scope = cache.Scope
	}
	updated := TokenCache{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Scope:        tr.Scope,
		ExpiresAt:    m.nowUTC().Add(time.Duration(tr.ExpiresIn) * time.Second),
		IDToken:      tr.IDToken,
	}
	if updated.IDToken == "" {
		updated.IDToken = cache.IDToken
	}
	if err := m.validateCachedDelegatedIdentity(profileName, updated, expectedAccountID, expectedTenantID); err != nil {
		return "", err
	}

	if err := m.saveToken(profileName, updated); err != nil {
		return "", err
	}

	return updated.AccessToken, nil
}

func (m *Manager) AcquireAppOnlyToken(ctx context.Context, profileName string, clientID string, authority string) (string, error) {
	secretKey, err := appSecretKey(profileName)
	if err != nil {
		return "", err
	}

	secret, err := secrets.GetSecret(secretKey)
	if err != nil {
		return "", fmt.Errorf("read client secret: %w", err)
	}
	defer secureZero(secret)
	if len(secret) == 0 {
		return "", ErrMissingSecret
	}

	req := url.Values{}
	req.Set("grant_type", "client_credentials")
	req.Set("client_id", clientID)
	req.Set("client_secret", string(secret))
	req.Set("scope", graphDefaultScope())

	body, status, err := m.doFormWithStatus(ctx, endpoint(authority, "/oauth2/v2.0/token"), req)
	if err != nil {
		return "", err
	}
	defer secureZero(body)

	if status != http.StatusOK {
		var oe oauthErrorResponse
		_ = json.Unmarshal(body, &oe)
		return "", fmt.Errorf("app-only token request failed (%s): %s", oe.Error, strings.TrimSpace(oe.ErrorDescription))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decode app-only token response: %w", err)
	}

	return tr.AccessToken, nil
}

func (m *Manager) ReadAccount(profileName string) (AccountInfo, error) {
	cache, err := m.loadToken(profileName)
	if err != nil {
		return AccountInfo{}, err
	}

	claims, err := parseIDClaims(cache.IDToken)
	if err != nil {
		return AccountInfo{}, err
	}

	return accountFromClaims(claims), nil
}

func (m *Manager) Logout(profileName string) error {
	cacheKey, err := tokenCacheKey(profileName)
	if err != nil {
		return err
	}
	if err := secrets.DeleteSecret(cacheKey); err != nil {
		return err
	}

	secretKey, err := appSecretKey(profileName)
	if err != nil {
		return err
	}
	if err := secrets.DeleteSecret(secretKey); err != nil {
		return err
	}

	// Clean up delegated client secret if stored.
	if delSecretKey, err := delegatedSecretKey(profileName); err == nil {
		_ = secrets.DeleteSecret(delSecretKey)
	}

	return nil
}

func (m *Manager) validateCachedDelegatedIdentity(
	profileName string,
	cache TokenCache,
	expectedAccountID string,
	expectedTenantID string,
) error {
	expectedAccountID = strings.TrimSpace(expectedAccountID)
	expectedTenantID = strings.TrimSpace(expectedTenantID)
	if expectedAccountID == "" && expectedTenantID == "" {
		return nil
	}

	claims, err := parseIDClaims(cache.IDToken)
	if err != nil {
		if purgeErr := m.purgeDelegatedTokenCache(profileName); purgeErr != nil {
			return purgeErr
		}
		return errfmt.NewUserFacingError(
			fmt.Sprintf(
				"cached delegated login for profile %s is invalid. Run `mog auth login --profile %s ...` to sign in again.",
				profileName,
				profileName,
			),
			err,
		)
	}

	account := accountFromClaims(claims)
	if expectedAccountID != "" && !strings.EqualFold(strings.TrimSpace(account.AccountID), expectedAccountID) {
		if purgeErr := m.purgeDelegatedTokenCache(profileName); purgeErr != nil {
			return purgeErr
		}
		return errfmt.NewUserFacingError(
			fmt.Sprintf(
				"cached delegated login for profile %s does not match the saved account. Run `mog auth login --profile %s ...` to sign in again.",
				profileName,
				profileName,
			),
			nil,
		)
	}

	if expectedTenantID != "" && !tenantIDsMatch(expectedTenantID, account.TenantID) {
		if purgeErr := m.purgeDelegatedTokenCache(profileName); purgeErr != nil {
			return purgeErr
		}
		return errfmt.NewUserFacingError(
			fmt.Sprintf(
				"cached delegated login for profile %s does not match the saved tenant. Run `mog auth login --profile %s ...` to sign in again.",
				profileName,
				profileName,
			),
			nil,
		)
	}

	return nil
}

func tenantIDsMatch(expectedTenantID string, actualTenantID string) bool {
	expected := strings.TrimSpace(expectedTenantID)
	actual := strings.TrimSpace(actualTenantID)

	if expected == "" {
		return true
	}
	if strings.EqualFold(expected, actual) {
		return true
	}
	if looksLikeGUID(expected) {
		return false
	}
	if !looksLikeTenantDomain(expected) {
		return false
	}

	// Tenant domains are valid profile inputs, but ID tokens expose tenant IDs in the
	// tid claim. If expected is a domain, we can only require a non-empty tenant claim.
	return actual != ""
}

func looksLikeGUID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 36 {
		return false
	}

	for i := 0; i < len(value); i++ {
		switch i {
		case 8, 13, 18, 23:
			if value[i] != '-' {
				return false
			}
		default:
			if !isHexByte(value[i]) {
				return false
			}
		}
	}

	return true
}

func isHexByte(value byte) bool {
	return (value >= '0' && value <= '9') ||
		(value >= 'a' && value <= 'f') ||
		(value >= 'A' && value <= 'F')
}

func looksLikeTenantDomain(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if !strings.Contains(value, ".") || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}

	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' {
			continue
		}
		return false
	}

	return true
}

func (m *Manager) purgeDelegatedTokenCache(profileName string) error {
	cacheKey, err := tokenCacheKey(profileName)
	if err != nil {
		return err
	}
	if err := secrets.DeleteSecret(cacheKey); err != nil {
		return fmt.Errorf("purge delegated token cache: %w", err)
	}
	return nil
}

func (m *Manager) saveToken(profileName string, cache TokenCache) error {
	payload, err := json.Marshal(cache)
	if err != nil {
		return fmt.Errorf("encode token cache: %w", err)
	}
	defer secureZero(payload)

	cacheKey, err := tokenCacheKey(profileName)
	if err != nil {
		return err
	}

	if err := secrets.SetSecret(cacheKey, payload); err != nil {
		return fmt.Errorf("store token cache: %w", err)
	}

	return nil
}

func (m *Manager) loadToken(profileName string) (TokenCache, error) {
	cacheKey, err := tokenCacheKey(profileName)
	if err != nil {
		return TokenCache{}, err
	}

	payload, err := secrets.GetSecret(cacheKey)
	if err != nil {
		return TokenCache{}, fmt.Errorf("read token cache: %w", err)
	}
	defer secureZero(payload)

	var cache TokenCache
	if err := json.Unmarshal(payload, &cache); err != nil {
		return TokenCache{}, fmt.Errorf("decode token cache: %w", err)
	}

	return cache, nil
}

func parseIDClaims(idToken string) (idClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return idClaims{}, errors.New("invalid id token")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return idClaims{}, fmt.Errorf("decode id token payload: %w", err)
	}

	var claims idClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return idClaims{}, fmt.Errorf("decode id token claims: %w", err)
	}

	return claims, nil
}

func accountFromClaims(claims idClaims) AccountInfo {
	accountID := strings.TrimSpace(claims.OID)
	if accountID == "" {
		accountID = strings.TrimSpace(claims.Sub)
	}

	username := strings.TrimSpace(claims.PreferredUsername)
	if username == "" {
		username = strings.TrimSpace(claims.Email)
	}
	if username == "" {
		username = strings.TrimSpace(claims.UPN)
	}

	return AccountInfo{
		AccountID: accountID,
		Username:  username,
		TenantID:  strings.TrimSpace(claims.TID),
	}
}

func accountFromWAMResponse(resp WAMResponse) AccountInfo {
	account := AccountInfo{
		AccountID: strings.TrimSpace(resp.AccountID),
		Username:  strings.TrimSpace(resp.Username),
		TenantID:  strings.TrimSpace(resp.TenantID),
	}
	if resp.IDTokenClaims != nil {
		account.AccountID = firstNonEmpty(account.AccountID, resp.IDTokenClaims.OID, resp.IDTokenClaims.Sub)
		account.Username = firstNonEmpty(account.Username, resp.IDTokenClaims.PreferredUsername, resp.IDTokenClaims.Email, resp.IDTokenClaims.UPN)
		account.TenantID = firstNonEmpty(account.TenantID, resp.IDTokenClaims.TID)
	}
	if strings.TrimSpace(resp.IDToken) != "" {
		if claims, err := parseIDClaims(resp.IDToken); err == nil {
			parsed := accountFromClaims(claims)
			account.AccountID = firstNonEmpty(account.AccountID, parsed.AccountID)
			account.Username = firstNonEmpty(account.Username, parsed.Username)
			account.TenantID = firstNonEmpty(account.TenantID, parsed.TenantID)
		}
	}

	return account
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}

	return ""
}

func (m *Manager) doForm(ctx context.Context, endpoint string, form url.Values) ([]byte, error) {
	body, status, err := m.doFormWithStatus(ctx, endpoint, form)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		var oe oauthErrorResponse
		_ = json.Unmarshal(body, &oe)
		return nil, fmt.Errorf("oauth request failed (%s): %s", oe.Error, strings.TrimSpace(oe.ErrorDescription))
	}

	return body, nil
}

func (m *Manager) doFormWithStatus(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("build oauth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("oauth request: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read oauth response: %w", err)
	}

	return b, resp.StatusCode, nil
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	t := time.NewTimer(delay)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func secureZero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
