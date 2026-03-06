package auth

import "time"

type DelegatedLoginInput struct {
	ProfileName  string
	Audience     string
	ClientID     string
	Authority    string
	TenantID     string
	Scopes       []string
	Secret       string // Optional client secret for confidential client apps
	RefreshToken string // Optional pre-existing refresh token for headless login
}

type AppOnlyLoginInput struct {
	ProfileName string
	Audience    string
	ClientID    string
	Authority   string
	TenantID    string
	Secret      string
}

type TokenCache struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	IDToken      string    `json:"id_token,omitempty"`
}

type AccountInfo struct {
	AccountID string
	Username  string
	TenantID  string
}

type idClaims struct {
	OID               string `json:"oid"`
	Sub               string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	UPN               string `json:"upn"`
	TID               string `json:"tid"`
}
