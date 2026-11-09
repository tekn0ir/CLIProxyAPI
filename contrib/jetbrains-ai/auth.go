package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	// refreshMargin renews tokens this long before they expire.
	refreshMargin = 10 * time.Minute
	loginLifetime = 15 * time.Minute
)

// credential is the provider-owned JSON stored in the auth file.
type credential struct {
	Type            string    `json:"type"`
	Email           string    `json:"email,omitempty"`
	RefreshToken    string    `json:"refresh_token"`
	IDToken         string    `json:"id_token,omitempty"`
	IDTokenExpiry   time.Time `json:"id_token_expiry"`
	LicenseID       string    `json:"license_id"`
	LicenseName     string    `json:"license_name,omitempty"`
	GrazieJWT       string    `json:"grazie_jwt,omitempty"`
	GrazieJWTExpiry time.Time `json:"grazie_jwt_expiry"`
}

func (c credential) nextRefresh() time.Time {
	next := c.GrazieJWTExpiry
	if c.IDTokenExpiry.Before(next) {
		next = c.IDTokenExpiry
	}
	return next.Add(-refreshMargin)
}

// fresh reports whether the JetBrains AI token can still be used for a while.
func (c credential) fresh(now time.Time) bool {
	return c.GrazieJWT != "" && now.Add(refreshMargin/2).Before(c.GrazieJWTExpiry)
}

// renew refreshes the ID token when needed and exchanges it for a new JetBrains AI token.
func renew(ctx context.Context, c credential) (credential, error) {
	if c.RefreshToken == "" || c.LicenseID == "" {
		return c, errors.New("jetbrains credential is incomplete; sign in again")
	}
	if c.IDToken == "" || time.Now().Add(refreshMargin/2).After(c.IDTokenExpiry) {
		tokens, err := refreshTokens(ctx, c.RefreshToken)
		if err != nil {
			return c, err
		}
		if tokens.IDToken == "" {
			return c, errors.New("jetbrains refresh returned no id_token")
		}
		c.IDToken = tokens.IDToken
		c.IDTokenExpiry = jwtExpiry(tokens.IDToken, time.Duration(tokens.ExpiresIn)*time.Second)
		if tokens.RefreshToken != "" {
			c.RefreshToken = tokens.RefreshToken
		}
	}
	jwt, err := provideAccess(ctx, c.IDToken, c.LicenseID)
	if err != nil {
		return c, err
	}
	c.GrazieJWT = jwt
	c.GrazieJWTExpiry = jwtExpiry(jwt, time.Hour)
	return c, nil
}

// cache keeps the newest credential per auth, so requests between host refreshes reuse
// one JetBrains AI token instead of exchanging a new one each time.
var cache = struct {
	sync.Mutex
	byAuth map[string]credential
}{byAuth: map[string]credential{}}

// currentCredential returns a usable credential for an auth, renewing it when needed.
// forceRenew discards the JetBrains AI token, for example after HTTP 401.
func currentCredential(ctx context.Context, authID string, storage []byte, forceRenew bool) (credential, error) {
	stored, err := decodeCredential(storage)
	if err != nil {
		return credential{}, err
	}
	cache.Lock()
	defer cache.Unlock()
	c := stored
	if cached, ok := cache.byAuth[authID]; ok && cached.GrazieJWTExpiry.After(stored.GrazieJWTExpiry) {
		c = cached
	}
	if forceRenew {
		c.GrazieJWT = ""
	}
	if !c.fresh(time.Now()) {
		if c, err = renew(ctx, c); err != nil {
			return credential{}, err
		}
	}
	cache.byAuth[authID] = c
	return c, nil
}

func decodeCredential(storage []byte) (credential, error) {
	var c credential
	if err := json.Unmarshal(storage, &c); err != nil {
		return c, fmt.Errorf("decode jetbrains credential: %w", err)
	}
	if c.Type != providerID {
		return c, fmt.Errorf("auth file type %q is not %s", c.Type, providerID)
	}
	return c, nil
}

func authData(c credential) (pluginapi.AuthData, error) {
	storage, err := json.Marshal(c)
	if err != nil {
		return pluginapi.AuthData{}, err
	}
	name := providerID + "-" + fileSafe(c.Email) + ".json"
	return pluginapi.AuthData{
		Provider:         providerID,
		ID:               name,
		FileName:         name,
		Label:            c.Email,
		StorageJSON:      storage,
		Metadata:         map[string]any{"type": providerID, "email": c.Email, "license": c.LicenseName},
		NextRefreshAfter: c.nextRefresh(),
	}, nil
}

func fileSafe(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "account"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == '@':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// startLogin builds the JetBrains Account authorization URL with PKCE. The verifier
// travels in the session metadata, which the host returns on every poll.
func startLogin() (pluginapi.AuthLoginStartResponse, error) {
	state, err := randomHex(24)
	if err != nil {
		return pluginapi.AuthLoginStartResponse{}, err
	}
	verifier, err := randomHex(48)
	if err != nil {
		return pluginapi.AuthLoginStartResponse{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{
		"client_id":             {clientID},
		"scope":                 {oauthScope},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"redirect_uri":          {redirectURI},
	}
	return pluginapi.AuthLoginStartResponse{
		Provider:  providerID,
		URL:       authorizeURL + "?" + query.Encode(),
		State:     state,
		ExpiresAt: time.Now().Add(loginLifetime).UTC(),
		Metadata:  map[string]any{"code_verifier": verifier},
	}, nil
}

// pollLogin finishes the login once the management UI has stored the callback. The
// browser lands on http://localhost:62345/?code=…&state=…, which does not load on a
// remote proxy; the person pastes that address into the management UI, and the host
// writes it to .oauth-<provider>-<state>.oauth in the auth directory.
func pollLogin(ctx context.Context, req pluginapi.AuthLoginPollRequest) pluginapi.AuthLoginPollResponse {
	callback, ok, err := readCallback(req.Host.AuthDir, req.State)
	if err != nil {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: err.Error()}
	}
	if !ok {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending}
	}
	if callback.Error != "" {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "JetBrains sign-in failed: " + callback.Error}
	}
	if callback.State != "" && callback.State != req.State {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "state does not match this sign-in"}
	}
	verifier, _ := req.Metadata["code_verifier"].(string)
	if verifier == "" {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "sign-in session lost its PKCE verifier; start again"}
	}
	c, err := completeLogin(ctx, callback.Code, verifier)
	if err != nil {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: err.Error()}
	}
	data, err := authData(c)
	if err != nil {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: err.Error()}
	}
	return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusSuccess, Message: "Signed in as " + c.Email, Auth: data}
}

func completeLogin(ctx context.Context, code, verifier string) (credential, error) {
	tokens, err := exchangeCode(ctx, code, verifier, redirectURI)
	if err != nil {
		return credential{}, err
	}
	if tokens.RefreshToken == "" || tokens.IDToken == "" {
		return credential{}, errors.New("jetbrains sign-in returned no refresh token or id_token")
	}
	license, err := findLicense(ctx, tokens.RefreshToken)
	if err != nil {
		return credential{}, err
	}
	email, _ := jwtClaims(tokens.IDToken)["email"].(string)
	c := credential{
		Type:          providerID,
		Email:         email,
		RefreshToken:  tokens.RefreshToken,
		IDToken:       tokens.IDToken,
		IDTokenExpiry: jwtExpiry(tokens.IDToken, time.Duration(tokens.ExpiresIn)*time.Second),
		LicenseID:     license.LicenseID,
		LicenseName:   strings.TrimSpace(license.Name + " " + license.Code),
	}
	return renew(ctx, c)
}

type callbackFile struct {
	Code  string `json:"code"`
	State string `json:"state"`
	Error string `json:"error"`
}

func readCallback(authDir, state string) (callbackFile, bool, error) {
	var cb callbackFile
	if authDir == "" || state == "" || strings.ContainsAny(state, `/\`) {
		return cb, false, errors.New("invalid sign-in session")
	}
	path := filepath.Join(authDir, ".oauth-"+providerID+"-"+state+".oauth")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cb, false, nil
	}
	if err != nil {
		return cb, false, fmt.Errorf("read sign-in callback: %w", err)
	}
	_ = os.Remove(path)
	if err = json.Unmarshal(raw, &cb); err != nil {
		return cb, false, fmt.Errorf("decode sign-in callback: %w", err)
	}
	if cb.Code == "" && cb.Error == "" {
		return cb, false, errors.New("sign-in callback has no code")
	}
	return cb, true, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
