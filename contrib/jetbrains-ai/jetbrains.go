package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MoeForge/moego/base64"
)

// JetBrains endpoints. They are variables so tests can point them at a local server.
// Nothing here is a documented public API; the requests follow what the Junie CLI and
// JetBrains AI Assistant send, as observed in open-source clients (see README.md).
var (
	authorizeURL = "https://junie.jetbrains.com/cli-auth"
	accountBase  = "https://oauth.account.jetbrains.com"
	cloudBase    = "https://api.jetbrains.cloud"
	aiBase       = "https://api.jetbrains.ai"
)

const (
	// clientID is the public OAuth client of the Junie CLI. Its registered redirect is
	// http://localhost:<port> with no path, on one of the ports 62345 to 62364.
	clientID     = "junie-cli"
	oauthScope   = "offline_access openid jb-authn-service"
	redirectURI  = "http://localhost:62345"
	agentHeader  = `{"name":"cliproxyapi-jetbrains-ai","version":"` + pluginVersion + `"}`
	userAudience = "jcp-user-management"
)

// authHTTP is used only while acquiring credentials, so it may carry a timeout.
var authHTTP = &http.Client{Timeout: 30 * time.Second}

// upstreamHTTP serves model requests. It has no timeout: a stream may run for a long time.
var upstreamHTTP = &http.Client{}

// statusError is an HTTP failure from JetBrains, kept with its status for the host.
type statusError struct {
	Status     int
	Body       string
	RetryAfter time.Duration
}

func (e *statusError) Error() string {
	return fmt.Sprintf("jetbrains: HTTP %d: %s", e.Status, truncate(e.Body, 300))
}

type tokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// exchangeCode trades the authorization code for JetBrains Account tokens.
func exchangeCode(ctx context.Context, code, verifier, redirect string) (tokenSet, error) {
	return postToken(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})
}

// refreshTokens refreshes the ID token. The response may rotate the refresh token.
func refreshTokens(ctx context.Context, refreshToken string) (tokenSet, error) {
	return postToken(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
}

// switchAudience returns a short-lived access token for another JetBrains service.
// Like the Junie CLI, any refresh token it returns is not kept.
func switchAudience(ctx context.Context, refreshToken, audience string) (string, error) {
	tokens, err := postToken(ctx, url.Values{
		"grant_type":    {"switch_audience"},
		"refresh_token": {refreshToken},
		"audience":      {audience},
		"client_id":     {clientID},
	})
	if err != nil {
		return "", err
	}
	if tokens.AccessToken == "" {
		return "", fmt.Errorf("jetbrains: switch_audience returned no access token")
	}
	return tokens.AccessToken, nil
}

func postToken(ctx context.Context, form url.Values) (tokenSet, error) {
	var tokens tokenSet
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, accountBase+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return tokens, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	body, err := doJSON(authHTTP, req)
	if err != nil {
		return tokens, fmt.Errorf("jetbrains token (%s): %w", form.Get("grant_type"), err)
	}
	if err = json.Unmarshal(body, &tokens); err != nil {
		return tokens, fmt.Errorf("decode jetbrains token: %w", err)
	}
	return tokens, nil
}

type accessOption struct {
	Type          string `json:"type"`
	AIAccess      bool   `json:"aiAccessEnabled"`
	Name          string `json:"name"`
	Code          string `json:"code"`
	LicenseID     string `json:"licenseId"`
	LicensedTo    string `json:"licensedTo"`
	ValidThrough  string `json:"validThrough"`
	WorkspaceName string `json:"workspaceName"`
}

// findLicense picks the account's best personal JetBrains AI license.
func findLicense(ctx context.Context, refreshToken string) (accessOption, error) {
	token, err := switchAudience(ctx, refreshToken, userAudience)
	if err != nil {
		return accessOption{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cloudBase+"/user-management/api/ai-access-options", nil)
	if err != nil {
		return accessOption{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	body, err := doJSON(authHTTP, req)
	if err != nil {
		return accessOption{}, fmt.Errorf("jetbrains ai-access-options: %w", err)
	}
	var resp struct {
		Options []accessOption `json:"aiAccessOptions"`
	}
	if err = json.Unmarshal(body, &resp); err != nil {
		return accessOption{}, fmt.Errorf("decode ai-access-options: %w", err)
	}
	return pickLicense(resp.Options)
}

// pickLicense prefers an enabled paid license: Ultimate, then Pro, then any other.
// Workspace seats need a different token flow and are not supported yet.
func pickLicense(options []accessOption) (accessOption, error) {
	rank := func(code string) int {
		switch strings.ToUpper(code) {
		case "AIU", "AIPU":
			return 3
		case "AIP":
			return 2
		case "AIF":
			return 0
		default:
			return 1
		}
	}
	best := -1
	var chosen accessOption
	for _, option := range options {
		if option.Type != "license" || !option.AIAccess || option.LicenseID == "" {
			continue
		}
		if r := rank(option.Code); r > best {
			best, chosen = r, option
		}
	}
	if best < 0 {
		return accessOption{}, fmt.Errorf("no JetBrains AI license with AI access was found on this account")
	}
	return chosen, nil
}

// provideAccess exchanges the ID token and license for a JetBrains AI token. A new
// account is registered with JetBrains AI first when the exchange is refused.
func provideAccess(ctx context.Context, idToken, licenseID string) (string, error) {
	token, err := postProvideAccess(ctx, idToken, licenseID)
	if err == nil {
		return token, nil
	}
	if !isClientError(err) {
		return "", err
	}
	if errRegister := postIdentity(ctx, "/auth/jetbrains-jwt/register", idToken, []byte(`{}`)); errRegister != nil {
		return "", fmt.Errorf("%w (register: %v)", err, errRegister)
	}
	return postProvideAccess(ctx, idToken, licenseID)
}

func postProvideAccess(ctx context.Context, idToken, licenseID string) (string, error) {
	payload, _ := json.Marshal(map[string]string{"licenseId": licenseID})
	req, err := identityRequest(ctx, "/auth/jetbrains-jwt/provide-access/license/v2", idToken, payload)
	if err != nil {
		return "", err
	}
	body, err := doJSON(authHTTP, req)
	if err != nil {
		return "", fmt.Errorf("jetbrains provide-access: %w", err)
	}
	var resp struct {
		State string `json:"state"`
		Token string `json:"token"`
	}
	if err = json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode provide-access: %w", err)
	}
	if resp.Token == "" {
		return "", fmt.Errorf("jetbrains provide-access returned no token (state %q)", resp.State)
	}
	return resp.Token, nil
}

func postIdentity(ctx context.Context, path, idToken string, payload []byte) error {
	req, err := identityRequest(ctx, path, idToken, payload)
	if err != nil {
		return err
	}
	_, err = doJSON(authHTTP, req)
	return err
}

func identityRequest(ctx context.Context, path, idToken string, payload []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, aiBase+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// profile is one model entry of the JetBrains AI profiles list (v9).
type profile struct {
	ID              string   `json:"id"`
	Provider        string   `json:"provider"`
	ProviderModelID string   `json:"providerModelID"`
	ModelName       string   `json:"modelName"`
	ContextLimit    int64    `json:"contextLimit"`
	MaxOutputTokens int64    `json:"maxOutputTokens"`
	Features        []string `json:"features"`
	LifeCycle       struct {
		Deprecated bool `json:"deprecated"`
	} `json:"lifeCycle"`
}

func fetchProfiles(ctx context.Context, jwt string) ([]profile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, aiBase+"/user/v5/llm/profiles/v9", nil)
	if err != nil {
		return nil, err
	}
	setAIHeaders(req, jwt)
	body, err := doJSON(authHTTP, req)
	if err != nil {
		return nil, fmt.Errorf("jetbrains profiles: %w", err)
	}
	var resp struct {
		Profiles []profile `json:"profiles"`
	}
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode profiles: %w", err)
	}
	return resp.Profiles, nil
}

// quotaResetAfter reads when the license quota resets, for a cooldown after HTTP 477.
func quotaResetAfter(ctx context.Context, jwt string) (time.Duration, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, aiBase+"/user/v5/quota/get", strings.NewReader(`{}`))
	if err != nil {
		return 0, false
	}
	setAIHeaders(req, jwt)
	body, err := doJSON(authHTTP, req)
	if err != nil {
		return 0, false
	}
	var resp struct {
		Current struct {
			Until int64 `json:"until"`
		} `json:"current"`
	}
	if json.Unmarshal(body, &resp) != nil || resp.Current.Until <= 0 {
		return 0, false
	}
	wait := time.Until(time.UnixMilli(resp.Current.Until))
	if wait <= 0 {
		return 0, false
	}
	return wait, true
}

func setAIHeaders(req *http.Request, jwt string) {
	req.Header.Set("Grazie-Authenticate-JWT", jwt)
	req.Header.Set("Grazie-Agent", agentHeader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
}

func doJSON(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &statusError{Status: resp.StatusCode, Body: string(body)}
	}
	return body, nil
}

func isClientError(err error) bool {
	var status *statusError
	return errors.As(err, &status) && status.Status >= 400 && status.Status < 500
}

// jwtClaims decodes a JWT payload without verifying it. It is only used to read the
// expiry and e-mail of tokens this plugin just received from JetBrains.
func jwtClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil
	}
	return claims
}

func jwtExpiry(token string, fallback time.Duration) time.Time {
	if exp, ok := jwtClaims(token)["exp"].(float64); ok && exp > 0 {
		return time.Unix(int64(exp), 0)
	}
	return time.Now().Add(fallback)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
