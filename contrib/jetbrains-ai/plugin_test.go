package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/base64"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func fakeJWT(claims map[string]any) string {
	raw, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

// fakeJetBrains serves the account, cloud and AI endpoints the plugin calls.
type fakeJetBrains struct {
	t            *testing.T
	server       *httptest.Server
	accessCalls  atomic.Int32
	messageCalls atomic.Int32
	// messages answers the Anthropic endpoint; nil streams a short reply.
	messages func(w http.ResponseWriter, r *http.Request, call int32)
	mu       sync.Mutex
	lastBody map[string]any
	lastJWT  string
}

func newFake(t *testing.T) *fakeJetBrains {
	f := &fakeJetBrains{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", f.token)
	mux.HandleFunc("/user-management/api/ai-access-options", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer um-access" {
			http.Error(w, "bad audience token", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"aiAccessOptions":[
			{"type":"license","aiAccessEnabled":true,"name":"AI Free","code":"AIF","licenseId":"FREE1"},
			{"type":"workspace","aiAccessEnabled":true,"workspaceName":"Team"},
			{"type":"license","aiAccessEnabled":true,"name":"AI Ultimate","code":"AIU","licenseId":"ULT1"},
			{"type":"license","aiAccessEnabled":false,"name":"AI Pro","code":"AIP","licenseId":"OFF1"}]}`)
	})
	mux.HandleFunc("/auth/jetbrains-jwt/provide-access/license/v2", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["licenseId"] != "ULT1" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer e30.") {
			http.Error(w, "wrong license or token", http.StatusBadRequest)
			return
		}
		n := f.accessCalls.Add(1)
		jwt := fakeJWT(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "n": n})
		fmt.Fprintf(w, `{"state":"PAID","token":%q}`, jwt)
	})
	mux.HandleFunc("/user/v5/llm/profiles/v9", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"profiles":[
			{"id":"anthropic-claude-opus-5-5","provider":"Anthropic","providerModelID":"claude-opus-5-5","modelName":"Claude Opus 5.5","contextLimit":1000000,"maxOutputTokens":64000,"features":["Chat"]},
			{"id":"anthropic-claude-4-sonnet","provider":"Anthropic","providerModelID":"claude-sonnet-4-20250514","features":["Chat"],"lifeCycle":{"deprecated":true}},
			{"id":"openai-gpt-6-astra","provider":"OpenAI","providerModelID":"gpt-6-astra","features":["Chat"]},
			{"id":"anthropic-embed","provider":"Anthropic","providerModelID":"claude-embed","features":["Embeddings"]}]}`)
	})
	mux.HandleFunc("/user/v5/quota/get", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"current":{"until":%d}}`, time.Now().Add(48*time.Hour).UnixMilli())
	})
	mux.HandleFunc(messagesPath, func(w http.ResponseWriter, r *http.Request) {
		n := f.messageCalls.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.lastBody, f.lastJWT = body, r.Header.Get("Grazie-Authenticate-JWT")
		f.mu.Unlock()
		if r.Header.Get("Grazie-Agent") == "" {
			http.Error(w, "missing agent", http.StatusBadRequest)
			return
		}
		if f.messages != nil {
			f.messages(w, r, n)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n")
		fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	accountBase, cloudBase, aiBase = f.server.URL, f.server.URL, f.server.URL
	cache.Lock()
	cache.byAuth = map[string]credential{}
	cache.Unlock()
	return f
}

func (f *fakeJetBrains) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.Form.Get("client_id") != clientID {
		http.Error(w, "bad client", http.StatusBadRequest)
		return
	}
	idToken := fakeJWT(map[string]any{"email": "Dev@Example.com", "exp": time.Now().Add(time.Hour).Unix()})
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		if r.Form.Get("code") != "the-code" || r.Form.Get("code_verifier") == "" || r.Form.Get("redirect_uri") != redirectURI {
			http.Error(w, "bad code exchange", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, `{"access_token":"a","refresh_token":"rt-1","id_token":%q,"expires_in":3600}`, idToken)
	case "refresh_token":
		fmt.Fprintf(w, `{"access_token":"a","refresh_token":"rt-2","id_token":%q,"expires_in":3600}`, idToken)
	case "switch_audience":
		if r.Form.Get("audience") != userAudience {
			http.Error(w, "bad audience", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `{"access_token":"um-access","expires_in":300}`)
	default:
		http.Error(w, "unsupported grant", http.StatusBadRequest)
	}
}

func call(t *testing.T, method string, req any) envelope {
	t.Helper()
	raw, _ := json.Marshal(req)
	out, err := handleMethod(method, raw)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("%s: decode envelope: %v", method, err)
	}
	return env
}

func decode[T any](t *testing.T, env envelope) T {
	t.Helper()
	var v T
	if !env.OK {
		t.Fatalf("envelope error: %+v", env.Error)
	}
	if err := json.Unmarshal(env.Result, &v); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return v
}

// signIn runs start and poll the way the management UI drives them and returns the auth.
func signIn(t *testing.T) pluginapi.AuthData {
	t.Helper()
	start := decode[pluginapi.AuthLoginStartResponse](t, call(t, pluginabi.MethodAuthLoginStart, pluginapi.AuthLoginStartRequest{Provider: providerID}))
	u, err := url.Parse(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != clientID || q.Get("redirect_uri") != redirectURI || q.Get("code_challenge_method") != "S256" || q.Get("state") != start.State {
		t.Fatalf("authorize URL = %s", start.URL)
	}
	dir := t.TempDir()
	poll := pluginapi.AuthLoginPollRequest{Provider: providerID, State: start.State, Host: pluginapi.HostConfigSummary{AuthDir: dir}, Metadata: start.Metadata}
	if got := decode[pluginapi.AuthLoginPollResponse](t, call(t, pluginabi.MethodAuthLoginPoll, poll)); got.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("poll before callback = %+v, want pending", got)
	}
	cb, _ := json.Marshal(callbackFile{Code: "the-code", State: start.State})
	if err := os.WriteFile(filepath.Join(dir, ".oauth-"+providerID+"-"+start.State+".oauth"), cb, 0o600); err != nil {
		t.Fatal(err)
	}
	done := decode[pluginapi.AuthLoginPollResponse](t, call(t, pluginabi.MethodAuthLoginPoll, poll))
	if done.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("poll after callback = %+v", done)
	}
	return done.Auth
}

func TestSignInFindsBestLicenseAndStoresCredential(t *testing.T) {
	newFake(t)
	auth := signIn(t)
	if auth.Provider != providerID || auth.FileName != "jetbrains-ai-dev@example.com.json" || auth.Label != "Dev@Example.com" {
		t.Fatalf("auth = %+v", auth)
	}
	c, err := decodeCredential(auth.StorageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if c.LicenseID != "ULT1" || c.RefreshToken != "rt-1" || c.GrazieJWT == "" || !c.fresh(time.Now()) {
		t.Fatalf("credential = %+v", c)
	}
	if !auth.NextRefreshAfter.Before(c.GrazieJWTExpiry) {
		t.Fatalf("NextRefreshAfter %v is not before the token expiry %v", auth.NextRefreshAfter, c.GrazieJWTExpiry)
	}
	parsed := decode[pluginapi.AuthParseResponse](t, call(t, pluginabi.MethodAuthParse, pluginapi.AuthParseRequest{FileName: "x.json", RawJSON: auth.StorageJSON}))
	if !parsed.Handled || parsed.Auth.ID != "x.json" {
		t.Fatalf("parse = %+v", parsed)
	}
	other := decode[pluginapi.AuthParseResponse](t, call(t, pluginabi.MethodAuthParse, pluginapi.AuthParseRequest{RawJSON: []byte(`{"type":"claude"}`)}))
	if other.Handled {
		t.Fatal("a foreign auth file was claimed")
	}
}

func TestSignInRejectsWrongStateAndErrors(t *testing.T) {
	newFake(t)
	dir := t.TempDir()
	for name, cb := range map[string]callbackFile{
		"other state": {Code: "the-code", State: "someone-else"},
		"denied":      {Error: "access_denied"},
	} {
		raw, _ := json.Marshal(cb)
		_ = os.WriteFile(filepath.Join(dir, ".oauth-"+providerID+"-s1.oauth"), raw, 0o600)
		got := pollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: "s1", Host: pluginapi.HostConfigSummary{AuthDir: dir}, Metadata: map[string]any{"code_verifier": "v"}})
		if got.Status != pluginapi.AuthLoginStatusError {
			t.Errorf("%s: status = %s, want error", name, got.Status)
		}
	}
}

func TestPickLicense(t *testing.T) {
	if _, err := pickLicense([]accessOption{{Type: "workspace", AIAccess: true}}); err == nil {
		t.Fatal("workspace-only account should have no license")
	}
	got, err := pickLicense([]accessOption{{Type: "license", AIAccess: true, Code: "AIF", LicenseID: "F"}, {Type: "license", AIAccess: true, Code: "AIP", LicenseID: "P"}})
	if err != nil || got.LicenseID != "P" {
		t.Fatalf("pickLicense = %+v, %v; want Pro over Free", got, err)
	}
}

func TestModelsListOnlyCurrentClaudeChatModels(t *testing.T) {
	newFake(t)
	auth := signIn(t)
	resp := decode[pluginapi.ModelResponse](t, call(t, pluginabi.MethodModelForAuth, pluginapi.AuthModelRequest{AuthID: auth.ID, StorageJSON: auth.StorageJSON}))
	if len(resp.Models) != 1 || resp.Models[0].ID != "claude-opus-5-5" || resp.Models[0].ContextLength != 1000000 {
		t.Fatalf("models = %+v", resp.Models)
	}
}

func TestStreamForwardsEventsAndUsesModelID(t *testing.T) {
	f := newFake(t)
	auth := signIn(t)
	var mu sync.Mutex
	var chunks []string
	closed := make(chan streamClose, 1)
	hostCall = func(method string, payload any) (json.RawMessage, error) {
		switch method {
		case pluginabi.MethodHostStreamEmit:
			mu.Lock()
			chunks = append(chunks, string(payload.(streamEmit).Payload))
			mu.Unlock()
		case pluginabi.MethodHostStreamClose:
			closed <- payload.(streamClose)
		}
		return json.RawMessage(`{}`), nil
	}
	req := rpcExecutorRequest{StreamID: "st1", ExecutorRequest: pluginapi.ExecutorRequest{
		AuthID: auth.ID, Model: "claude-opus-5-5(high)", StorageJSON: auth.StorageJSON,
		Payload: []byte(`{"model":"whatever","stream":false,"max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`),
	}}
	if env := call(t, pluginabi.MethodExecutorExecuteStream, req); !env.OK {
		t.Fatalf("execute_stream = %+v", env.Error)
	}
	select {
	case c := <-closed:
		if c.Error != "" {
			t.Fatalf("stream closed with error %q", c.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream never closed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(chunks) != 3 || !strings.HasPrefix(chunks[0], "event: message_start\n") || !strings.HasSuffix(chunks[2], "\n\n") {
		t.Fatalf("chunks = %q", chunks)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastBody["model"] != "claude-opus-5-5" || f.lastBody["stream"] != true || f.lastBody["max_tokens"] != float64(10) {
		t.Fatalf("upstream body = %v", f.lastBody)
	}
}

func TestExpiredTokenIsRenewedAfter401(t *testing.T) {
	f := newFake(t)
	auth := signIn(t)
	f.messages = func(w http.ResponseWriter, r *http.Request, n int32) {
		if n == 1 {
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"type":"message","content":[{"type":"text","text":"ok"}]}`)
	}
	before := f.accessCalls.Load()
	env := call(t, pluginabi.MethodExecutorExecute, rpcExecutorRequest{ExecutorRequest: pluginapi.ExecutorRequest{
		AuthID: auth.ID, Model: "claude-opus-5-5", StorageJSON: auth.StorageJSON, Payload: []byte(`{"messages":[]}`),
	}})
	resp := decode[pluginapi.ExecutorResponse](t, env)
	if !strings.Contains(string(resp.Payload), `"ok"`) || f.messageCalls.Load() != 2 || f.accessCalls.Load() != before+1 {
		t.Fatalf("payload=%s messages=%d renewals=%d", resp.Payload, f.messageCalls.Load(), f.accessCalls.Load()-before)
	}
}

func TestQuotaExhaustedBecomes429WithCooldownUntilReset(t *testing.T) {
	f := newFake(t)
	auth := signIn(t)
	f.messages = func(w http.ResponseWriter, r *http.Request, _ int32) {
		w.WriteHeader(quotaExhausted)
		_, _ = io.WriteString(w, `{"error":"quota exceeded"}`)
	}
	env := call(t, pluginabi.MethodExecutorExecuteStream, rpcExecutorRequest{StreamID: "st2", ExecutorRequest: pluginapi.ExecutorRequest{
		AuthID: auth.ID, Model: "claude-opus-5-5", StorageJSON: auth.StorageJSON, Payload: []byte(`{"messages":[]}`),
	}})
	if env.OK || env.Error == nil || env.Error.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("envelope = %+v, want a 429 error", env)
	}
	if env.Error.RetryAfterSeconds < int64((47 * time.Hour).Seconds()) {
		t.Fatalf("retry_after_seconds = %d, want about 48h", env.Error.RetryAfterSeconds)
	}
}

func TestStreamWithoutMessageStopFails(t *testing.T) {
	err := streamResponse(strings.NewReader("event: message_start\ndata: {}\n\n"), func([]byte) error { return nil })
	if err == nil {
		t.Fatal("a truncated stream was accepted")
	}
}

func TestCountTokensIsNotImplemented(t *testing.T) {
	env := call(t, pluginabi.MethodExecutorCountTokens, rpcExecutorRequest{})
	if env.OK || env.Error.HTTPStatus != http.StatusNotImplemented {
		t.Fatalf("count_tokens = %+v", env)
	}
}

func TestRegistrationDeclaresClaudeExecutor(t *testing.T) {
	reg := decode[registration](t, call(t, pluginabi.MethodPluginRegister, map[string]any{}))
	if !reg.Capabilities.AuthProvider || !reg.Capabilities.Executor || reg.Capabilities.ExecutorInputFormats[0] != "claude" || reg.Capabilities.ExecutorModelScope != pluginapi.ExecutorModelScopeOAuth {
		t.Fatalf("registration = %+v", reg)
	}
	id := decode[identifierResponse](t, call(t, pluginabi.MethodAuthIdentifier, nil))
	if id.Identifier != providerID {
		t.Fatalf("identifier = %+v", id)
	}
}
