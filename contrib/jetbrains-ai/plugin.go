package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	providerID    = "jetbrains-ai"
	pluginVersion = "0.1.0"
)

// hostCall is set by the C ABI glue; tests replace it.
var hostCall func(method string, payload any) (json.RawMessage, error)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

// envelopeError carries http_status and retry_after_seconds, which the host turns into
// the status error that drives account cooldowns.
type envelopeError struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	HTTPStatus        int    `json:"http_status,omitempty"`
	RetryAfterSeconds int64  `json:"retry_after_seconds,omitempty"`
}

type registration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  capabilities       `json:"capabilities"`
}

type capabilities struct {
	ModelProvider         bool                         `json:"model_provider"`
	AuthProvider          bool                         `json:"auth_provider"`
	Executor              bool                         `json:"executor"`
	ExecutorModelScope    pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats  []string                     `json:"executor_input_formats"`
	ExecutorOutputFormats []string                     `json:"executor_output_formats"`
}

type identifierResponse struct {
	Identifier string                        `json:"identifier"`
	Entries    []pluginapi.AuthProviderEntry `json:"entries,omitempty"`
}

type rpcExecutorRequest struct {
	pluginapi.ExecutorRequest
	StreamID string `json:"stream_id,omitempty"`
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "JetBrains AI",
			Version:          pluginVersion,
			Author:           "tekn0ir",
			GitHubRepository: "https://github.com/tekn0ir/CLIProxyAPI",
		},
		Capabilities: capabilities{
			ModelProvider:         true,
			AuthProvider:          true,
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeOAuth,
			ExecutorInputFormats:  []string{"claude"},
			ExecutorOutputFormats: []string{"claude"},
		},
	}
}

func handleMethod(method string, request []byte) ([]byte, error) {
	ctx := context.Background()
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodAuthIdentifier, pluginabi.MethodExecutorIdentifier:
		return okEnvelope(identifierResponse{
			Identifier: providerID,
			Entries:    []pluginapi.AuthProviderEntry{{Identifier: providerID, Name: "JetBrains AI"}},
		})
	case pluginabi.MethodAuthParse:
		return parseAuth(request)
	case pluginabi.MethodAuthLoginStart:
		resp, err := startLogin()
		if err != nil {
			return nil, err
		}
		return okEnvelope(resp)
	case pluginabi.MethodAuthLoginPoll:
		var req pluginapi.AuthLoginPollRequest
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, err
		}
		return okEnvelope(pollLogin(ctx, req))
	case pluginabi.MethodAuthRefresh:
		return refreshAuth(ctx, request)
	case pluginabi.MethodModelStatic:
		return okEnvelope(pluginapi.ModelResponse{Provider: providerID})
	case pluginabi.MethodModelForAuth:
		return modelsForAuth(ctx, request)
	case pluginabi.MethodExecutorExecute:
		var req rpcExecutorRequest
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, err
		}
		resp, err := execute(ctx, req.ExecutorRequest)
		if err != nil {
			return failure(err), nil
		}
		return okEnvelope(resp)
	case pluginabi.MethodExecutorExecuteStream:
		return executeStream(ctx, request)
	case pluginabi.MethodExecutorCountTokens:
		// JetBrains AI has no token counting endpoint; 501 keeps the account available.
		return failure(&statusError{Status: http.StatusNotImplemented, Body: "token counting is not supported"}), nil
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func parseAuth(request []byte) ([]byte, error) {
	var req pluginapi.AuthParseRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	c, err := decodeCredential(req.RawJSON)
	if err != nil {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	data, err := authData(c)
	if err != nil {
		return nil, err
	}
	if req.FileName != "" {
		data.FileName, data.ID = req.FileName, req.FileName
	}
	return okEnvelope(pluginapi.AuthParseResponse{Handled: true, Auth: data})
}

func refreshAuth(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.AuthRefreshRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	c, err := currentCredential(ctx, req.AuthID, req.StorageJSON, true)
	if err != nil {
		return failure(&statusError{Status: http.StatusUnauthorized, Body: err.Error()}), nil
	}
	data, err := authData(c)
	if err != nil {
		return nil, err
	}
	data.ID = req.AuthID
	return okEnvelope(pluginapi.AuthRefreshResponse{Auth: data, NextRefreshAfter: c.nextRefresh()})
}

// modelsForAuth lists the account's Claude models under their Anthropic ids (for
// example claude-opus-5-5), so the host pools this account with other providers of the
// same model.
func modelsForAuth(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.AuthModelRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	c, err := currentCredential(ctx, req.AuthID, req.StorageJSON, false)
	if err != nil {
		return nil, err
	}
	profiles, err := fetchProfiles(ctx, c.GrazieJWT)
	if err != nil {
		return nil, err
	}
	return okEnvelope(pluginapi.ModelResponse{Provider: providerID, Models: claudeModels(profiles)})
}

func claudeModels(profiles []profile) []pluginapi.ModelInfo {
	seen := map[string]bool{}
	var models []pluginapi.ModelInfo
	for _, p := range profiles {
		id := strings.TrimSpace(p.ProviderModelID)
		if p.Provider != "Anthropic" || id == "" || p.LifeCycle.Deprecated || !hasFeature(p.Features, "Chat") || seen[id] {
			continue
		}
		seen[id] = true
		name := p.ModelName
		if name == "" {
			name = id
		}
		models = append(models, pluginapi.ModelInfo{
			ID:                  id,
			Object:              "model",
			OwnedBy:             "anthropic",
			Type:                "claude",
			DisplayName:         name + " (JetBrains AI)",
			Name:                id,
			ContextLength:       p.ContextLimit,
			InputTokenLimit:     p.ContextLimit,
			MaxCompletionTokens: p.MaxOutputTokens,
			OutputTokenLimit:    p.MaxOutputTokens,
		})
	}
	return models
}

func hasFeature(features []string, want string) bool {
	for _, f := range features {
		if strings.EqualFold(f, want) {
			return true
		}
	}
	return false
}

type streamEmit struct {
	StreamID string `json:"stream_id"`
	Payload  []byte `json:"payload,omitempty"`
}

type streamClose struct {
	StreamID    string         `json:"stream_id"`
	Error       string         `json:"error,omitempty"`
	ErrorDetail *envelopeError `json:"error_detail,omitempty"`
}

// executeStream sends the request before answering, so an upstream refusal (quota,
// auth) reaches the host as a status error it can fail over on. The body is then
// forwarded in the background through host.stream.emit.
func executeStream(ctx context.Context, request []byte) ([]byte, error) {
	var req rpcExecutorRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return nil, err
	}
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return errorEnvelope("executor_error", errNoStreamID.Error()), nil
	}
	resp, err := send(ctx, req.ExecutorRequest, true)
	if err != nil {
		return failure(err), nil
	}
	go func() {
		defer func() { _ = resp.Body.Close() }()
		errStream := streamResponse(resp.Body, func(chunk []byte) error {
			_, errEmit := hostCall(pluginabi.MethodHostStreamEmit, streamEmit{StreamID: streamID, Payload: chunk})
			return errEmit
		})
		closing := streamClose{StreamID: streamID}
		if errStream != nil {
			detail := errorDetail(errStream)
			closing.Error, closing.ErrorDetail = detail.Message, &detail
		}
		_, _ = hostCall(pluginabi.MethodHostStreamClose, closing)
	}()
	return okEnvelope(map[string]any{"headers": http.Header{"Content-Type": {"text/event-stream"}}})
}

func errorDetail(err error) envelopeError {
	detail := envelopeError{Code: "upstream_error", Message: err.Error()}
	var status *statusError
	if errors.As(err, &status) {
		detail.HTTPStatus = status.Status
		detail.Message = status.Body
		if status.RetryAfter > 0 {
			detail.RetryAfterSeconds = int64(status.RetryAfter.Seconds())
		}
		if status.Status == http.StatusTooManyRequests {
			detail.Code = "rate_limited"
		}
	}
	return detail
}

func failure(err error) []byte {
	detail := errorDetail(err)
	raw, _ := json.Marshal(envelope{OK: false, Error: &detail})
	return raw
}

func okEnvelope(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}
