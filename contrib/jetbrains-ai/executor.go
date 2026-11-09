package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// messagesPath is JetBrains AI's native Anthropic Messages endpoint. It takes the
// Anthropic request shape with the provider's own model id, so Claude-format requests
// pass through unchanged; the host translates other client formats to and from it.
const messagesPath = "/user/v5/llm/anthropic/v1/messages"

// quotaExhausted is JetBrains AI's status for a license that has used up its credits.
const quotaExhausted = 477

// defaultQuotaCooldown applies when the quota reset time cannot be read.
const defaultQuotaCooldown = time.Hour

// upstreamModel strips a thinking suffix such as "(high)" from the requested model.
func upstreamModel(model string) string {
	if i := strings.IndexByte(model, '('); i > 0 {
		model = model[:i]
	}
	return strings.TrimSpace(model)
}

func buildBody(req pluginapi.ExecutorRequest, stream bool) ([]byte, error) {
	doc := ojson.NewDoc(req.Payload)
	if err := doc.Set("model", upstreamModel(req.Model)); err != nil {
		return nil, fmt.Errorf("set model: %w", err)
	}
	if err := doc.Set("stream", stream); err != nil {
		return nil, fmt.Errorf("set stream: %w", err)
	}
	return doc.Bytes(), nil
}

// send posts the request with the auth's JetBrains AI token. After HTTP 401 it renews
// the token once and retries. A non-2xx answer is returned as *statusError.
func send(ctx context.Context, req pluginapi.ExecutorRequest, stream bool) (*http.Response, error) {
	body, err := buildBody(req, stream)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		c, errCred := currentCredential(ctx, req.AuthID, req.StorageJSON, attempt > 0)
		if errCred != nil {
			return nil, &statusError{Status: http.StatusUnauthorized, Body: errCred.Error()}
		}
		httpReq, errReq := http.NewRequestWithContext(ctx, http.MethodPost, aiBase+messagesPath, bytes.NewReader(body))
		if errReq != nil {
			return nil, errReq
		}
		setAIHeaders(httpReq, c.GrazieJWT)
		httpReq.Header.Set("anthropic-version", headerOr(req.Headers, "anthropic-version", "2023-06-01"))
		if stream {
			httpReq.Header.Set("Accept", "text/event-stream")
		}
		resp, errDo := upstreamHTTP.Do(httpReq)
		if errDo != nil {
			return nil, errDo
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		return nil, upstreamError(ctx, resp.StatusCode, string(errBody), c.GrazieJWT)
	}
	return nil, &statusError{Status: http.StatusUnauthorized, Body: "jetbrains rejected the renewed token"}
}

// upstreamError maps JetBrains statuses to what the host's cooldowns understand, so
// round-robin moves on to another account: an exhausted quota becomes 429 with a
// cooldown until the quota resets, and a region block (451) becomes 403.
func upstreamError(ctx context.Context, status int, body, jwt string) *statusError {
	switch status {
	case quotaExhausted:
		wait, ok := quotaResetAfter(ctx, jwt)
		if !ok {
			wait = defaultQuotaCooldown
		}
		return &statusError{Status: http.StatusTooManyRequests, Body: "JetBrains AI quota exhausted: " + body, RetryAfter: wait}
	case http.StatusUnavailableForLegalReasons:
		return &statusError{Status: http.StatusForbidden, Body: "JetBrains AI is not available in this region: " + body}
	default:
		return &statusError{Status: status, Body: body}
	}
}

func headerOr(h http.Header, key, fallback string) string {
	if v := strings.TrimSpace(h.Get(key)); v != "" {
		return v
	}
	return fallback
}

func execute(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	resp, err := send(ctx, req, false)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return pluginapi.ExecutorResponse{}, fmt.Errorf("read jetbrains response: %w", err)
	}
	return pluginapi.ExecutorResponse{Payload: payload, Headers: http.Header{"Content-Type": {"application/json"}}}, nil
}

// streamResponse forwards the upstream SSE stream one complete event at a time,
// as the built-in Claude executor does. emit returns an error once the host has
// closed the stream, which ends the upstream read.
func streamResponse(body io.Reader, emit func([]byte) error) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(nil, 50<<20)
	var event bytes.Buffer
	sawStop := false
	flush := func() error {
		if event.Len() == 0 {
			return nil
		}
		if bytes.Contains(event.Bytes(), []byte("message_stop")) {
			sawStop = true
		}
		chunk := bytes.Clone(event.Bytes())
		event.Reset()
		return emit(chunk)
	}
	for scanner.Scan() {
		line := scanner.Bytes()
		event.Write(line)
		event.WriteByte('\n')
		if len(bytes.TrimSpace(line)) == 0 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read jetbrains stream: %w", err)
	}
	if event.Len() > 0 {
		event.WriteByte('\n')
		if err := flush(); err != nil {
			return err
		}
	}
	if !sawStop {
		return &statusError{Status: http.StatusBadGateway, Body: "jetbrains stream closed before message_stop"}
	}
	return nil
}

var errNoStreamID = errors.New("stream_id is required for executor.execute_stream")
