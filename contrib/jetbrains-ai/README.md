# JetBrains AI plugin

A CLIProxyAPI plugin that serves Claude models from your own JetBrains AI subscription (AI Pro or AI Ultimate). It adds:

- an OAuth sign-in with your JetBrains Account, started from the management UI like the built-in providers;
- automatic discovery of the account's JetBrains AI license;
- token refresh;
- the account's Claude models, under their Anthropic ids (for example `claude-opus-5-5`). The proxy pools them with any other provider of the same model, so round-robin and failover include this account;
- an executor that forwards requests to JetBrains AI's native Anthropic Messages endpoint.

Clients in other formats (OpenAI chat completions, Responses) work through the host's translators.

## Limits

- Only Claude models are served. JetBrains AI's OpenAI, Google and xAI models are not listed yet.
- Only personal licenses work. Organisation workspace seats need another token flow.
- Token counting returns 501.
- None of the JetBrains endpoints are documented public APIs. The requests follow the Junie CLI and AI Assistant, as seen in open-source clients:
  - `rock3r/headroom`: OAuth with the `junie-cli` client, license lookup and access exchange;
  - `RoadToNowhereX/jb-ai-proxy`: the native Anthropic endpoint and HTTP 477.

  They can change without notice.
- Use it only with your own subscription. JetBrains' AI terms forbid giving third parties access to it.

## Build

```sh
cd contrib/jetbrains-ai
go test ./...
CGO_ENABLED=1 go build -buildmode=c-shared -o jetbrains-ai.so .
```

## Enable

Put `jetbrains-ai.so` in the plugin directory and enable it:

```yaml
plugins:
  enabled: true
  dir: "/CLIProxyAPI/plugins"
  configs:
    jetbrains-ai:
      enabled: true
```

## Sign in

1. Open the management UI, go to OAuth login and choose **JetBrains AI**.
2. Sign in to your JetBrains Account in the window that opens.
3. JetBrains redirects to `http://localhost:62345/?code=…&state=…`. The page does not load unless the proxy runs on the same machine, which is expected.
4. Copy that full address from the browser's address bar and paste it into the management UI's callback field.

The plugin then:
1. exchanges the code;
2. finds your best enabled license (Ultimate before Pro);
3. saves `jetbrains-ai-<email>.json` in the auth directory.

## Failover

| JetBrains answer | Reported to the host as | Effect |
|---|---|---|
| HTTP 477 (quota used up) | 429 | Cooldown until the quota reset time from `/user/v5/quota/get`, or one hour if that is unknown. Round-robin moves on to the next account. |
| 401 | 401 if renewing fails | The plugin renews the JetBrains AI token once and retries first. |
| 451 (region blocked) | 403 | |
