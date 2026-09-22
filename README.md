# pi-jev-redact

`pi-jev-redact` is a [Pi coding harness](https://github.com/earendil-works/pi-mono) extension that replaces sensitive text with `<-REDACTED->` immediately before a provider request leaves your machine.

It protects text in the final serialized provider payload—including system prompts, conversation context, and tool results—while leaving Pi's local session history unchanged.

![pi-jev-redact detecting and replacing a demo OpenAI-style key before the provider request](docs/images/redaction-notification.png)

## Install

From npm:

```bash
pi install npm:pi-jev-redact
```

From GitHub:

```bash
pi install git:github.com/BubbatheVTOG/pi-jev-redact
```

Try it for one Pi process without installing:

```bash
pi -e npm:pi-jev-redact
```

## What it detects

Detection breadth follows a 1–10 `threshold` (higher means more sensitive):

- **1–3:** PEM private keys plus Anthropic/OpenAI-style keys;
- **4–6 (default 5):** all established secret rules, adding GitHub, Slack,
  Google API, and JSON Web Tokens;
- **7–8:** personal information, including email addresses, common US phone
  formats, US Social Security numbers, and payment-card-shaped values;
- **9–10:** network identifiers (IPv4 and MAC addresses) plus aggressive bearer
  token, URL credential, and generic secret-assignment patterns.

You can add exact literals, environment-variable values, and bounded regular
expressions. `builtins` and `pii` explicitly override the threshold-derived
secret/PII groups.

## Configuration

Create a global configuration at `~/.pi/agent/pi-redact.json`, or a project configuration at `.pi/pi-redact.json`. These filenames are retained for compatibility with existing installations. Project configuration is read only for trusted projects. When both exist, project booleans override global booleans and custom rules are combined.

```json
{
  "enabled": true,
  "threshold": 7,
  "builtins": true,
  "pii": true,
  "notify": true,
  "confirmIntent": true,
  "env": ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
  "literals": ["private.example.test"],
  "patterns": [
    {
      "pattern": "SECRET-[A-Z0-9]{12}"
    }
  ]
}
```

Prefer `env` rules for credentials. Do not commit literal secrets to a project configuration. Literal values must be at least four characters. Pattern rules are limited to 512 characters and reject backreferences, lookbehind, empty matches, and common nested-quantifier forms.

When redaction occurs, interactive Pi sessions receive a notification containing
only the replacement count and broad rule categories. With `confirmIntent`
(default `true`), each previously unseen sensitive span also prompts: approve to
send the redacted payload, or deny to censor the whole provider request. Decisions
are remembered by SHA-256 fingerprint, so the same span is not repeatedly asked
about. A previously denied span is silently censored if it reappears. Headless
sessions cannot prompt and proceed with the redacted payload.

The matched text is never written to disk. The decision cache stores only hashes,
timestamps, decisions, and category names; the optional request log in the next
section receives only the already-redacted payload.

Configuration changes take effect after `/reload` or a new Pi session.

## Logging

By default `pi-jev-redact` writes no files. To inspect exactly what leaves your machine, enable a per-session request log in Pi's `settings.json` (global: `~/.pi/agent/settings.json`; a project `.pi/settings.json` overrides key-by-key for trusted projects):

```json
{
  "piRedact": {
    "log": "report",
    "logDir": "/tmp/pi-redact",
    "logMaxBytes": 16777216,
    "decisionDir": "/private/cache/pi-jev-redact"
  }
}
```

- `log` — `"report"` writes metadata only: timestamp, session, cwd, replacement count, rule categories, and payload size in bytes. `"payload"` additionally includes the full redacted provider payload. `false` or an absent key disables logging.
- `logDir` — directory for per-session JSONL files, one line per provider request, named `<session-id>.jsonl`. Default `/tmp/pi-redact`. Files are created with `0600` permissions and the directory with `0700`.
- `logMaxBytes` — per-session file cap in bytes, default 16 MiB; `0` disables the cap. When the next entry would exceed the cap, a single marker line is written and logging stops for the rest of that session.
- `decisionDir` — location for `decisions.json`, containing only redaction-span
  fingerprints and approve/deny metadata. Defaults to `$XDG_CACHE_HOME` or
  `~/.cache/pi-jev-redact` on Linux, `~/Library/Caches/pi-jev-redact` on macOS,
  and `%LOCALAPPDATA%/pi-jev-redact` on Windows. Files use mode `0600`; the
  directory uses `0700`. Set this to a `/tmp` location for reboot-ephemeral
  decisions.

With logging enabled, every provider request is recorded, including requests where nothing matched. `payload`-mode entries contain only the redacted payload. Credential-header values that must remain intact for transport are forcibly replaced in the logging copy, even if they do not match an enabled detection rule, so provider authentication is never persisted. Invalid `piRedact` values degrade to logging-disabled with a warning; provider requests are never blocked by a logging misconfiguration.

The default directory lives in `/tmp`, which is world-readable and cleared on reboot. Point `logDir` at a private, persistent location if you need the log to survive.

## Security model and limits

`pi-jev-redact` is a last-mile text redactor, not a complete sandbox or secret manager.

- The original text remains in Pi's local session files and terminal transcript.
- Image contents, data URIs, and base64-like binary strings are intentionally not modified. No OCR is performed.
- Normal HTTP authentication headers are assembled after the provider payload
  hook and are not changed. For providers that embed a `headers` object inside
  the payload, credential-bearing fields (`Authorization`, `Proxy-Authorization`,
  `x-api-key`, `api-key`, and `x-goog-api-key`) are explicitly preserved while
  other header fields remain eligible for redaction.
- Detection is pattern-based. Unknown secret formats require a custom rule.
- Invalid or unreadable configuration, including a configured environment variable that is unset or too short, fails closed: provider requests are replaced with an empty payload and should fail before context is transmitted. Fix the warning and reload Pi.
- Pi runs `before_provider_request` handlers in extension load order. An extension loaded after `pi-jev-redact` can add new sensitive text after redaction. Load `pi-jev-redact` last when combining payload-rewriting extensions.
- Regular-expression validation reduces obvious denial-of-service patterns but is not a formal proof of linear runtime. Treat project configuration as trusted code.

Before relying on it for regulated or high-impact data, test representative provider payloads and use provider-side data controls as defense in depth.

## Development

Requires Node.js 20 or newer.

```bash
npm install
npm run check
npm run test:integration:auth  # real Pi process + local mock provider
npm run pack:check
```

`test:integration:auth` creates temporary Pi state and a local OpenAI-compatible
mock provider. It verifies that the configured transport credential arrives
unchanged in `Authorization`, the credential never appears in the JSON body,
and a separate key-shaped value placed in prompt content is replaced by
`<-REDACTED->`. No real provider or credential is used.

## Related packages

- [`pi-jev-anti-slop`](https://pi.dev/packages/pi-jev-anti-slop) — structured Jev code and prose review ([npm](https://www.npmjs.com/package/pi-jev-anti-slop), [GitHub](https://github.com/BubbatheVTOG/pi-jev-anti-slop)).
- [`pi-jev-tool-guard`](https://pi.dev/packages/pi-jev-tool-guard) — context-aware Jev safeguards for Pi tool calls ([npm](https://www.npmjs.com/package/pi-jev-tool-guard), [GitHub](https://github.com/BubbatheVTOG/pi-jev-tool-guard)).

## License

[MIT](LICENSE)
