# pi-jev-redact

`pi-jev-redact` is a [Pi coding harness](https://github.com/earendil-works/pi-mono) extension that replaces sensitive text with `<-REDACTED->` immediately before a provider request leaves your machine.

It protects text in the final serialized provider payload—including system prompts, conversation context, and tool results—while leaving Pi's local session history unchanged.

![pi-jev-redact detecting and replacing a demo OpenAI-style key before the provider request](docs/images/redaction-notification.png)

## Disable or pause redaction

For a guaranteed package-level disable, run `pi config`, select the scope where
`pi-jev-redact` is installed, and disable its extension resource. Then run
`/reload` or start a new Pi process.

To keep the extension loaded but bypass redaction, create or edit the global
`~/.pi/agent/pi-redact.json`:

```json
{
  "enabled": false
}
```

Then run `/reload` or start a new Pi process. A trusted project's
`.pi/pi-redact.json` is applied after the global file and can set `enabled` back
to `true`; use `pi config` when the disable must not be overridable by project
configuration. For one diagnostic process with **all** auto-discovered
extensions disabled, start Pi with `pi --no-extensions` (explicit `-e` paths
still load).

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

Create a global configuration at `~/.pi/agent/pi-redact.json`, or a project configuration at `.pi/pi-redact.json`. These filenames are retained for compatibility with existing installations. Project configuration is read only for trusted projects. When both exist, project scalar options (`enabled`, `threshold`, `builtins`, `pii`, `notify`, and `confirmIntent`) override global values and custom rules are combined.

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

### Redaction configuration reference

| Key                  | Default  | Accepted values and behavior                                                                                                                                                                                                                                      |
| -------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `enabled`            | `true`   | Boolean master toggle. When `false`, requests pass through unchanged and no redaction log entry is produced.                                                                                                                                                      |
| `threshold`          | `5`      | Integer 1–10 selecting the built-in detection tiers described above.                                                                                                                                                                                              |
| `builtins`           | derived  | When absent, thresholds 1–3 use core provider/private-key rules and 4–10 use all established secret rules. `true` forces all established secret rules at any threshold; `false` disables core, platform, and aggressive secret rules. Custom rules remain active. |
| `pii`                | derived  | When absent, PII begins at threshold 7 and network identifiers at 9. `true` enables PII at any threshold (network identifiers still require threshold 9); `false` disables both PII and network rules.                                                            |
| `notify`             | `true`   | Show privacy-safe replacement and censor notifications in interactive sessions.                                                                                                                                                                                   |
| `confirmIntent`      | `true`   | Prompt once for each previously unseen sensitive fingerprint. Approval sends the redacted payload; denial censors the entire provider request. Headless sessions cannot prompt and send only the redacted payload.                                                |
| `env`                | `[]`     | Environment-variable names matching `^[A-Z_][A-Z0-9_]*$`. Resolved values become exact literal rules; unset or shorter-than-four values produce a fail-closed warning.                                                                                            |
| `literals`           | `[]`     | Exact strings of at least four characters. Do not commit actual credentials.                                                                                                                                                                                      |
| `patterns`           | `[]`     | Objects containing `pattern` and optional `flags`; each produces category `configured-pattern`.                                                                                                                                                                   |
| `patterns[].pattern` | required | Regular-expression source, 1–512 characters, non-empty-match only, and rejected when unsafe/backtracking-prone. Backreferences, lookbehind, and common nested quantifiers are disallowed.                                                                         |
| `patterns[].flags`   | `""`     | Any unique combination of `i`, `m`, `s`, `u`, and `y`. Global matching is added automatically; specifying `g` is rejected.                                                                                                                                        |

### Default rationale

Threshold 5 catches established secret formats without broadly treating common
emails, phone numbers, or IP addresses in source code as PII. Set threshold 7
(or `pii: true`) when PII protection should be active by default; use threshold
9 for network identifiers and aggressive generic-secret patterns. Intent
confirmation defaults on, while request logging defaults off. Authentication
headers remain intact only for provider transport and are forcibly removed from
any payload logging copy.

Global configuration is applied first; a trusted project file applies second.
The latest `enabled`, `threshold`, `builtins`, `pii`, `notify`, and
`confirmIntent` values win. `env`, `literals`, and `patterns` are additive
across both files. Untrusted project files are never read. Configuration files
larger than 64 KiB are ignored with a fail-closed warning.

Prefer `env` rules for credentials. Do not commit literal secrets to a project configuration.

When redaction occurs, interactive Pi sessions receive a notification containing
only the replacement count and broad rule categories. With `confirmIntent`
(default `true`), each previously unseen sensitive span also prompts: approve to
send the redacted payload, or deny to censor the whole provider request. Decisions
are remembered by SHA-256 fingerprint, so the same span is not repeatedly asked
about. A previously denied span is silently censored if it reappears. Concurrent
intent checks are serialized so one new fingerprint produces one prompt.
Headless sessions cannot prompt and proceed with the redacted payload.

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
  decisions. The cache keeps at most 10,000 entries and evicts the oldest first.
  Writes use atomic replacement plus a cross-process lock/reload/merge cycle, so
  multiple Pi processes sharing one directory preserve one another's decisions.

With logging enabled, every provider request is recorded, including requests where nothing matched. `payload`-mode entries contain only the redacted payload. Credential-header values that must remain intact for transport are forcibly replaced in the logging copy, even if they do not match an enabled detection rule, so provider authentication is never persisted. Invalid `piRedact` values degrade to logging-disabled with a warning; provider requests are never blocked by a logging misconfiguration.

The default log directory is `/tmp/pi-redact`; the extension creates that subdirectory with mode `0700` and files with `0600`, even though its `/tmp` parent is shared. Temporary storage is commonly cleared during reboot or system cleanup but is not a durability guarantee. Point `logDir` at a private, persistent location when logs must survive.

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
