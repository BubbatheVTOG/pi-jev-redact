# pi-redact

`pi-redact` is a [Pi coding harness](https://github.com/earendil-works/pi-mono) extension that replaces sensitive text with `*****` immediately before a provider request leaves your machine.

It protects text in the final serialized provider payload—including system prompts, conversation context, and tool results—while leaving Pi's local session history unchanged.

## Install

From npm:

```bash
pi install npm:pi-redact
```

From GitHub:

```bash
pi install git:github.com/BubbatheVTOG/pi-redact
```

Try it for one Pi process without installing:

```bash
pi -e npm:pi-redact
```

## What it detects

Built-in rules conservatively recognize:

- Anthropic and OpenAI-style API keys
- GitHub tokens
- Slack tokens
- Google API keys
- JSON Web Tokens
- PEM private keys

You can add exact literals, environment-variable values, and bounded regular expressions.

## Configuration

Create a global configuration at `~/.pi/agent/pi-redact.json`, or a project configuration at `.pi/pi-redact.json`. Project configuration is read only for trusted projects. When both exist, project booleans override global booleans and custom rules are combined.

```json
{
  "enabled": true,
  "builtins": true,
  "notify": true,
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

When redaction occurs, interactive Pi sessions receive a notification containing only the replacement count and broad rule categories. The matched text is never logged by `pi-redact`.

Configuration changes take effect after `/reload` or a new Pi session.

## Security model and limits

`pi-redact` is a last-mile text redactor, not a complete sandbox or secret manager.

- The original text remains in Pi's local session files and terminal transcript.
- Image contents, data URIs, and base64-like binary strings are intentionally not modified. No OCR is performed.
- HTTP authentication headers are outside the context payload and are not changed.
- Detection is pattern-based. Unknown secret formats require a custom rule.
- Invalid or unreadable configuration, including a configured environment variable that is unset or too short, fails closed: provider requests are replaced with an empty payload and should fail before context is transmitted. Fix the warning and reload Pi.
- Pi runs `before_provider_request` handlers in extension load order. An extension loaded after `pi-redact` can add new sensitive text after redaction. Load `pi-redact` last when combining payload-rewriting extensions.
- Regular-expression validation reduces obvious denial-of-service patterns but is not a formal proof of linear runtime. Treat project configuration as trusted code.

Before relying on it for regulated or high-impact data, test representative provider payloads and use provider-side data controls as defense in depth.

## Development

Requires Node.js 20 or newer.

```bash
npm install
npm run check
npm run pack:check
```

## License

[MIT](LICENSE)
