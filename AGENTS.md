# Repository guidance

## Scope

`pi-jev-redact` is a last-mile Pi provider-payload redactor. Preserve local session data while ensuring detected secrets/PII are replaced immediately before outbound provider requests.

## Layout

- `src/config.ts` — `pi-redact.json` parsing and threshold-derived rule tiers.
- `src/redactor.ts` — built-in and custom text rules.
- `src/payload.ts` — immutable payload traversal, header exemptions, fingerprints.
- `src/decisions.ts` — privacy-preserving approval/denial cache.
- `src/logger.ts` — optional redacted request logging.
- `src/index.ts` — extension lifecycle, notifications, intent confirmation.
- `test/` — deterministic Vitest coverage; no live provider requests.

## Checks

```bash
npm install
npm run check
npm run pack:check
```

Run `npm run check` before committing. Construct key-shaped test fixtures from harmless fragments; an active pi-jev-redact installation can otherwise remove literal fixture text from the provider request before the agent sees it.

## Conventions

- Never persist raw matched text. Decision storage contains only SHA-256 fingerprints and metadata.
- Authentication values inside outbound credential headers must pass through unchanged; redact matching values elsewhere.
- Invalid redaction configuration fails closed. Logging/cache failures warn and do not expose original values.
- Keep regexes bounded and covered by deterministic tests.
- Never log or commit credentials.

## Release

Run checks and pack validation, bump package versions without creating an automatic tag, commit with an imperative subject, push `main`, then `npm publish`. Verify with `npm view <package> version`.
