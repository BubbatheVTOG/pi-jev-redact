import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const extension = join(repo, "src", "index.ts");
const root = await mkdtemp(join(tmpdir(), "pi-jev-redact-auth-"));
const agentDir = join(root, "agent");
const projectDir = join(root, "project");
await mkdir(agentDir, { recursive: true });
await mkdir(projectDir, { recursive: true });

// Construct a key-shaped but fake credential without placing one literal token
// in source. It is used only as transport authentication, never in the prompt.
const expectedKey = ["sk", "proj", "transport-only-abcdefghijklmnop"].join("-");
const promptKey = ["sk", "proj", "prompt-only-abcdefghijklmnop"].join("-");
let capturedAuthorization: string | undefined;
let capturedBody = "";

const server = createServer((request, response) => {
  const chunks: Buffer[] = [];
  request.on("data", (chunk: Buffer | string) =>
    chunks.push(Buffer.from(chunk)),
  );
  request.on("end", () => {
    capturedAuthorization = request.headers.authorization;
    capturedBody = Buffer.concat(chunks).toString("utf8");
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
    });
    response.write(
      `data: ${JSON.stringify({
        id: "chatcmpl-integration",
        object: "chat.completion.chunk",
        created: 0,
        model: "mock-model",
        choices: [
          {
            index: 0,
            delta: { role: "assistant", content: "ok" },
            finish_reason: null,
          },
        ],
      })}\n\n`,
    );
    response.write(
      `data: ${JSON.stringify({
        id: "chatcmpl-integration",
        object: "chat.completion.chunk",
        created: 0,
        model: "mock-model",
        choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
      })}\n\n`,
    );
    response.end("data: [DONE]\n\n");
  });
});

try {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert(address && typeof address === "object");

  await writeFile(
    join(agentDir, "models.json"),
    `${JSON.stringify(
      {
        providers: {
          integration: {
            baseUrl: `http://127.0.0.1:${address.port}/v1`,
            api: "openai-completions",
            apiKey: "$INTEGRATION_PROVIDER_KEY",
            authHeader: true,
            models: [
              {
                id: "mock-model",
                name: "Mock integration model",
                reasoning: false,
                input: ["text"],
                contextWindow: 16_384,
                maxTokens: 256,
                cost: {
                  input: 0,
                  output: 0,
                  cacheRead: 0,
                  cacheWrite: 0,
                },
              },
            ],
          },
        },
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );
  await writeFile(
    join(agentDir, "pi-redact.json"),
    `${JSON.stringify(
      {
        enabled: true,
        threshold: 5,
        notify: false,
        confirmIntent: false,
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );

  const child = spawn(
    "pi",
    [
      "--no-extensions",
      "--extension",
      extension,
      "--provider",
      "integration",
      "--model",
      "mock-model",
      "--print",
      "--no-tools",
      "--no-session",
      "--no-context-files",
      `The following is prompt content, not transport authentication: ${promptKey}. Return only the word ok.`,
    ],
    {
      cwd: projectDir,
      env: {
        ...process.env,
        PI_CODING_AGENT_DIR: agentDir,
        INTEGRATION_PROVIDER_KEY: expectedKey,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer | string) =>
    stdout.push(Buffer.from(chunk)),
  );
  child.stderr.on("data", (chunk: Buffer | string) =>
    stderr.push(Buffer.from(chunk)),
  );
  const timeout = setTimeout(() => child.kill("SIGKILL"), 30_000);
  const exitCode = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code));
  });
  clearTimeout(timeout);

  assert.equal(
    exitCode,
    0,
    `Pi integration process failed:\n${Buffer.concat(stderr).toString("utf8")}\n${Buffer.concat(stdout).toString("utf8")}`,
  );
  assert.equal(
    capturedAuthorization,
    `Bearer ${expectedKey}`,
    "pi-jev-redact changed the provider authentication header",
  );
  assert.equal(
    capturedBody.includes(expectedKey),
    false,
    "transport credential unexpectedly appeared in the JSON request body",
  );
  assert.equal(
    capturedBody.includes(promptKey),
    false,
    "a key-shaped value from prompt content was not redacted",
  );
  assert.equal(
    capturedBody.includes("<-REDACTED->"),
    true,
    "the provider body does not contain the redaction marker",
  );
  process.stdout.write(
    "PASS: auth header unchanged; key-shaped prompt content redacted\n",
  );
} finally {
  server.close();
  await rm(root, { recursive: true, force: true });
}
