// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { resolve } from "node:path";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import {
  authorizationServerMetadataUrl,
  buildBearerChallenge,
  CacheHints,
  computeS256Challenge,
  generatePkceVerifier,
  HEADER_MISMATCH,
  INVALID_PARAMS,
  JsonRpcError,
  META_SERVER_INFO,
  METHOD_NOT_FOUND,
  McpClient,
  McpServer,
  OAuthError,
  OriginGuard,
  PARSE_ERROR,
  protectedResourceMetadataUrl,
  protectedResourceMetadataUrls,
  parseBearerChallenge,
  REVISION_2025_11_25,
  REVISION_2026_07_28,
  StdioTransport,
  StreamableHttpHandler,
  SUPPORTED_REVISIONS,
  serveStdio,
  validateAuthorizationServerMetadata,
  validateObjectSchema,
  validateProtectedResourceMetadata,
  verifyS256,
} from "@passmcp/sdk";

const STDIO_SERVER_PATH = resolve(import.meta.dirname, "..", "examples", "stdio-server.mjs");

test("serveStdio handles notifications silently and recovers from malformed JSON lines", async () => {
  const srv = new McpServer({ name: "stdio-unit", version: "0.0.10" });
  srv.registerTool({ name: "echo", readOnlyHint: true }, (args) => String(args.msg ?? "ok"));

  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: string[] = [];
  output.setEncoding("utf8");
  output.on("data", (chunk: string) => chunks.push(chunk));

  const loopPromise = serveStdio(srv, input, output);
  input.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
  input.write("{truncated-json\n");
  input.write("   \n");
  input.write('{"jsonrpc":"2.0","id":7,"method":"ping"}\n');
  input.end();
  await loopPromise;

  const lines = chunks
    .join("")
    .split("\n")
    .filter((line) => line.trim() !== "");
  assert.equal(lines.length, 2);
  const errFrame = JSON.parse(lines[0]) as { error: { code: number } };
  assert.equal(errFrame.error.code, PARSE_ERROR);
  const pingFrame = JSON.parse(lines[1]) as { id: number; result: Record<string, unknown> };
  assert.equal(pingFrame.id, 7);
  assert.deepEqual(pingFrame.result, {});
});

test("StdioTransport connects in-memory and spawns examples/stdio-server.mjs", async () => {
  const srv = new McpServer({ name: "pipe-srv", version: "0.0.10" });
  srv.registerTool({ name: "status", readOnlyHint: true }, () => "ready");
  const memClient = new McpClient(StdioTransport.fromInMemoryServer(srv), {
    transportKind: "stdio",
  });
  const disc = await memClient.discover();
  assert.equal(disc.resultType, "discover");
  assert.deepEqual(await memClient.callTool("status"), {
    content: [{ type: "text", text: "ready" }],
  });
  await memClient.close();

  const childClient = McpClient.fromStdio({
    command: process.execPath,
    args: [STDIO_SERVER_PATH],
  });
  try {
    const childDisc = await childClient.discover();
    assert.equal(childDisc.resultType, "discover");
    assert.deepEqual(childDisc.supportedVersions, [...SUPPORTED_REVISIONS]);
    const meta = childDisc._meta as Record<string, unknown>;
    assert.deepEqual(meta[META_SERVER_INFO], {
      name: "passmcp-sdk-typescript-demo",
      version: "0.0.9",
    });

    const toolOut = await childClient.callTool("inspect_target", {
      endpoint: "https://mcp.example.com/mcp",
    });
    assert.deepEqual(toolOut.structuredContent, {
      endpoint: "https://mcp.example.com/mcp",
      transport: "http",
    });
    const resOut = await childClient.readResource("passmcp://sdk/overview");
    assert.equal(Array.isArray(resOut.contents), true);
    const promptOut = await childClient.getPrompt("audit_summary", { server_name: "demo" });
    assert.equal(Array.isArray(promptOut.messages), true);
  } finally {
    await childClient.close();
  }
});

function buildValidatedServer(): McpServer {
  const srv = new McpServer({
    name: "validator",
    version: "0.0.10",
    cacheHints: new CacheHints({ cacheable: true, ttl: 120, scope: "private" }),
  });
  srv.registerTool(
    {
      name: "compute",
      readOnlyHint: true,
      inputSchema: {
        type: "object",
        additionalProperties: false,
        required: ["count", "label"],
        properties: { count: { type: "integer" }, label: { type: "string" } },
      },
      outputSchema: {
        type: "object",
        required: ["doubled"],
        properties: { doubled: { type: "integer" } },
      },
    },
    (args) => ({ doubled: (args.count as number) * 2 }),
  );
  srv.registerPrompt(
    { name: "greet", arguments: [{ name: "who", required: true }] },
    (args) => `Hello ${args.who}`,
  );
  return srv;
}

test("validates tool inputSchema, structuredContent, prompt arguments, and CacheHints", async () => {
  const srv = buildValidatedServer();
  const listResp = await srv.handleRequest({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  assert.equal(listResp?.result?.ttlMs, 120_000);
  assert.equal(listResp?.result?.cacheScope, "private");

  for (const badArgs of [
    { count: 3 },
    { count: 3.5, label: "x" },
    { count: 3, label: "x", extra: true },
  ]) {
    const resp = await srv.handleRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "compute", arguments: badArgs },
    });
    assert.equal(resp?.error?.code, INVALID_PARAMS);
  }

  const validCall = await srv.handleRequest({
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "compute", arguments: { count: 4, label: "ok" } },
  });
  assert.deepEqual(validCall?.result?.structuredContent, { doubled: 8 });

  const missingPromptArg = await srv.handleRequest({
    jsonrpc: "2.0",
    id: 6,
    method: "prompts/get",
    params: { name: "greet", arguments: {} },
  });
  assert.equal(missingPromptArg?.error?.code, INVALID_PARAMS);

  assert.throws(
    () => validateObjectSchema({ type: "object" }, "bad" as unknown as Record<string, unknown>),
    JsonRpcError,
  );
  assert.equal(new CacheHints({ cacheable: false, scope: "private" }).ttlMs, 0);
});

test("StreamableHttpHandler enforces Origin 403, Bearer 401, 405 Allow, and -32700", async () => {
  const srv = new McpServer({
    name: "http-2026",
    version: "0.0.10",
    revision: REVISION_2026_07_28,
    originGuard: new OriginGuard(["https://console.example.com"]),
  });
  srv.registerTool({ name: "ping_tool", readOnlyHint: true }, () => "pong");

  const metaUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
  const handler = new StreamableHttpHandler(srv, {
    bearerValidator: (tok) => tok === "good-token",
    resourceMetadataUrl: metaUrl,
  });

  const forbidden = await handler.fetch(
    new Request("https://mcp.example.com/mcp", {
      method: "POST",
      headers: { Origin: "https://evil.invalid" },
      body: "{}",
    }),
  );
  assert.equal(forbidden.status, 403);

  const unauth = await handler.fetch(
    new Request("https://mcp.example.com/mcp", { method: "POST", body: "{}" }),
  );
  assert.equal(unauth.status, 401);
  assert.equal(
    unauth.headers.get("www-authenticate")?.includes(`resource_metadata="${metaUrl}"`),
    true,
  );

  const getResp = await handler.fetch(
    new Request("https://mcp.example.com/mcp", {
      method: "GET",
      headers: { Authorization: "Bearer good-token" },
    }),
  );
  assert.equal(getResp.status, 405);
  assert.equal(getResp.headers.get("allow"), "POST");

  const badJson = await handler.fetch(
    new Request("https://mcp.example.com/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer good-token" },
      body: "{bad",
    }),
  );
  assert.equal(badJson.status, 400);
  assert.equal(((await badJson.json()) as { error: { code: number } }).error.code, PARSE_ERROR);
});

test("StreamableHttpHandler enforces 2026-07-28 -32020 header mismatch and 404 unknown RPC", async () => {
  const srv = new McpServer({
    name: "http-2026-stateless",
    version: "0.0.10",
    revision: REVISION_2026_07_28,
  });
  srv.registerTool({ name: "ping_tool", readOnlyHint: true }, () => "pong");
  const handler = new StreamableHttpHandler(srv, {
    bearerValidator: (tok) => tok === "good-token",
  });

  const mismatch = await handler.fetch(
    new Request("https://mcp.example.com/mcp", {
      method: "POST",
      headers: {
        Authorization: "Bearer good-token",
        "MCP-Protocol-Version": REVISION_2026_07_28,
        "MCP-Method": "tools/list",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
    }),
  );
  assert.equal(mismatch.status, 400);
  assert.equal(((await mismatch.json()) as { error: { code: number } }).error.code, HEADER_MISMATCH);

  const unknownMethod = await handler.fetch(
    new Request("https://mcp.example.com/mcp", {
      method: "POST",
      headers: { Authorization: "Bearer good-token" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "prompts/list" }),
    }),
  );
  assert.equal(unknownMethod.status, 404);
  assert.equal(
    ((await unknownMethod.json()) as { error: { code: number } }).error.code,
    METHOD_NOT_FOUND,
  );

  const client = McpClient.fromHttp("https://mcp.example.com/mcp", {
    bearerToken: "good-token",
    protocolVersion: REVISION_2026_07_28,
    fetchFn: handler.fetch,
  });
  assert.equal((await client.listTools()).length, 1);
});

test("StreamableHttpHandler issues and enforces Mcp-Session-Id in stateful mode", async () => {
  const srv = new McpServer({
    name: "http-session",
    version: "0.0.10",
    revision: REVISION_2025_11_25,
  });
  srv.registerTool({ name: "info", readOnlyHint: true }, () => "session-ok");
  const handler = new StreamableHttpHandler(srv, { requireSession: true });

  const missingSession = await handler.fetch(
    new Request("https://mcp.example.com/mcp", {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
    }),
  );
  assert.equal(missingSession.status, 404);

  const client = McpClient.fromHttp("https://mcp.example.com/mcp", {
    fetchFn: handler.fetch,
  });
  await client.initialize();
  assert.deepEqual(await client.ping(), {});

  const bogusSession = await handler.fetch(
    new Request("https://mcp.example.com/mcp", {
      method: "POST",
      headers: { "Mcp-Session-Id": "unknown-session" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }),
    }),
  );
  assert.equal(bogusSession.status, 404);
});

test("computes and verifies RFC 7636 S256 PKCE challenges and Bearer challenges", () => {
  const rfcVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
  assert.equal(computeS256Challenge(rfcVerifier), rfcChallenge);
  assert.equal(verifyS256(rfcVerifier, rfcChallenge), true);
  assert.equal(verifyS256(rfcVerifier, "wrong"), false);

  const generated = generatePkceVerifier(64);
  assert.equal(generated.length, 64);
  assert.equal(verifyS256(generated, computeS256Challenge(generated)), true);
  assert.throws(() => generatePkceVerifier(42), OAuthError);
  assert.throws(() => computeS256Challenge("short"), OAuthError);

  const header = buildBearerChallenge({
    resourceMetadata: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    scope: "mcp:tools",
    error: "invalid_token",
    errorDescription: "Token expired",
  });
  const parsed = parseBearerChallenge(header);
  assert.equal(
    parsed.resourceMetadata,
    "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
  );
  assert.equal(parsed.scope, "mcp:tools");
  assert.equal(parsed.error, "invalid_token");
  assert.equal(parsed.errorDescription, "Token expired");
  assert.throws(() => parseBearerChallenge('Basic realm="x"'), OAuthError);
});

test("derives and validates RFC 9728 Protected Resource Metadata", () => {
  assert.deepEqual(protectedResourceMetadataUrls("https://mcp.example.com/mcp"), [
    "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    "https://mcp.example.com/.well-known/oauth-protected-resource",
  ]);
  assert.equal(
    protectedResourceMetadataUrl("https://mcp.example.com/"),
    "https://mcp.example.com/.well-known/oauth-protected-resource",
  );

  const prm = validateProtectedResourceMetadata(
    {
      resource: "https://mcp.example.com/mcp",
      authorization_servers: ["https://auth.example.com/tenant"],
      scopes_supported: ["mcp:read"],
    },
    "https://mcp.example.com/mcp",
  );
  assert.deepEqual(prm.authorizationServers, ["https://auth.example.com/tenant"]);

  assert.throws(
    () =>
      validateProtectedResourceMetadata(
        {
          resource: "https://other.example.com/mcp",
          authorization_servers: ["https://auth.example.com"],
        },
        "https://mcp.example.com/mcp",
      ),
    OAuthError,
  );
});

test("derives and validates RFC 8414 OAuth 2.1 Authorization Server Metadata", () => {
  assert.equal(
    authorizationServerMetadataUrl("https://auth.example.com/tenant"),
    "https://auth.example.com/.well-known/oauth-authorization-server/tenant",
  );
  const asm = validateAuthorizationServerMetadata(
    {
      issuer: "https://auth.example.com/tenant",
      authorization_endpoint: "https://auth.example.com/tenant/authorize",
      token_endpoint: "https://auth.example.com/tenant/token",
      registration_endpoint: "https://auth.example.com/tenant/register",
      code_challenge_methods_supported: ["S256"],
    },
    "https://auth.example.com/tenant",
  );
  assert.equal(asm.codeChallengeMethodsSupported.includes("S256"), true);

  assert.throws(
    () =>
      validateAuthorizationServerMetadata({
        issuer: "https://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        code_challenge_methods_supported: ["plain"],
      }),
    OAuthError,
  );
  assert.throws(
    () =>
      validateAuthorizationServerMetadata({
        issuer: "http://auth.example.com",
        authorization_endpoint: "https://auth.example.com/authorize",
        token_endpoint: "https://auth.example.com/token",
        code_challenge_methods_supported: ["S256"],
      }),
    OAuthError,
  );
});
