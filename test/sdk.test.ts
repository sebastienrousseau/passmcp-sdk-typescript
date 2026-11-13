// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { test } from "node:test";
import {
  AttestationError,
  CacheHints,
  INVALID_PARAMS,
  JsonRpcError,
  LEGACY_RESOURCE_NOT_FOUND,
  METHOD_NOT_FOUND,
  McpClient,
  McpServer,
  NoSuchCheckError,
  OriginGuard,
  PARSE_ERROR,
  Policy,
  PolicyViolationError,
  parseStatement,
  REVISION_2025_06_18,
  REVISION_2025_11_25,
  REVISION_2026_07_28,
  subjectFor,
  targetDescriptor,
} from "@passmcp/sdk";

const FIXTURE_PATH = resolve(import.meta.dirname, "..", "testdata", "statement.json");

function loadFixtureDoc(): Record<string, unknown> {
  return JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as Record<string, unknown>;
}

const TAMPER_CASES: ReadonlyArray<readonly [string, (doc: Record<string, unknown>) => void]> = [
  ["_type is", (d) => (d._type = "x")],
  ["predicateType is", (d) => (d.predicateType = "x")],
  ["no subject", (d) => (d.subject = [])],
  [
    "2 subjects",
    (d) => {
      const subs = d.subject as unknown[];
      subs.push(structuredClone(subs[0]));
    },
  ],
  ["subject has no name", (d) => (((d.subject as Record<string, unknown>[])[0]).name = "   ")],
  [
    "subject is named",
    (d) => {
      ((d.subject as Record<string, unknown>[])[0]).name = "https://trusted.example.com/mcp";
    },
  ],
  [
    "no sha256 or sha512 digest",
    (d) => (((d.subject as Record<string, unknown>[])[0]).digest = {}),
  ],
  [
    "sha256 digest does not cover",
    (d) => (((d.subject as Record<string, Record<string, string>>[])[0]).digest.sha256 = "0".repeat(64)),
  ],
  ["subjectKind is", (d) => ((d.predicate as Record<string, unknown>).subjectKind = "artifact")],
  [
    "no endpoint",
    (d) => (((d.predicate as Record<string, Record<string, unknown>>).target).endpoint = " "),
  ],
  [
    "no transport",
    (d) => (((d.predicate as Record<string, Record<string, unknown>>).target).transport = ""),
  ],
  [
    "unknown transport",
    (d) => (((d.predicate as Record<string, Record<string, unknown>>).target).transport = "pigeon"),
  ],
  [
    "not identified",
    (d) => (((d.predicate as Record<string, Record<string, unknown>>).instrument).version = ""),
  ],
  ["no run time", (d) => ((d.predicate as Record<string, unknown>).ranAt = "")],
  [
    "no run time",
    (d) => ((d.predicate as Record<string, unknown>).ranAt = "0001-01-01T00:00:00Z"),
  ],
  [
    "no verdicts",
    (d) => {
      const p = d.predicate as Record<string, unknown>;
      p.verdicts = [];
      p.counts = { pass: 0, warn: 0, fail: 0, skip: 0, info: 0 };
    },
  ],
  [
    "checkInventory is empty",
    (d) =>
      (((d.predicate as Record<string, Record<string, unknown>>).judgedAgainst).checkInventory = ""),
  ],
  [
    "no rubric version",
    (d) => (((d.predicate as Record<string, Record<string, unknown>>).judgedAgainst).rubric = ""),
  ],
  [
    "has no id",
    (d) => (((d.predicate as Record<string, Record<string, unknown>[]>).verdicts[0]).id = ""),
  ],
  [
    "has status",
    (d) =>
      (((d.predicate as Record<string, Record<string, unknown>[]>).verdicts[0]).status = "maybe"),
  ],
  [
    "counts disagree",
    (d) => (((d.predicate as Record<string, Record<string, number>>).counts).pass = 7),
  ],
];

test("parses testdata/statement.json and verifies covers/verdictFor", () => {
  const st = parseStatement(readFileSync(FIXTURE_PATH));
  assert.equal(st.scoreTotal, 88);
  assert.equal(st.scoreGrade, "B");
  assert.equal(st.covers("http", "https://mcp.example.com/mcp"), true);
  assert.equal(st.covers("http", "  https://mcp.example.com/mcp  "), true);
  assert.equal(st.covers("stdio", "https://mcp.example.com/mcp"), false);
  assert.equal(st.covers("http", "https://other.example.com/mcp"), false);

  const verdict = st.verdictFor("protocol.origin");
  assert.equal(verdict.status, "fail");
  assert.equal(verdict.severity, "major");
  assert.deepEqual(verdict.evidence, ["req#12"]);
  assert.throws(() => st.verdictFor("never.measured"), NoSuchCheckError);
});

test("rejects every tampered or incomplete statement shape", () => {
  for (const [fragment, mutate] of TAMPER_CASES) {
    const doc = loadFixtureDoc();
    mutate(doc);
    assert.throws(
      () => parseStatement(JSON.stringify(doc)),
      (err: unknown) => err instanceof AttestationError && err.message.includes(fragment),
      `expected AttestationError mentioning ${fragment}`,
    );
  }
});

test("verifies SHA-512, multi-digest sets, uppercase hex rejection, and scoreless statements", () => {
  const desc = targetDescriptor("http", "https://mcp.example.com/mcp");
  const good256 = createHash("sha256").update(desc).digest("hex");
  const good512 = createHash("sha512").update(desc).digest("hex");

  const sha512Only = loadFixtureDoc();
  ((sha512Only.subject as Record<string, unknown>[])[0]).digest = { sha512: good512 };
  assert.equal(parseStatement(JSON.stringify(sha512Only)).covers("http", "https://mcp.example.com/mcp"), true);

  const bothPlusUnknown = loadFixtureDoc();
  ((bothPlusUnknown.subject as Record<string, unknown>[])[0]).digest = {
    sha256: good256,
    sha512: good512,
    md5: "ignored",
  };
  assert.equal(parseStatement(JSON.stringify(bothPlusUnknown)).covers("http", "https://mcp.example.com/mcp"), true);

  const bad512 = loadFixtureDoc();
  ((bad512.subject as Record<string, unknown>[])[0]).digest = {
    sha256: good256,
    sha512: "0".repeat(128),
  };
  assert.throws(() => parseStatement(JSON.stringify(bad512)), /sha512 digest does not cover/);

  const upperHex = loadFixtureDoc();
  ((upperHex.subject as Record<string, unknown>[])[0]).digest = {
    sha256: good256.toUpperCase(),
  };
  assert.throws(() => parseStatement(JSON.stringify(upperHex)), /sha256 digest does not cover/);

  const scoreless = loadFixtureDoc();
  const pred = scoreless.predicate as Record<string, unknown>;
  delete pred.score;
  (pred.judgedAgainst as Record<string, unknown>).rubric = "";
  pred.verdicts = [
    { id: "c1", phase: "p", status: "pass" },
    { id: "c2", phase: "p", status: "warn" },
  ];
  pred.counts = { pass: 1, warn: 1, fail: 0, skip: 0, info: 0 };
  const parsedScoreless = parseStatement(JSON.stringify(scoreless));
  assert.equal(parsedScoreless.scoreTotal, undefined);
  assert.equal(parsedScoreless.scoreGrade, undefined);
  assert.equal(
    subjectFor("http", "https://mcp.example.com/mcp").digest.sha256,
    "a386a033799c95c21f3d01b2f0efcf71b95b1ef2a420908ce34e3c1eb41a2325",
  );
  assert.throws(() => parseStatement("{broken"), AttestationError);
  assert.throws(() => parseStatement(new Uint8Array([0xff, 0xfe])), AttestationError);
});

test("omits undeclared capabilities and rejects undeclared RPCs with -32601", async () => {
  const srv = new McpServer({ name: "minimal", version: "0.0.10" });
  const init = await srv.handleRequest({ jsonrpc: "2.0", id: 1, method: "initialize" });
  assert.deepEqual(init?.result?.capabilities, {});

  const disc = await srv.handleRequest({ jsonrpc: "2.0", id: 2, method: "server/discover" });
  assert.deepEqual(disc?.result?.capabilities, {});
  assert.equal("tools" in (disc?.result ?? {}), false);
  assert.equal("resources" in (disc?.result ?? {}), false);
  assert.equal("prompts" in (disc?.result ?? {}), false);

  for (const method of [
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
    "unknown/rpc",
  ]) {
    const resp = await srv.handleRequest({ jsonrpc: "2.0", id: 9, method });
    assert.equal(resp?.error?.code, METHOD_NOT_FOUND);
  }

  assert.equal(
    await srv.handleJson('{"jsonrpc":"2.0","method":"notifications/initialized"}'),
    null,
  );
  const parseErr = JSON.parse((await srv.handleJson("{bad")) ?? "{}") as {
    error: { code: number };
  };
  assert.equal(parseErr.error.code, PARSE_ERROR);
});

test("enforces SEP-2164 missing resource error shapes across revisions", async () => {
  const srvCurrent = new McpServer({
    name: "docs",
    version: "0.0.10",
    revision: REVISION_2026_07_28,
  });
  srvCurrent.registerResource({ uri: "docs://readme", name: "readme" }, () => "hello");

  const ok = await srvCurrent.handleRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "resources/read",
    params: { uri: "docs://readme" },
  });
  const contents = ok?.result?.contents as Array<{ text: string }>;
  assert.equal(contents[0].text, "hello");

  const missing = await srvCurrent.handleRequest({
    jsonrpc: "2.0",
    id: 2,
    method: "resources/read",
    params: { uri: "docs://missing" },
  });
  assert.equal(missing?.error?.code, INVALID_PARAMS);
  assert.deepEqual(missing?.error?.data, { uri: "docs://missing" });

  for (const rev of [REVISION_2025_11_25, REVISION_2025_06_18] as const) {
    const srvLegacy = new McpServer({ name: "docs", version: "0.0.10", revision: rev });
    srvLegacy.registerResource({ uri: "docs://readme", name: "readme" }, () => "hello");

    const legacyMissing = await srvLegacy.handleRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "resources/read",
      params: { uri: "docs://missing" },
    });
    assert.equal(legacyMissing?.error?.code, LEGACY_RESOURCE_NOT_FOUND);
    assert.deepEqual(legacyMissing?.error?.data, { uri: "docs://missing" });

    const legacyDisc = await srvLegacy.handleRequest({
      jsonrpc: "2.0",
      id: 4,
      method: "server/discover",
    });
    assert.equal(legacyDisc?.error?.code, METHOD_NOT_FOUND);
  }
});

test("validates SEP-2549 CacheHints and emits _meta on list responses", async () => {
  assert.throws(() => new CacheHints(-1, "public"), RangeError);
  assert.throws(() => new CacheHints(1.5, "public"), RangeError);
  assert.throws(() => new CacheHints(0, "shared" as unknown as "public"), RangeError);

  const srv = new McpServer({
    name: "catalog",
    version: "0.0.10",
    cacheHints: new CacheHints(0, "public"),
  });
  srv.registerTool({ name: "ping_tool", readOnlyHint: true }, () => "pong");
  srv.registerResource({ uri: "cat://one", name: "one" }, () => "1");
  srv.registerResourceTemplate({ uriTemplate: "cat://items/{id}", name: "item" });
  srv.registerPrompt(
    {
      name: "summarize",
      description: "Summarize topic",
      arguments: [{ name: "topic", required: true }],
    },
    (args) => `Summarize ${args.topic}`,
  );

  for (const method of [
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
  ]) {
    const resp = await srv.handleRequest({ jsonrpc: "2.0", id: 1, method });
    assert.deepEqual(resp?.result?._meta, { ttlMs: 0, cacheScope: "public" });
  }

  const promptResp = await srv.handleRequest({
    jsonrpc: "2.0",
    id: 2,
    method: "prompts/get",
    params: { name: "summarize", arguments: { topic: "SEP-2549" } },
  });
  const messages = promptResp?.result?.messages as Array<{ content: { text: string } }>;
  assert.equal(messages[0].content.text, "Summarize SEP-2549");
});

test("enforces OriginGuard on handleHttp and node:http Streamable HTTP server", async () => {
  const guard = new OriginGuard(["https://App.Example.com:8443"]);
  assert.equal(guard.isAllowed(undefined), true);
  assert.equal(guard.isAllowed("https://app.example.com:8443"), true);
  assert.equal(guard.isAllowed("https://passmcp-origin-probe.invalid"), false);
  assert.equal(guard.isAllowed("null"), false);
  assert.equal(guard.isAllowed(""), false);

  const strictGuard = new OriginGuard(["https://app.example.com"], {
    allowMissingOrigin: false,
  });
  assert.equal(strictGuard.isAllowed(undefined), false);

  const srv = new McpServer({ name: "http-srv", version: "0.0.10", originGuard: guard });
  srv.registerTool({ name: "health", readOnlyHint: true }, () => "ok");

  const badHttp = await srv.handleHttp('{"jsonrpc":"2.0","id":1,"method":"ping"}', {
    origin: "https://passmcp-origin-probe.invalid",
  });
  assert.equal(badHttp.status, 403);

  const goodHttp = await srv.handleHttp('{"jsonrpc":"2.0","id":1,"method":"ping"}', {
    origin: "https://app.example.com:8443",
  });
  assert.equal(goodHttp.status, 200);
  assert.deepEqual(JSON.parse(goodHttp.body ?? "{}"), {
    jsonrpc: "2.0",
    id: 1,
    result: {},
  });

  const notifHttp = await srv.handleHttp(
    '{"jsonrpc":"2.0","method":"notifications/initialized"}',
    { origin: "https://app.example.com:8443" },
  );
  assert.equal(notifHttp.status, 202);
  assert.equal(notifHttp.body, null);

  const httpServer = srv.createHttpServer();
  assert.equal(typeof httpServer.listen, "function");
});

test("enforces Policy readOnlyHint=true default and verified Statement gates", async () => {
  const srv = new McpServer({ name: "ops", version: "0.0.10" });
  srv.registerTool({ name: "status", readOnlyHint: true }, () => "green");
  srv.registerTool({ name: "drop_table", readOnlyHint: false }, () => "dropped");

  const client = McpClient.fromServer(srv);
  assert.deepEqual(await client.callTool("status"), { content: [{ type: "text", text: "green" }] });
  await assert.rejects(() => client.callTool("drop_table"), PolicyViolationError);

  const mutClient = McpClient.fromServer(srv, {
    policy: new Policy({ allowMutations: true }),
  });
  assert.deepEqual(await mutClient.callTool("drop_table"), {
    content: [{ type: "text", text: "dropped" }],
  });

  const st = parseStatement(readFileSync(join(FIXTURE_PATH), "utf8"));
  const strictClient = McpClient.fromServer(srv, {
    endpoint: "https://mcp.example.com/mcp",
    transportKind: "http",
    policy: new Policy({ statement: st }),
  });
  await assert.rejects(() => strictClient.callTool("status"), /failure/);

  const wrongEndpointClient = McpClient.fromServer(srv, {
    endpoint: "https://other.example.com/mcp",
    transportKind: "http",
    policy: new Policy({ statement: st, requireZeroFailures: false }),
  });
  await assert.rejects(() => wrongEndpointClient.callTool("status"), /does not cover/);

  const gatedClient = McpClient.fromServer(srv, {
    endpoint: "https://mcp.example.com/mcp",
    transportKind: "http",
    policy: new Policy({
      statement: st,
      requireZeroFailures: false,
      minScore: 85,
      requiredChecks: ["auth.unauthenticated_tools"],
    }),
  });
  assert.deepEqual(await gatedClient.callTool("status"), {
    content: [{ type: "text", text: "green" }],
  });
  await assert.rejects(() => gatedClient.callTool("missing"), JsonRpcError);
});
