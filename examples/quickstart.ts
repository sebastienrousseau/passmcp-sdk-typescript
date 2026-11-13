// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  CacheHints,
  McpClient,
  McpServer,
  OriginGuard,
  Policy,
  parseStatement,
} from "@passmcp/sdk";

const repoRoot = resolve(import.meta.dirname, "..");

const srv = new McpServer({
  name: "billing",
  version: "0.0.10",
  cacheHints: new CacheHints(60_000, "private"),
  originGuard: new OriginGuard(["https://console.example.com"]),
});

srv.registerTool(
  { name: "health", description: "Read-only health probe", readOnlyHint: true },
  async () => ({ content: [{ type: "text", text: "ok" }] }),
);
srv.registerResource(
  { uri: "billing://status", name: "status", description: "Service status" },
  async () => "healthy",
);

const st = parseStatement(readFileSync(join(repoRoot, "testdata", "statement.json"), "utf8"));
if (!st.covers("http", "https://mcp.example.com/mcp")) {
  throw new Error("untrusted server");
}

const client = McpClient.fromServer(srv, {
  endpoint: "https://mcp.example.com/mcp",
  transportKind: "http",
  policy: new Policy({
    allowMutations: false,
    statement: st,
    requireZeroFailures: false,
    minScore: 80,
    requiredChecks: ["auth.unauthenticated_tools"],
  }),
});

const discovered = await client.discover();
const toolRes = await client.callTool("health");
const content = toolRes.content as Array<{ text: string }>;
console.log(
  `${srv.name} v${srv.version} revision=${String(discovered.protocolVersion)} tool=${content[0].text} grade=${st.scoreGrade ?? "none"}`,
);
