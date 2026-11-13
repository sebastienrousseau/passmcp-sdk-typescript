// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CacheHints,
  INVALID_PARAMS,
  JsonRpcError,
  McpServer,
  serveStdio,
} from "@passmcp/sdk";

const INSPECT_TARGET_TOOL = {
  name: "inspect_target",
  title: "Inspect MCP Target",
  description:
    "Inspect an HTTPS or stdio MCP target identifier and classify its transport without making any network connections.",
  readOnlyHint: true,
  inputSchema: {
    type: "object",
    additionalProperties: false,
    required: ["endpoint"],
    properties: {
      endpoint: {
        type: "string",
        description: "HTTPS or stdio target endpoint identifier to inspect",
      },
    },
  },
  outputSchema: {
    type: "object",
    required: ["endpoint", "transport"],
    properties: {
      endpoint: { type: "string" },
      transport: { type: "string" },
    },
  },
  annotations: {
    title: "Inspect MCP Target",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

function inspectTarget(args) {
  const endpoint = args.endpoint;
  if (typeof endpoint !== "string" || endpoint.trim() === "") {
    throw new JsonRpcError(INVALID_PARAMS, "endpoint must be a non-empty string");
  }
  const trimmed = endpoint.trim();
  const transport =
    trimmed.startsWith("https://") || trimmed.startsWith("http://") ? "http" : "stdio";
  const structured = { endpoint: trimmed, transport };
  return {
    content: [{ type: "text", text: JSON.stringify(structured) }],
    structuredContent: structured,
  };
}

export function buildDemoServer() {
  const srv = new McpServer({
    name: "passmcp-sdk-typescript-demo",
    version: "0.0.9",
    cacheHints: new CacheHints({ cacheable: true, ttl: 300, scope: "public" }),
    instructions:
      "Reference MCP server built with passmcp-sdk demonstrating read-only tools, SEP-2164 resources, prompts, and SEP-2549 cache hints.",
  });

  srv.registerTool(INSPECT_TARGET_TOOL, inspectTarget);
  srv.registerResource(
    {
      uri: "passmcp://sdk/overview",
      name: "sdk-overview",
      title: "SDK Overview",
      description: "Overview of the passmcp SDK capabilities and supported MCP revisions.",
      mimeType: "text/plain",
    },
    () =>
      "passmcp-sdk-typescript supports MCP revisions 2025-06-18, 2025-11-25, and 2026-07-28 with capability-derived dispatch, SEP-2164, SEP-2549, and offline attestations.",
  );
  srv.registerPrompt(
    {
      name: "audit_summary",
      title: "Audit Summary Prompt",
      description: "Generate a concise audit summary prompt for a named MCP server.",
      arguments: [
        {
          name: "server_name",
          description: "Name of the MCP server being audited",
          required: true,
        },
      ],
    },
    (args) => [
      {
        role: "user",
        text: `Summarize the MCP conformance posture for server ${args.server_name}.`,
      },
    ],
  );
  return srv;
}

const isMain =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isMain) {
  await serveStdio(buildDemoServer());
}
