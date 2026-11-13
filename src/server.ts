// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { CacheHints, type CacheHintsInit, type CacheScope, validateObjectSchema } from "./schema.ts";
import {
  formatPromptOutput,
  formatResourceOutput,
  formatToolOutput,
  INTERNAL_ERROR,
  INVALID_PARAMS,
  INVALID_REQUEST,
  isRecord,
  JsonRpcError,
  type JsonRpcResponse,
  LEGACY_RESOURCE_NOT_FOUND,
  type McpRevision,
  META_SERVER_INFO,
  METHOD_NOT_FOUND,
  PARSE_ERROR,
  type Prompt,
  type PromptMessage,
  promptToWire,
  type Resource,
  type ResourceContent,
  type ResourceTemplate,
  resourceToWire,
  REVISION_2026_07_28,
  rpcError,
  rpcResult,
  SUPPORTED_REVISIONS,
  templateToWire,
  type Tool,
  type ToolCallOutput,
  toolToWire,
} from "./types.ts";

export { CacheHints, type CacheHintsInit, type CacheScope };

export type ToolHandler = (
  args: Record<string, unknown>,
) =>
  | Promise<ToolCallOutput | Record<string, unknown> | string>
  | ToolCallOutput
  | Record<string, unknown>
  | string;

export type ResourceHandler = (
  uri: string,
) =>
  | Promise<ResourceContent | readonly ResourceContent[] | string>
  | ResourceContent
  | readonly ResourceContent[]
  | string;

export type PromptHandler = (
  args: Record<string, string>,
) =>
  | Promise<readonly PromptMessage[] | Record<string, unknown> | string>
  | readonly PromptMessage[]
  | Record<string, unknown>
  | string;

function normalizeOrigin(origin: string): string {
  const trimmed = origin.trim();
  if (trimmed === "" || trimmed.toLowerCase() === "null") {
    throw new Error("Origin must be an explicit http(s) origin, not empty or 'null'");
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid HTTP Origin: ${origin}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported HTTP Origin protocol: ${origin}`);
  }
  if ((parsed.pathname !== "" && parsed.pathname !== "/") || parsed.search || parsed.hash) {
    throw new Error(`Origin must not carry path, query, or hash: ${origin}`);
  }
  return parsed.origin;
}

export interface OriginGuardOptions {
  readonly allowMissingOrigin?: boolean;
}

export class OriginGuard {
  private readonly allowed: ReadonlySet<string>;
  private readonly allowMissing: boolean;

  constructor(allowedOrigins: Iterable<string> = [], options?: OriginGuardOptions) {
    const normalized = new Set<string>();
    for (const item of allowedOrigins) {
      normalized.add(normalizeOrigin(item));
    }
    this.allowed = normalized;
    this.allowMissing = options?.allowMissingOrigin ?? true;
  }

  isAllowed(origin: string | undefined | null): boolean {
    if (origin === undefined || origin === null) {
      return this.allowMissing;
    }
    try {
      return this.allowed.has(normalizeOrigin(origin));
    } catch {
      return false;
    }
  }

  check(origin: string | undefined | null): void {
    if (!this.isAllowed(origin)) {
      throw new Error(`Forbidden HTTP Origin: ${String(origin)}`);
    }
  }
}

export interface McpServerOptions {
  readonly name: string;
  readonly version: string;
  readonly revision?: McpRevision;
  readonly cacheHints?: CacheHints;
  readonly originGuard?: OriginGuard;
  readonly instructions?: string;
  readonly supportedVersions?: readonly McpRevision[];
}

function validatePromptArguments(prompt: Prompt, rawArgs: unknown): Record<string, string> {
  if (!isRecord(rawArgs)) {
    throw new JsonRpcError(INVALID_PARAMS, "Invalid params: arguments must be an object");
  }
  const args: Record<string, string> = {};
  for (const [k, v] of Object.entries(rawArgs)) {
    if (typeof v !== "string") {
      throw new JsonRpcError(INVALID_PARAMS, `Prompt argument "${k}" must be a string`);
    }
    args[k] = v;
  }
  const declared = prompt.arguments ?? [];
  for (const arg of declared) {
    const missing = !Object.hasOwn(args, arg.name) || args[arg.name].trim() === "";
    if (arg.required && missing) {
      throw new JsonRpcError(INVALID_PARAMS, `Missing required prompt argument: ${arg.name}`, {
        argument: arg.name,
      });
    }
  }
  return args;
}

function extractRpcId(req: Record<string, unknown>): string | number | null {
  const rawId = req.id;
  return typeof rawId === "string" || typeof rawId === "number" ? rawId : null;
}

export class McpServer {
  readonly name: string;
  readonly version: string;
  readonly revision: McpRevision;
  readonly cacheHints?: CacheHints;
  readonly originGuard?: OriginGuard;
  readonly instructions?: string;
  readonly supportedVersions: readonly McpRevision[];

  private readonly tools = new Map<string, { tool: Tool; handler: ToolHandler }>();
  private readonly resources = new Map<string, { resource: Resource; handler: ResourceHandler }>();
  private readonly templates = new Map<string, ResourceTemplate>();
  private readonly prompts = new Map<string, { prompt: Prompt; handler: PromptHandler }>();

  constructor(options: McpServerOptions) {
    if (options.name.trim() === "" || options.version.trim() === "") {
      throw new Error("McpServer name and version must be non-empty");
    }
    const rev = options.revision ?? REVISION_2026_07_28;
    if (!SUPPORTED_REVISIONS.includes(rev)) {
      throw new Error(`Unsupported MCP revision: ${String(rev)}`);
    }
    this.name = options.name;
    this.version = options.version;
    this.revision = rev;
    this.cacheHints = options.cacheHints;
    this.originGuard = options.originGuard;
    this.instructions = options.instructions;
    this.supportedVersions =
      options.supportedVersions ??
      (rev === REVISION_2026_07_28 ? [...SUPPORTED_REVISIONS] : [rev]);
  }

  registerTool(tool: Tool, handler: ToolHandler): void {
    if (tool.name.trim() === "") {
      throw new Error("Tool.name must be non-empty");
    }
    this.tools.set(tool.name, { tool, handler });
  }

  registerResource(resource: Resource, handler: ResourceHandler): void {
    if (resource.uri.trim() === "" || resource.name.trim() === "") {
      throw new Error("Resource.uri and Resource.name must be non-empty");
    }
    this.resources.set(resource.uri, { resource, handler });
  }

  registerResourceTemplate(template: ResourceTemplate): void {
    if (template.uriTemplate.trim() === "" || template.name.trim() === "") {
      throw new Error("ResourceTemplate.uriTemplate and name must be non-empty");
    }
    this.templates.set(template.uriTemplate, template);
  }

  registerPrompt(prompt: Prompt, handler: PromptHandler): void {
    if (prompt.name.trim() === "") {
      throw new Error("Prompt.name must be non-empty");
    }
    this.prompts.set(prompt.name, { prompt, handler });
  }

  capabilities(): Record<string, Record<string, never>> {
    const caps: Record<string, Record<string, never>> = {};
    if (this.tools.size > 0) {
      caps.tools = {};
    }
    if (this.resources.size > 0 || this.templates.size > 0) {
      caps.resources = {};
    }
    if (this.prompts.size > 0) {
      caps.prompts = {};
    }
    return caps;
  }

  private withListMeta(payload: Record<string, unknown>): Record<string, unknown> {
    if (this.cacheHints !== undefined && this.revision === REVISION_2026_07_28) {
      return this.cacheHints.applyToList(payload);
    }
    return payload;
  }

  private handleInitialize(params: Record<string, unknown>): Record<string, unknown> {
    const reqVer = params.protocolVersion;
    const negotiated =
      typeof reqVer === "string" && (SUPPORTED_REVISIONS as readonly string[]).includes(reqVer)
        ? reqVer
        : this.revision;
    return {
      protocolVersion: negotiated,
      capabilities: this.capabilities(),
      serverInfo: { name: this.name, version: this.version },
      ...(this.instructions ? { instructions: this.instructions } : {}),
    };
  }

  private handleDiscover(): Record<string, unknown> {
    if (this.revision !== REVISION_2026_07_28) {
      throw new JsonRpcError(METHOD_NOT_FOUND, "Method not found: server/discover");
    }
    const caps = this.capabilities();
    const info = { name: this.name, version: this.version };
    const res: Record<string, unknown> = {
      resultType: "discover",
      protocolVersion: this.revision,
      supportedVersions: [...this.supportedVersions],
      serverInfo: info,
      capabilities: caps,
      _meta: { [META_SERVER_INFO]: { ...info } },
    };
    if ("tools" in caps) {
      res.tools = Array.from(this.tools.values(), ({ tool }) => toolToWire(tool));
    }
    if ("resources" in caps) {
      res.resources = Array.from(this.resources.values(), ({ resource }) =>
        resourceToWire(resource),
      );
      res.resourceTemplates = Array.from(this.templates.values(), (tpl) => templateToWire(tpl));
    }
    if ("prompts" in caps) {
      res.prompts = Array.from(this.prompts.values(), ({ prompt }) => promptToWire(prompt));
    }
    if (this.instructions) {
      res.instructions = this.instructions;
    }
    return res;
  }

  private async handleToolsCall(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (this.tools.size === 0) {
      throw new JsonRpcError(METHOD_NOT_FOUND, "Method not found: tools/call");
    }
    const name = params.name;
    if (typeof name !== "string" || name.trim() === "") {
      throw new JsonRpcError(INVALID_PARAMS, "Invalid params: missing tool name");
    }
    const rawArgs = params.arguments ?? {};
    if (!isRecord(rawArgs)) {
      throw new JsonRpcError(INVALID_PARAMS, "Invalid params: arguments must be an object");
    }
    const entry = this.tools.get(name);
    if (!entry) {
      throw new JsonRpcError(INVALID_PARAMS, `Unknown tool: ${name}`, { name });
    }
    validateObjectSchema(entry.tool.inputSchema, rawArgs);
    return formatToolOutput(entry.tool, await entry.handler(rawArgs));
  }

  private async handleResourcesRead(
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    if (this.resources.size === 0 && this.templates.size === 0) {
      throw new JsonRpcError(METHOD_NOT_FOUND, "Method not found: resources/read");
    }
    const uri = params.uri;
    if (typeof uri !== "string" || uri.trim() === "") {
      throw new JsonRpcError(INVALID_PARAMS, "Invalid params: missing resource uri");
    }
    const entry = this.resources.get(uri);
    if (!entry) {
      const code =
        this.revision === REVISION_2026_07_28 ? INVALID_PARAMS : LEGACY_RESOURCE_NOT_FOUND;
      throw new JsonRpcError(code, `Resource not found: ${uri}`, { uri });
    }
    return formatResourceOutput(
      uri,
      entry.resource.mimeType ?? "text/plain",
      await entry.handler(uri),
    );
  }

  private async handlePromptsGet(
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    if (this.prompts.size === 0) {
      throw new JsonRpcError(METHOD_NOT_FOUND, "Method not found: prompts/get");
    }
    const name = params.name;
    if (typeof name !== "string" || name.trim() === "") {
      throw new JsonRpcError(INVALID_PARAMS, "Invalid params: missing prompt name");
    }
    const entry = this.prompts.get(name);
    if (!entry) {
      throw new JsonRpcError(INVALID_PARAMS, `Unknown prompt: ${name}`, { name });
    }
    const args = validatePromptArguments(entry.prompt, params.arguments ?? {});
    return formatPromptOutput(entry.prompt.description, await entry.handler(args));
  }

  private handleToolsList(): Record<string, unknown> {
    if (this.tools.size === 0) {
      throw new JsonRpcError(METHOD_NOT_FOUND, "Method not found: tools/list");
    }
    return this.withListMeta({
      tools: Array.from(this.tools.values(), ({ tool }) => toolToWire(tool)),
    });
  }

  private handleResourcesList(): Record<string, unknown> {
    if (this.resources.size === 0 && this.templates.size === 0) {
      throw new JsonRpcError(METHOD_NOT_FOUND, "Method not found: resources/list");
    }
    return this.withListMeta({
      resources: Array.from(this.resources.values(), ({ resource }) => resourceToWire(resource)),
    });
  }

  private handleTemplatesList(): Record<string, unknown> {
    if (this.resources.size === 0 && this.templates.size === 0) {
      throw new JsonRpcError(METHOD_NOT_FOUND, "Method not found: resources/templates/list");
    }
    return this.withListMeta({
      resourceTemplates: Array.from(this.templates.values(), (tpl) => templateToWire(tpl)),
    });
  }

  private handlePromptsList(): Record<string, unknown> {
    if (this.prompts.size === 0) {
      throw new JsonRpcError(METHOD_NOT_FOUND, "Method not found: prompts/list");
    }
    return this.withListMeta({
      prompts: Array.from(this.prompts.values(), ({ prompt }) => promptToWire(prompt)),
    });
  }

  private async dispatch(
    method: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const routes: Record<string, () => Promise<Record<string, unknown>> | Record<string, unknown>> =
      {
        initialize: () => this.handleInitialize(params),
        ping: () => ({}),
        "server/discover": () => this.handleDiscover(),
        "tools/list": () => this.handleToolsList(),
        "tools/call": () => this.handleToolsCall(params),
        "resources/list": () => this.handleResourcesList(),
        "resources/templates/list": () => this.handleTemplatesList(),
        "resources/read": () => this.handleResourcesRead(params),
        "prompts/list": () => this.handlePromptsList(),
        "prompts/get": () => this.handlePromptsGet(params),
      };
    const handler = Object.hasOwn(routes, method) ? routes[method] : undefined;
    if (!handler) {
      throw new JsonRpcError(METHOD_NOT_FOUND, `Method not found: ${method}`);
    }
    return handler();
  }

  private async executeRpc(
    reqId: string | number | null,
    method: string,
    params: Record<string, unknown>,
  ): Promise<JsonRpcResponse> {
    if (method === "notifications/initialized") {
      return rpcResult(reqId, {});
    }
    try {
      return rpcResult(reqId, await this.dispatch(method, params));
    } catch (err) {
      if (err instanceof JsonRpcError) {
        return rpcError(reqId, err.code, err.message, err.data);
      }
      return rpcError(reqId, INTERNAL_ERROR, `Internal error: ${String(err)}`);
    }
  }

  async handleRequest(req: unknown): Promise<JsonRpcResponse | null> {
    if (!isRecord(req)) {
      return rpcError(null, INVALID_REQUEST, "Invalid Request");
    }
    const hasId = Object.hasOwn(req, "id");
    const reqId = extractRpcId(req);
    const method = req.method;
    if (req.jsonrpc !== "2.0" || typeof method !== "string" || method.trim() === "") {
      return rpcError(reqId, INVALID_REQUEST, "Invalid Request");
    }
    if (req.params !== undefined && !isRecord(req.params)) {
      return hasId ? rpcError(reqId, INVALID_PARAMS, "Invalid params: expected object") : null;
    }
    if (!hasId) {
      return null;
    }
    return this.executeRpc(reqId, method, req.params ?? {});
  }

  async handleJson(raw: string | Uint8Array): Promise<string | null> {
    let decoded: unknown;
    try {
      const text =
        typeof raw === "string" ? raw : new TextDecoder("utf-8", { fatal: true }).decode(raw);
      decoded = JSON.parse(text);
    } catch {
      return JSON.stringify(rpcError(null, PARSE_ERROR, "Parse error"));
    }
    const response = await this.handleRequest(decoded);
    return response !== null ? JSON.stringify(response) : null;
  }

  async handleHttp(
    raw: string | Uint8Array,
    options?: { readonly origin?: string | null },
  ): Promise<{ readonly status: number; readonly body: string | null }> {
    if (this.originGuard !== undefined && !this.originGuard.isAllowed(options?.origin)) {
      return {
        status: 403,
        body: JSON.stringify(rpcError(null, INVALID_REQUEST, "Forbidden Origin")),
      };
    }
    const body = await this.handleJson(raw);
    return body === null ? { status: 202, body: null } : { status: 200, body };
  }

  createHttpServer(): Server {
    return createServer(async (req: IncomingMessage, res: ServerResponse) => {
      if (req.method !== "POST") {
        res.writeHead(405, { Allow: "POST", "Content-Type": "application/json" });
        res.end(JSON.stringify(rpcError(null, INVALID_REQUEST, "Method Not Allowed")));
        return;
      }
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
      }
      const originHeader = Array.isArray(req.headers.origin)
        ? req.headers.origin[0]
        : req.headers.origin;
      const out = await this.handleHttp(Buffer.concat(chunks), { origin: originHeader });
      if (out.body === null) {
        res.writeHead(out.status).end();
        return;
      }
      res.writeHead(out.status, { "Content-Type": "application/json" });
      res.end(out.body);
    });
  }
}
