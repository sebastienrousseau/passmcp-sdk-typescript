// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { NoSuchCheckError, type Statement } from "./attestation.ts";
import {
  HttpClientTransport,
  type HttpTransportOptions,
} from "./http_transport.ts";
import type { McpServer } from "./server.ts";
import { type StdioSpawnOptions, StdioTransport } from "./stdio.ts";
import {
  isRecord,
  JsonRpcError,
  type JsonRpcRequest,
  type JsonRpcResponse,
  METHOD_NOT_FOUND,
  type Tool,
  toolFromWire,
} from "./types.ts";

export type TransportCallable = (
  request: JsonRpcRequest,
) => Promise<JsonRpcResponse | null> | JsonRpcResponse | null;

export class PolicyViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyViolationError";
  }
}

export interface PolicyOptions {
  readonly allowMutations?: boolean;
  readonly statement?: Statement;
  readonly requireZeroFailures?: boolean;
  readonly minScore?: number;
  readonly requiredChecks?: readonly string[];
}

export class Policy {
  readonly allowMutations: boolean;
  readonly statement?: Statement;
  readonly requireZeroFailures: boolean;
  readonly minScore?: number;
  readonly requiredChecks: readonly string[];

  constructor(options?: PolicyOptions) {
    this.allowMutations = options?.allowMutations ?? false;
    this.statement = options?.statement;
    this.requireZeroFailures = options?.requireZeroFailures ?? true;
    this.minScore = options?.minScore;
    this.requiredChecks = options?.requiredChecks ? [...options.requiredChecks] : [];
  }

  private checkRequiredVerdicts(stmt: Statement): void {
    for (const checkId of this.requiredChecks) {
      let status: string;
      try {
        status = stmt.verdictFor(checkId).status;
      } catch (err) {
        if (err instanceof NoSuchCheckError) {
          throw new PolicyViolationError(err.message);
        }
        throw err;
      }
      if (status !== "pass") {
        throw new PolicyViolationError(
          `Required check "${checkId}" has status "${status}", want "pass"`,
        );
      }
    }
  }

  checkTarget(transport: string, endpoint: string): void {
    const stmt = this.statement;
    if (!stmt) {
      return;
    }
    if (!stmt.covers(transport, endpoint)) {
      throw new PolicyViolationError(
        `Attestation statement does not cover target ${transport}:${endpoint}`,
      );
    }
    if (this.requireZeroFailures && stmt.predicate.counts.fail > 0) {
      throw new PolicyViolationError(
        `Attestation statement records ${stmt.predicate.counts.fail} failure(s)`,
      );
    }
    if (this.minScore !== undefined) {
      const total = stmt.scoreTotal;
      if (total === undefined || total < this.minScore) {
        throw new PolicyViolationError(
          `Attestation score ${String(total)} is below minimum ${this.minScore}`,
        );
      }
    }
    this.checkRequiredVerdicts(stmt);
  }

  checkTool(tool: Tool): void {
    const readOnly = tool.annotations?.readOnlyHint ?? tool.readOnlyHint;
    if (!this.allowMutations && readOnly !== true) {
      throw new PolicyViolationError(
        `Refusing to execute tool "${tool.name}": readOnlyHint is not true and Policy.allowMutations is false`,
      );
    }
  }
}

export function httpTransport(
  endpoint: string,
  options?: HttpTransportOptions | Readonly<Record<string, string>>,
): TransportCallable {
  if (
    options &&
    !("bearerToken" in options) &&
    !("fetchFn" in options) &&
    !("protocolVersion" in options) &&
    !("headers" in options)
  ) {
    return new HttpClientTransport(endpoint, {
      headers: options as Readonly<Record<string, string>>,
    }).send;
  }
  return new HttpClientTransport(endpoint, options as HttpTransportOptions | undefined).send;
}

export interface McpClientOptions {
  readonly endpoint?: string;
  readonly transportKind?: string;
  readonly policy?: Policy;
}

export interface TransportObject {
  readonly send: TransportCallable;
  close?: () => Promise<void>;
}

export interface StdioClientSpawnInit extends StdioSpawnOptions {
  readonly command: string;
  readonly args?: readonly string[];
  readonly policy?: Policy;
}

export class McpClient {
  readonly endpoint: string;
  readonly transportKind: string;
  readonly policy: Policy;
  private readonly send: TransportCallable;
  private readonly closeFn?: () => Promise<void>;
  private nextId = 0;
  private toolsCache: Map<string, Tool> | null = null;

  constructor(transport: TransportCallable | TransportObject, options?: McpClientOptions) {
    if (typeof transport === "function") {
      this.send = transport;
    } else {
      this.send = transport.send;
      this.closeFn = transport.close ? () => transport.close!() : undefined;
    }
    this.endpoint = options?.endpoint ?? "stdio://local";
    this.transportKind = options?.transportKind ?? "stdio";
    this.policy = options?.policy ?? new Policy();
  }

  static fromServer(server: McpServer, options?: McpClientOptions): McpClient {
    return new McpClient((req) => server.handleRequest(req), {
      endpoint: options?.endpoint ?? "https://mcp.example.com/mcp",
      transportKind: options?.transportKind ?? "http",
      policy: options?.policy,
    });
  }

  static fromHttp(
    endpoint: string,
    options?: HttpTransportOptions & { readonly policy?: Policy },
  ): McpClient {
    const tr = new HttpClientTransport(endpoint, options);
    return new McpClient(tr, {
      endpoint,
      transportKind: "http",
      policy: options?.policy,
    });
  }

  static fromStdio(
    commandOrInit: string | StdioClientSpawnInit,
    args: readonly string[] = [],
    options?: StdioSpawnOptions & { readonly policy?: Policy },
  ): McpClient {
    const cmd = typeof commandOrInit === "string" ? commandOrInit : commandOrInit.command;
    const cmdArgs = typeof commandOrInit === "string" ? args : (commandOrInit.args ?? []);
    const opts = typeof commandOrInit === "string" ? options : commandOrInit;
    const transport = StdioTransport.spawn(cmd, cmdArgs, opts);
    return new McpClient(transport, {
      endpoint: [cmd, ...cmdArgs].join(" "),
      transportKind: "stdio",
      policy: opts?.policy,
    });
  }

  async close(): Promise<void> {
    if (this.closeFn) {
      await this.closeFn();
    }
  }

  private async call(
    method: string,
    params?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    this.policy.checkTarget(this.transportKind, this.endpoint);
    this.nextId += 1;
    const req: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: this.nextId,
      method,
      ...(params !== undefined ? { params } : {}),
    };
    const response = await this.send(req);
    if (!response) {
      throw new JsonRpcError(-32603, `Missing JSON-RPC response for ${method}`);
    }
    if (response.error) {
      throw new JsonRpcError(response.error.code, response.error.message, response.error.data);
    }
    if (!isRecord(response.result)) {
      throw new JsonRpcError(-32603, `Malformed JSON-RPC result for ${method}`);
    }
    return response.result;
  }

  async discover(): Promise<Record<string, unknown>> {
    try {
      const res = await this.call("server/discover", {});
      if (Array.isArray(res.tools)) {
        const map = new Map<string, Tool>();
        for (const item of res.tools) {
          if (isRecord(item)) {
            const parsed = toolFromWire(item);
            map.set(parsed.name, parsed);
          }
        }
        this.toolsCache = map;
      }
      return res;
    } catch (err) {
      if (!(err instanceof JsonRpcError) || err.code !== METHOD_NOT_FOUND) {
        throw err;
      }
    }
    return this.initialize();
  }

  async initialize(protocolVersion = "2025-11-25"): Promise<Record<string, unknown>> {
    const initRes = await this.call("initialize", {
      protocolVersion,
      capabilities: {},
      clientInfo: { name: "@passmcp/sdk", version: "0.0.10" },
    });
    await this.send({ jsonrpc: "2.0", method: "notifications/initialized" });
    return initRes;
  }

  async ping(): Promise<Record<string, unknown>> {
    return this.call("ping");
  }

  async listTools(): Promise<Tool[]> {
    const res = await this.call("tools/list", {});
    if (!Array.isArray(res.tools)) {
      throw new JsonRpcError(-32603, "Invalid tools/list response");
    }
    const tools: Tool[] = [];
    const map = new Map<string, Tool>();
    for (const item of res.tools) {
      if (isRecord(item)) {
        const parsed = toolFromWire(item);
        tools.push(parsed);
        map.set(parsed.name, parsed);
      }
    }
    this.toolsCache = map;
    return tools;
  }

  async callTool(
    name: string,
    args?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    this.policy.checkTarget(this.transportKind, this.endpoint);
    if (this.toolsCache === null) {
      await this.listTools();
    }
    const tool = this.toolsCache?.get(name);
    if (!tool) {
      throw new JsonRpcError(-32602, `Unknown tool: ${name}`, { name });
    }
    this.policy.checkTool(tool);
    return this.call("tools/call", { name, arguments: args ?? {} });
  }

  async readResource(uri: string): Promise<Record<string, unknown>> {
    return this.call("resources/read", { uri });
  }

  async getPrompt(
    name: string,
    args?: Record<string, string>,
  ): Promise<Record<string, unknown>> {
    return this.call("prompts/get", {
      name,
      ...(args !== undefined ? { arguments: args } : {}),
    });
  }
}
