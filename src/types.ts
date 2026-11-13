// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

export const REVISION_2026_07_28 = "2026-07-28";
export const REVISION_2025_11_25 = "2025-11-25";
export const REVISION_2025_06_18 = "2025-06-18";

export type McpRevision =
  | typeof REVISION_2026_07_28
  | typeof REVISION_2025_11_25
  | typeof REVISION_2025_06_18;

export const SUPPORTED_REVISIONS: readonly McpRevision[] = [
  REVISION_2026_07_28,
  REVISION_2025_11_25,
  REVISION_2025_06_18,
];

export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const INTERNAL_ERROR = -32603;
export const LEGACY_RESOURCE_NOT_FOUND = -32002;
export const HEADER_MISMATCH = -32020;

export const META_SERVER_INFO = "io.modelcontextprotocol/serverInfo";
export const META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion";

export class JsonRpcError extends Error {
  readonly code: number;
  readonly data: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = "JsonRpcError";
    this.code = code;
    this.data = data;
  }

  toWire(): Record<string, unknown> {
    const out: Record<string, unknown> = { code: this.code, message: this.message };
    if (this.data !== undefined) {
      out.data = this.data;
    }
    return out;
  }
}

export interface ToolAnnotations {
  readonly title?: string;
  readonly readOnlyHint?: boolean;
  readonly destructiveHint?: boolean;
  readonly idempotentHint?: boolean;
  readonly openWorldHint?: boolean;
}

export interface Tool {
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly readOnlyHint?: boolean;
  readonly destructiveHint?: boolean;
  readonly idempotentHint?: boolean;
  readonly openWorldHint?: boolean;
  readonly annotations?: ToolAnnotations;
  readonly inputSchema?: Record<string, unknown>;
  readonly outputSchema?: Record<string, unknown>;
}

export interface ToolContentItem {
  readonly type: "text";
  readonly text: string;
}

export interface ToolCallOutput {
  readonly content: readonly ToolContentItem[];
  readonly structuredContent?: Record<string, unknown>;
  readonly isError?: boolean;
}

export interface Resource {
  readonly uri: string;
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly mimeType?: string;
}

export interface ResourceTemplate {
  readonly uriTemplate: string;
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly mimeType?: string;
}

export interface ResourceContent {
  readonly uri: string;
  readonly mimeType?: string;
  readonly text?: string;
  readonly blob?: string;
}

export interface PromptArgument {
  readonly name: string;
  readonly description?: string;
  readonly required?: boolean;
}

export interface Prompt {
  readonly name: string;
  readonly title?: string;
  readonly description?: string;
  readonly arguments?: readonly PromptArgument[];
}

export interface PromptMessage {
  readonly role: "user" | "assistant";
  readonly text: string;
}

export interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

export interface JsonRpcErrorBody {
  readonly code: number;
  readonly message: string;
  readonly data?: unknown;
}

export interface JsonRpcResponse {
  readonly jsonrpc: "2.0";
  readonly id: string | number | null;
  readonly result?: Record<string, unknown>;
  readonly error?: JsonRpcErrorBody;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function rpcResult(
  id: string | number | null,
  result: Record<string, unknown>,
): JsonRpcResponse {
  return { jsonrpc: "2.0", id, result };
}

export function rpcError(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown,
): JsonRpcResponse {
  const error = data !== undefined ? { code, message, data } : { code, message };
  return { jsonrpc: "2.0", id, error };
}

function setIfDefined(
  target: Record<string, unknown>,
  key: string,
  primary: unknown,
  fallback?: unknown,
): void {
  const chosen = primary !== undefined ? primary : fallback;
  if (chosen !== undefined) {
    target[key] = chosen;
  }
}

function buildToolAnnotationsWire(tool: Tool): Record<string, unknown> {
  const src = tool.annotations;
  const out: Record<string, unknown> = {
    readOnlyHint: (src?.readOnlyHint ?? tool.readOnlyHint) === true,
  };
  setIfDefined(out, "title", src?.title, tool.title);
  setIfDefined(out, "destructiveHint", src?.destructiveHint, tool.destructiveHint);
  setIfDefined(out, "idempotentHint", src?.idempotentHint, tool.idempotentHint);
  setIfDefined(out, "openWorldHint", src?.openWorldHint, tool.openWorldHint);
  return out;
}

export function toolToWire(tool: Tool): Record<string, unknown> {
  return {
    name: tool.name,
    ...(tool.title ? { title: tool.title } : {}),
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? { type: "object", properties: {} },
    ...(tool.outputSchema ? { outputSchema: tool.outputSchema } : {}),
    annotations: buildToolAnnotationsWire(tool),
  };
}

export function toolFromWire(raw: Record<string, unknown>): Tool {
  const name = raw.name;
  if (typeof name !== "string" || name.trim() === "") {
    throw new Error("Wire tool entry is missing a non-empty name");
  }
  const annotations = raw.annotations;
  const readOnly =
    (isRecord(annotations) && annotations.readOnlyHint === true) || raw.readOnlyHint === true;
  return {
    name,
    description: typeof raw.description === "string" ? raw.description : "",
    readOnlyHint: readOnly,
    inputSchema: isRecord(raw.inputSchema) ? raw.inputSchema : undefined,
    outputSchema: isRecord(raw.outputSchema) ? raw.outputSchema : undefined,
    title: typeof raw.title === "string" ? raw.title : undefined,
  };
}

export function resourceToWire(resource: Resource): Record<string, unknown> {
  return {
    uri: resource.uri,
    name: resource.name,
    ...(resource.title ? { title: resource.title } : {}),
    ...(resource.description ? { description: resource.description } : {}),
    mimeType: resource.mimeType ?? "text/plain",
  };
}

export function templateToWire(tpl: ResourceTemplate): Record<string, unknown> {
  return {
    uriTemplate: tpl.uriTemplate,
    name: tpl.name,
    ...(tpl.title ? { title: tpl.title } : {}),
    ...(tpl.description ? { description: tpl.description } : {}),
    ...(tpl.mimeType ? { mimeType: tpl.mimeType } : {}),
  };
}

export function promptToWire(prompt: Prompt): Record<string, unknown> {
  return {
    name: prompt.name,
    ...(prompt.title ? { title: prompt.title } : {}),
    ...(prompt.description ? { description: prompt.description } : {}),
    ...(prompt.arguments && prompt.arguments.length > 0
      ? {
          arguments: prompt.arguments.map((arg) => ({
            name: arg.name,
            required: arg.required === true,
            ...(arg.description ? { description: arg.description } : {}),
          })),
        }
      : {}),
  };
}

export function formatToolOutput(
  tool: Tool,
  out: ToolCallOutput | Record<string, unknown> | string,
): Record<string, unknown> {
  if (typeof out === "string") {
    return { content: [{ type: "text", text: out }] };
  }
  if ("content" in out && Array.isArray(out.content)) {
    const typed = out as ToolCallOutput;
    return {
      content: typed.content,
      ...(typed.structuredContent !== undefined
        ? { structuredContent: typed.structuredContent }
        : {}),
      ...(typed.isError !== undefined ? { isError: typed.isError } : {}),
    };
  }
  if (tool.outputSchema !== undefined) {
    return {
      content: [{ type: "text", text: JSON.stringify(out) }],
      structuredContent: out,
    };
  }
  return out as Record<string, unknown>;
}

export function formatResourceOutput(
  uri: string,
  mimeType: string,
  out: ResourceContent | readonly ResourceContent[] | string,
): Record<string, unknown> {
  if (typeof out === "string") {
    return { contents: [{ uri, mimeType, text: out }] };
  }
  return { contents: Array.isArray(out) ? out : [out] };
}

export function formatPromptOutput(
  description: string | undefined,
  out: readonly PromptMessage[] | Record<string, unknown> | string,
): Record<string, unknown> {
  if (typeof out === "string") {
    return {
      ...(description ? { description } : {}),
      messages: [{ role: "user", content: { type: "text", text: out } }],
    };
  }
  if (Array.isArray(out)) {
    return {
      ...(description ? { description } : {}),
      messages: out.map((m) => ({ role: m.role, content: { type: "text", text: m.text } })),
    };
  }
  return out as Record<string, unknown>;
}
