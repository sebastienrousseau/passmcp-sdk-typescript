// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { buildBearerChallenge } from "./oauth.ts";
import type { McpServer, OriginGuard } from "./server.ts";
import {
  HEADER_MISMATCH,
  INVALID_REQUEST,
  isRecord,
  JsonRpcError,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type McpRevision,
  META_PROTOCOL_VERSION,
  METHOD_NOT_FOUND,
  PARSE_ERROR,
  REVISION_2026_07_28,
  rpcError,
} from "./types.ts";

export type BearerValidator = (token: string) => Promise<boolean> | boolean;
export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export interface StreamableHttpOptions {
  readonly originGuard?: OriginGuard;
  readonly bearerValidator?: BearerValidator;
  readonly resourceMetadataUrl?: string;
  readonly requiredScope?: string;
  readonly enableSessions?: boolean;
  readonly requireSession?: boolean;
}

function jsonResponse(
  status: number,
  payload: unknown,
  extraHeaders?: Record<string, string>,
): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...(extraHeaders ?? {}),
    },
  });
}

function extractBearerToken(authHeader: string | null): string | null {
  if (!authHeader) {
    return null;
  }
  const match = /^\s*Bearer\s+(\S+)\s*$/i.exec(authHeader);
  return match ? match[1] : null;
}

function readRequestId(decoded: unknown): string | number | null {
  if (!isRecord(decoded)) {
    return null;
  }
  const rawId = decoded.id;
  return typeof rawId === "string" || typeof rawId === "number" ? rawId : null;
}

function readMetaProtocolVersion(decoded: unknown): string | undefined {
  if (!isRecord(decoded) || !isRecord(decoded.params) || !isRecord(decoded.params._meta)) {
    return undefined;
  }
  const bodyVer = decoded.params._meta[META_PROTOCOL_VERSION];
  return typeof bodyVer === "string" ? bodyVer : undefined;
}

function checkStatelessHeaders(req: Request, decoded: unknown): Response | null {
  const protoHdr = req.headers.get("MCP-Protocol-Version");
  const methodHdr = req.headers.get("MCP-Method");
  if (protoHdr !== REVISION_2026_07_28 && methodHdr === null) {
    return null;
  }
  const reqId = readRequestId(decoded);
  const bodyMethod = isRecord(decoded) ? decoded.method : undefined;
  if (methodHdr !== null && methodHdr !== bodyMethod) {
    return jsonResponse(
      400,
      rpcError(reqId, HEADER_MISMATCH, "MCP-Method header disagrees with body method"),
    );
  }
  const bodyVer = readMetaProtocolVersion(decoded);
  if (protoHdr !== null && bodyVer !== undefined && bodyVer !== protoHdr) {
    return jsonResponse(
      400,
      rpcError(reqId, HEADER_MISMATCH, "MCP-Protocol-Version disagrees with _meta"),
    );
  }
  return null;
}

function nodeRequestHeaders(req: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (typeof v === "string") {
      headers.set(k, v);
    } else if (Array.isArray(v) && v.length > 0) {
      headers.set(k, v[0]);
    }
  }
  return headers;
}

export class StreamableHttpHandler {
  readonly server: McpServer;
  private readonly originGuard?: OriginGuard;
  private readonly bearerValidator?: BearerValidator;
  private readonly resourceMetadataUrl: string;
  private readonly requiredScope: string;
  private readonly enableSessions: boolean;
  private readonly requireSession: boolean;
  private readonly sessions = new Set<string>();

  constructor(server: McpServer, options?: StreamableHttpOptions) {
    this.server = server;
    this.originGuard = options?.originGuard ?? server.originGuard;
    this.bearerValidator = options?.bearerValidator;
    this.resourceMetadataUrl = options?.resourceMetadataUrl ?? "";
    this.requiredScope = options?.requiredScope ?? "";
    this.requireSession = options?.requireSession ?? false;
    this.enableSessions =
      options?.enableSessions ?? (this.requireSession || server.revision !== REVISION_2026_07_28);
  }

  private async authenticate(req: Request): Promise<Response | null> {
    if (!this.bearerValidator) {
      return null;
    }
    const token = extractBearerToken(req.headers.get("Authorization"));
    if (token !== null && (await this.bearerValidator(token))) {
      return null;
    }
    const challenge = buildBearerChallenge({
      resourceMetadata: this.resourceMetadataUrl,
      scope: this.requiredScope,
      error: token !== null ? "invalid_token" : undefined,
    });
    return jsonResponse(401, rpcError(null, INVALID_REQUEST, "Unauthorized"), {
      "WWW-Authenticate": challenge,
    });
  }

  private checkSession(
    req: Request,
    decoded: unknown,
  ): { err: Response | null; headers: Record<string, string> } {
    if (!this.enableSessions) {
      return { err: null, headers: {} };
    }
    const method = isRecord(decoded) ? decoded.method : undefined;
    const reqId = readRequestId(decoded);
    const sid = req.headers.get("Mcp-Session-Id");
    if (method === "initialize") {
      const newSid = randomBytes(18).toString("base64url");
      this.sessions.add(newSid);
      return { err: null, headers: { "Mcp-Session-Id": newSid } };
    }
    if ((sid === null && this.requireSession) || (sid !== null && !this.sessions.has(sid))) {
      return {
        err: jsonResponse(404, rpcError(reqId, INVALID_REQUEST, "Unknown session")),
        headers: {},
      };
    }
    return { err: null, headers: sid ? { "Mcp-Session-Id": sid } : {} };
  }

  private async preflight(req: Request): Promise<Response | null> {
    if (this.originGuard !== undefined && !this.originGuard.isAllowed(req.headers.get("Origin"))) {
      return jsonResponse(403, rpcError(null, INVALID_REQUEST, "Forbidden Origin"));
    }
    const authErr = await this.authenticate(req);
    if (authErr !== null) {
      return authErr;
    }
    if (req.method.toUpperCase() !== "POST") {
      return jsonResponse(405, rpcError(null, INVALID_REQUEST, "Method Not Allowed"), {
        Allow: "POST",
      });
    }
    return null;
  }

  readonly fetch: FetchLike = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const req = input instanceof Request ? input : new Request(input, init);
    const pre = await this.preflight(req);
    if (pre !== null) {
      return pre;
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(await req.text());
    } catch {
      return jsonResponse(400, rpcError(null, PARSE_ERROR, "Parse error"));
    }
    const mismatch = checkStatelessHeaders(req, decoded);
    if (mismatch !== null) {
      return mismatch;
    }
    const sess = this.checkSession(req, decoded);
    if (sess.err !== null) {
      return sess.err;
    }
    const rpcResp = await this.server.handleRequest(decoded);
    if (rpcResp === null) {
      return new Response(null, { status: 202, headers: sess.headers });
    }
    const isUnknownOn2026 =
      this.server.revision === REVISION_2026_07_28 && rpcResp.error?.code === METHOD_NOT_FOUND;
    return jsonResponse(isUnknownOn2026 ? 404 : 200, rpcResp, sess.headers);
  };

  toNodeListener(): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
    return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.from(chunk as Uint8Array));
      }
      const method = req.method ?? "GET";
      const hasBody = method !== "GET" && method !== "HEAD";
      const webReq = new Request(`http://${req.headers.host ?? "127.0.0.1"}${req.url ?? "/mcp"}`, {
        method,
        headers: nodeRequestHeaders(req),
        body: hasBody ? Buffer.concat(chunks) : undefined,
      });
      const webResp = await this.fetch(webReq);
      const outHeaders: Record<string, string> = {};
      webResp.headers.forEach((val, key) => {
        outHeaders[key] = val;
      });
      res.writeHead(webResp.status, outHeaders);
      const bodyBuf = Buffer.from(await webResp.arrayBuffer());
      res.end(bodyBuf.length > 0 ? bodyBuf : undefined);
    };
  }

  createNodeServer(): Server {
    const listener = this.toNodeListener();
    return createServer((req, res) => {
      void listener(req, res);
    });
  }
}

export function createFetchHandler(
  server: McpServer,
  options?: StreamableHttpOptions,
): FetchLike {
  return new StreamableHttpHandler(server, options).fetch;
}

export interface HttpTransportOptions {
  readonly bearerToken?: string;
  readonly protocolVersion?: McpRevision | null;
  readonly headers?: Readonly<Record<string, string>>;
  readonly fetchFn?: FetchLike;
}

export class HttpClientTransport {
  readonly endpoint: string;
  readonly bearerToken?: string;
  readonly protocolVersion: McpRevision | null;
  sessionId: string | null = null;
  private readonly extraHeaders: Readonly<Record<string, string>>;
  private readonly fetchFn: FetchLike;

  constructor(endpoint: string, options?: HttpTransportOptions) {
    this.endpoint = endpoint;
    this.bearerToken = options?.bearerToken;
    this.protocolVersion =
      options?.protocolVersion === undefined ? REVISION_2026_07_28 : options.protocolVersion;
    this.extraHeaders = options?.headers ?? {};
    this.fetchFn = options?.fetchFn ?? fetch;
  }

  readonly send = async (payload: JsonRpcRequest): Promise<JsonRpcResponse | null> => {
    const hdrs: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...this.extraHeaders,
    };
    if (this.bearerToken) {
      hdrs.Authorization = `Bearer ${this.bearerToken}`;
    }
    if (this.sessionId) {
      hdrs["Mcp-Session-Id"] = this.sessionId;
    }
    if (this.protocolVersion === REVISION_2026_07_28) {
      hdrs["MCP-Protocol-Version"] = REVISION_2026_07_28;
      hdrs["MCP-Method"] = payload.method;
    }
    const resp = await this.fetchFn(this.endpoint, {
      method: "POST",
      headers: hdrs,
      body: JSON.stringify(payload),
    });
    const sid = resp.headers.get("Mcp-Session-Id");
    if (sid) {
      this.sessionId = sid;
    }
    if (resp.status === 202 || resp.status === 204) {
      return null;
    }
    const text = await resp.text();
    if (text.trim() === "") {
      if (resp.status >= 400) {
        throw new JsonRpcError(INVALID_REQUEST, `HTTP ${resp.status}`, {
          status: resp.status,
          wwwAuthenticate: resp.headers.get("WWW-Authenticate"),
        });
      }
      return null;
    }
    const decoded: unknown = JSON.parse(text);
    if (!isRecord(decoded)) {
      throw new JsonRpcError(INVALID_REQUEST, "Invalid JSON-RPC response envelope");
    }
    return decoded as unknown as JsonRpcResponse;
  };
}
