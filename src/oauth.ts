// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { isRecord } from "./types.ts";

const PKCE_UNRESERVED_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
const AUTH_PARAM_RE = /([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^\s,]+))/g;

export class OAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OAuthError";
  }
}

export interface BearerChallenge {
  readonly resourceMetadata: string;
  readonly scope: string;
  readonly error: string;
  readonly errorDescription: string;
}

export interface ProtectedResourceMetadata {
  readonly resource: string;
  readonly authorizationServers: readonly string[];
  readonly scopesSupported: readonly string[];
  readonly bearerMethodsSupported: readonly string[];
}

export interface AuthorizationServerMetadata {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly codeChallengeMethodsSupported: readonly string[];
  readonly registrationEndpoint: string;
  readonly scopesSupported: readonly string[];
}

export function generatePkceVerifier(length = 64): string {
  if (typeof length !== "number" || !Number.isInteger(length) || length < 43 || length > 128) {
    throw new OAuthError("PKCE code_verifier length must be an integer between 43 and 128");
  }
  return randomBytes(96).toString("base64url").slice(0, length);
}

export function computeS256Challenge(verifier: string): string {
  if (typeof verifier !== "string" || !PKCE_UNRESERVED_RE.test(verifier)) {
    throw new OAuthError("PKCE code_verifier must be 43..128 RFC 7636 unreserved characters");
  }
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export function verifyS256(verifier: string, challenge: string): boolean {
  if (typeof challenge !== "string" || challenge.trim() === "") {
    return false;
  }
  let expected: string;
  try {
    expected = computeS256Challenge(verifier);
  } catch {
    return false;
  }
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(challenge, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function escapeQuoted(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export interface BearerChallengeInit {
  readonly resourceMetadata?: string;
  readonly scope?: string;
  readonly error?: string;
  readonly errorDescription?: string;
}

export function buildBearerChallenge(init?: BearerChallengeInit): string {
  const pairs: Array<[string, string | undefined]> = [
    ["resource_metadata", init?.resourceMetadata],
    ["scope", init?.scope],
    ["error", init?.error],
    ["error_description", init?.errorDescription],
  ];
  const parts: string[] = [];
  for (const [key, val] of pairs) {
    if (val && val.length > 0) {
      parts.push(`${key}="${escapeQuoted(val)}"`);
    }
  }
  return parts.length === 0 ? "Bearer" : `Bearer ${parts.join(", ")}`;
}

function extractAuthParams(afterScheme: string): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (const match of afterScheme.trim().matchAll(AUTH_PARAM_RE)) {
    const key = match[1].toLowerCase();
    const val = match[2] !== undefined ? match[2] : match[3];
    parsed[key] = val !== undefined ? val : "";
  }
  return parsed;
}

export function parseBearerChallenge(headerValue: string): BearerChallenge {
  const trimmed = headerValue.trim();
  if (!trimmed.toLowerCase().startsWith("bearer")) {
    throw new OAuthError("WWW-Authenticate header does not start with Bearer scheme");
  }
  const afterScheme = trimmed.slice(6);
  if (afterScheme.length > 0 && !/^\s/.test(afterScheme)) {
    throw new OAuthError("Invalid scheme prefix in WWW-Authenticate header");
  }
  const parsed = extractAuthParams(afterScheme);
  return {
    resourceMetadata: parsed.resource_metadata ?? "",
    scope: parsed.scope ?? "",
    error: parsed.error ?? "",
    errorDescription: parsed.error_description ?? "",
  };
}

function parseHttpsUrl(raw: string, label: string, allowLoopbackHttp = false): URL {
  if (typeof raw !== "string" || raw.trim() === "") {
    throw new OAuthError(`${label} must be a non-empty URL`);
  }
  let parsed: URL;
  try {
    parsed = new URL(raw.trim());
  } catch {
    throw new OAuthError(`Invalid ${label}: ${raw}`);
  }
  const loopback =
    allowLoopbackHttp &&
    parsed.protocol === "http:" &&
    ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname.toLowerCase());
  if (parsed.protocol !== "https:" && !loopback) {
    throw new OAuthError(`${label} must use https:// (got ${raw})`);
  }
  if (parsed.search || parsed.hash) {
    throw new OAuthError(`${label} must not carry query or hash: ${raw}`);
  }
  return parsed;
}

export function protectedResourceMetadataUrls(resourceUrl: string): readonly string[] {
  const parsed = parseHttpsUrl(resourceUrl, "resource URL", true);
  const cleanPath = parsed.pathname.replace(/\/+$/, "");
  const rootUrl = `${parsed.origin}/.well-known/oauth-protected-resource`;
  if (cleanPath === "") {
    return [rootUrl];
  }
  return [`${parsed.origin}/.well-known/oauth-protected-resource${cleanPath}`, rootUrl];
}

export function protectedResourceMetadataUrl(resourceUrl: string): string {
  return protectedResourceMetadataUrls(resourceUrl)[0];
}

export function authorizationServerMetadataUrl(issuerUrl: string): string {
  const parsed = parseHttpsUrl(issuerUrl, "issuer URL");
  const cleanPath = parsed.pathname.replace(/\/+$/, "");
  return cleanPath === ""
    ? `${parsed.origin}/.well-known/oauth-authorization-server`
    : `${parsed.origin}/.well-known/oauth-authorization-server${cleanPath}`;
}

function decodeMetadataObject(
  raw: string | Uint8Array | Record<string, unknown>,
  label: string,
): Record<string, unknown> {
  if (isRecord(raw)) {
    return raw;
  }
  try {
    const text =
      typeof raw === "string" ? raw : new TextDecoder("utf-8", { fatal: true }).decode(raw);
    const decoded: unknown = JSON.parse(text);
    if (!isRecord(decoded)) {
      throw new OAuthError(`${label} root must be a JSON object`);
    }
    return decoded;
  } catch (err) {
    if (err instanceof OAuthError) {
      throw err;
    }
    throw new OAuthError(`Invalid ${label} JSON: ${String(err)}`);
  }
}

function readStringList(obj: Record<string, unknown>, key: string): readonly string[] {
  const val = obj[key];
  if (val === undefined) {
    return [];
  }
  if (!Array.isArray(val) || !val.every((x) => typeof x === "string" && x.trim() !== "")) {
    throw new OAuthError(`${key} must be an array of non-empty strings`);
  }
  return [...val];
}

function canonicalResource(url: string): string {
  const parsed = parseHttpsUrl(url, "resource", true);
  const cleanPath = parsed.pathname.replace(/\/+$/, "");
  return `${parsed.origin}${cleanPath}`;
}

export function validateProtectedResourceMetadata(
  raw: string | Uint8Array | Record<string, unknown>,
  expectedResource: string,
): ProtectedResourceMetadata {
  const doc = decodeMetadataObject(raw, "Protected Resource Metadata");
  if (typeof doc.resource !== "string" || doc.resource.trim() === "") {
    throw new OAuthError("Protected Resource Metadata is missing 'resource'");
  }
  if (canonicalResource(doc.resource) !== canonicalResource(expectedResource)) {
    throw new OAuthError(
      `Protected Resource Metadata resource mismatch: got "${doc.resource}", expected "${expectedResource}"`,
    );
  }
  const authServers = readStringList(doc, "authorization_servers");
  if (authServers.length === 0) {
    throw new OAuthError("Protected Resource Metadata requires at least one authorization_server");
  }
  for (const srv of authServers) {
    parseHttpsUrl(srv, "authorization_server");
  }
  return {
    resource: doc.resource,
    authorizationServers: authServers,
    scopesSupported: readStringList(doc, "scopes_supported"),
    bearerMethodsSupported: readStringList(doc, "bearer_methods_supported"),
  };
}

function requireNonEmptyEndpoint(
  doc: Record<string, unknown>,
  field: string,
  allowLoopbackHttp: boolean,
): string {
  const val = doc[field];
  if (typeof val !== "string" || val.trim() === "") {
    throw new OAuthError(`Authorization Server Metadata is missing '${field}'`);
  }
  parseHttpsUrl(val, field, allowLoopbackHttp);
  return val;
}

export function validateAuthorizationServerMetadata(
  raw: string | Uint8Array | Record<string, unknown>,
  expectedIssuer?: string,
): AuthorizationServerMetadata {
  const doc = decodeMetadataObject(raw, "Authorization Server Metadata");
  const issuer = requireNonEmptyEndpoint(doc, "issuer", false);
  if (
    expectedIssuer !== undefined &&
    issuer.replace(/\/+$/, "") !== expectedIssuer.replace(/\/+$/, "")
  ) {
    throw new OAuthError(`Issuer mismatch: got "${issuer}", expected "${expectedIssuer}"`);
  }
  const authorizationEndpoint = requireNonEmptyEndpoint(doc, "authorization_endpoint", true);
  const tokenEndpoint = requireNonEmptyEndpoint(doc, "token_endpoint", true);
  const methods = readStringList(doc, "code_challenge_methods_supported");
  if (!methods.includes("S256")) {
    throw new OAuthError("OAuth 2.1 requires 'S256' in code_challenge_methods_supported");
  }
  const reg = doc.registration_endpoint;
  if (reg !== undefined && typeof reg !== "string") {
    throw new OAuthError("registration_endpoint must be a string");
  }
  return {
    issuer,
    authorizationEndpoint,
    tokenEndpoint,
    codeChallengeMethodsSupported: methods,
    registrationEndpoint: reg ?? "",
    scopesSupported: readStringList(doc, "scopes_supported"),
  };
}
