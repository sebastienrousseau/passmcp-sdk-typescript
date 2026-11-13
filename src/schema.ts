// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { INVALID_PARAMS, isRecord, JsonRpcError } from "./types.ts";

export type CacheScope = "public" | "private";

export interface CacheHintsInit {
  readonly cacheable?: boolean;
  readonly ttl?: number;
  readonly ttlMs?: number;
  readonly scope?: CacheScope;
  readonly cacheScope?: CacheScope;
}

function requireNonNegativeInt(value: number, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new RangeError(`${label} must be an integer >= 0`);
  }
  return value;
}

function resolveTtlMs(init: CacheHintsInit): number {
  if (init.ttlMs !== undefined) {
    const ms = requireNonNegativeInt(init.ttlMs, "CacheHints.ttlMs");
    return init.cacheable === false ? 0 : ms;
  }
  if (init.ttl !== undefined) {
    const secs = requireNonNegativeInt(init.ttl, "CacheHints.ttl");
    return init.cacheable === false ? 0 : secs * 1000;
  }
  if (init.cacheable === false) {
    return 0;
  }
  throw new RangeError("CacheHints requires ttlMs, ttl, or cacheable: false");
}

export class CacheHints {
  readonly ttlMs: number;
  readonly cacheScope: CacheScope;

  constructor(ttlMsOrInit: number | CacheHintsInit, cacheScope: CacheScope = "private") {
    if (typeof ttlMsOrInit === "number") {
      if (!Number.isInteger(ttlMsOrInit) || ttlMsOrInit < 0) {
        throw new RangeError("CacheHints.ttlMs must be an integer >= 0");
      }
      if (cacheScope !== "public" && cacheScope !== "private") {
        throw new RangeError("CacheHints.cacheScope must be 'public' or 'private'");
      }
      this.ttlMs = ttlMsOrInit;
      this.cacheScope = cacheScope;
      return;
    }
    const resolvedScope = ttlMsOrInit.scope ?? ttlMsOrInit.cacheScope ?? "private";
    if (resolvedScope !== "public" && resolvedScope !== "private") {
      throw new RangeError("CacheHints.cacheScope must be 'public' or 'private'");
    }
    this.ttlMs = resolveTtlMs(ttlMsOrInit);
    this.cacheScope = resolvedScope;
  }

  get cacheable(): boolean {
    return this.ttlMs > 0;
  }

  get ttl(): number {
    return Math.floor(this.ttlMs / 1000);
  }

  get scope(): CacheScope {
    return this.cacheScope;
  }

  toMeta(): Record<string, unknown> {
    return { ttlMs: this.ttlMs, cacheScope: this.cacheScope };
  }

  applyToList(payload: Record<string, unknown>): Record<string, unknown> {
    return {
      ...payload,
      ttlMs: this.ttlMs,
      cacheScope: this.cacheScope,
      _meta: this.toMeta(),
    };
  }
}

function matchesJsonType(expected: string, value: unknown): boolean {
  switch (expected) {
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "object":
      return isRecord(value);
    case "array":
      return Array.isArray(value);
    case "null":
      return value === null;
    default:
      return true;
  }
}

function validatePropertyValue(
  key: string,
  propSchema: Record<string, unknown>,
  value: unknown,
): void {
  const expected = propSchema.type;
  if (typeof expected === "string" && !matchesJsonType(expected, value)) {
    throw new JsonRpcError(INVALID_PARAMS, `Invalid argument "${key}": expected ${expected}`, {
      argument: key,
      expected,
    });
  }
  if (
    Array.isArray(expected) &&
    !expected.some((t) => typeof t === "string" && matchesJsonType(t, value))
  ) {
    throw new JsonRpcError(INVALID_PARAMS, `Invalid argument "${key}": wrong type`, {
      argument: key,
    });
  }
  if (Array.isArray(propSchema.enum) && !propSchema.enum.includes(value)) {
    throw new JsonRpcError(INVALID_PARAMS, `Invalid argument "${key}": value not in enum`, {
      argument: key,
    });
  }
}

function checkRequiredKeys(required: unknown, args: Record<string, unknown>): void {
  if (!Array.isArray(required)) {
    return;
  }
  for (const reqKey of required) {
    if (typeof reqKey === "string" && !Object.hasOwn(args, reqKey)) {
      throw new JsonRpcError(INVALID_PARAMS, `Missing required argument: ${reqKey}`, {
        argument: reqKey,
      });
    }
  }
}

export function validateObjectSchema(
  schema: Record<string, unknown> | undefined,
  args: Record<string, unknown>,
): void {
  if (!schema) {
    return;
  }
  if (!isRecord(args)) {
    throw new JsonRpcError(INVALID_PARAMS, "Invalid params: arguments must be an object");
  }
  checkRequiredKeys(schema.required, args);
  const props = isRecord(schema.properties) ? schema.properties : {};
  if (schema.additionalProperties === false) {
    for (const key of Object.keys(args)) {
      if (!Object.hasOwn(props, key)) {
        throw new JsonRpcError(INVALID_PARAMS, `Unexpected argument: ${key}`, { argument: key });
      }
    }
  }
  for (const [key, val] of Object.entries(args)) {
    const propSchema = props[key];
    if (isRecord(propSchema)) {
      validatePropertyValue(key, propSchema, val);
    }
  }
}
