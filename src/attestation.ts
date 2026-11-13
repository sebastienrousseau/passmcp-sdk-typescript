// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { isRecord } from "./types.ts";

export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const PREDICATE_TYPE = "https://satellion.com/attestation/mcp-evaluation/v1";
export const SUBJECT_KIND_DESCRIPTOR = "mcp-target-descriptor";

const VALID_TRANSPORTS = new Set(["http", "stdio"]);
const VALID_STATUSES = new Set(["pass", "warn", "fail", "skip", "info"]);

export class AttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestationError";
  }
}

export class NoSuchCheckError extends Error {
  readonly checkId: string;

  constructor(checkId: string) {
    super(`attestation: the statement carries no verdict for that check: ${checkId}`);
    this.name = "NoSuchCheckError";
    this.checkId = checkId;
  }
}

export interface Subject {
  readonly name: string;
  readonly digest: Readonly<Record<string, string>>;
}

export interface ServerIdentity {
  readonly name: string;
  readonly version: string;
  readonly protocolVersion: string;
}

export interface Target {
  readonly transport: string;
  readonly endpoint: string;
  readonly server?: ServerIdentity;
}

export interface Basis {
  readonly specRevision: string;
  readonly rubric: string;
  readonly checkInventory: string;
}

export interface Instrument {
  readonly name: string;
  readonly version: string;
  readonly reportSchemaVersion: number;
}

export interface Verdict {
  readonly id: string;
  readonly phase: string;
  readonly status: string;
  readonly severity: string;
  readonly evidence: readonly string[];
  readonly doc: string;
}

export interface Counts {
  readonly pass: number;
  readonly warn: number;
  readonly fail: number;
  readonly skip: number;
  readonly info: number;
}

export interface Score {
  readonly total: number;
  readonly grade: string;
  readonly categoriesAssessed: number;
  readonly categoriesTotal: number;
}

export interface Evaluation {
  readonly subjectKind: string;
  readonly target: Target;
  readonly judgedAgainst: Basis;
  readonly instrument: Instrument;
  readonly ranAt: string;
  readonly took: string;
  readonly verdicts: readonly Verdict[];
  readonly counts: Counts;
  readonly score?: Score;
  readonly blocked: string;
  readonly traceId: string;
}

export function targetDescriptor(transport: string, endpoint: string): Buffer {
  return Buffer.from(`${transport}\n${endpoint.trim()}`, "utf8");
}

export function subjectFor(transport: string, endpoint: string): Subject {
  const sha256 = createHash("sha256")
    .update(targetDescriptor(transport, endpoint))
    .digest("hex");
  return { name: endpoint, digest: { sha256 } };
}

function checkDigestSet(
  digest: Readonly<Record<string, string>>,
  descriptor: Buffer,
): { found: boolean; mismatch: string } {
  const known: ReadonlyArray<readonly [string, string]> = [
    ["sha256", createHash("sha256").update(descriptor).digest("hex")],
    ["sha512", createHash("sha512").update(descriptor).digest("hex")],
  ];
  let found = false;
  let mismatch = "";
  for (const [alg, expected] of known) {
    if (!Object.hasOwn(digest, alg)) {
      continue;
    }
    found = true;
    if (digest[alg] !== expected && mismatch === "") {
      mismatch = alg;
    }
  }
  return { found, mismatch };
}

export class Statement {
  readonly type: string;
  readonly subject: readonly Subject[];
  readonly predicateType: string;
  readonly predicate: Evaluation;

  constructor(
    type: string,
    subject: readonly Subject[],
    predicateType: string,
    predicate: Evaluation,
  ) {
    this.type = type;
    this.subject = subject;
    this.predicateType = predicateType;
    this.predicate = predicate;
  }

  get scoreTotal(): number | undefined {
    return this.predicate.score?.total;
  }

  get scoreGrade(): string | undefined {
    return this.predicate.score?.grade;
  }

  covers(transport: string, endpoint: string): boolean {
    if (this.subject.length !== 1) {
      return false;
    }
    const { found, mismatch } = checkDigestSet(
      this.subject[0].digest,
      targetDescriptor(transport, endpoint),
    );
    return found && mismatch === "";
  }

  verdictFor(checkId: string): Verdict {
    for (const verdict of this.predicate.verdicts) {
      if (verdict.id === checkId) {
        return verdict;
      }
    }
    throw new NoSuchCheckError(checkId);
  }
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new AttestationError(`attestation: ${label} must be an object`);
  }
  return value;
}

function strField(obj: Record<string, unknown>, key: string): string {
  const val = obj[key];
  if (val === undefined || val === null) {
    return "";
  }
  if (typeof val !== "string") {
    throw new AttestationError(`attestation: ${key} must be a string`);
  }
  return val;
}

function intField(obj: Record<string, unknown>, key: string): number {
  const val = obj[key];
  if (val === undefined) {
    return 0;
  }
  if (typeof val !== "number" || !Number.isInteger(val)) {
    throw new AttestationError(`attestation: ${key} must be an integer`);
  }
  return val;
}

function isValidTimestamp(ranAt: string): boolean {
  const trimmed = ranAt.trim();
  if (trimmed === "" || trimmed.startsWith("0001-01-01T00:00:00")) {
    return false;
  }
  const ms = Date.parse(trimmed);
  return !Number.isNaN(ms);
}

function parseSubjects(raw: unknown): readonly Subject[] {
  if (raw === undefined || raw === null) {
    return [];
  }
  if (!Array.isArray(raw)) {
    throw new AttestationError("attestation: subject must be an array");
  }
  return raw.map((entry) => {
    const sub = requireObject(entry, "subject entry");
    const rawDigest = sub.digest;
    const digest: Record<string, string> = {};
    if (rawDigest !== undefined && rawDigest !== null) {
      const map = requireObject(rawDigest, "subject.digest");
      for (const [k, v] of Object.entries(map)) {
        if (typeof v !== "string") {
          throw new AttestationError("attestation: subject.digest values must be strings");
        }
        digest[k] = v;
      }
    }
    return { name: strField(sub, "name"), digest };
  });
}

function parseVerdicts(raw: unknown): readonly Verdict[] {
  if (raw === undefined || raw === null) {
    return [];
  }
  if (!Array.isArray(raw)) {
    throw new AttestationError("attestation: predicate.verdicts must be an array");
  }
  return raw.map((entry) => {
    const item = requireObject(entry, "verdict");
    let evidence: string[] = [];
    if (item.evidence !== undefined && item.evidence !== null) {
      if (!Array.isArray(item.evidence) || !item.evidence.every((x) => typeof x === "string")) {
        throw new AttestationError("attestation: verdict.evidence must be a string array");
      }
      evidence = [...item.evidence];
    }
    return {
      id: strField(item, "id"),
      phase: strField(item, "phase"),
      status: strField(item, "status"),
      severity: strField(item, "severity"),
      evidence,
      doc: strField(item, "doc"),
    };
  });
}

function parseServerIdentity(raw: unknown): ServerIdentity | undefined {
  if (raw === undefined || raw === null) {
    return undefined;
  }
  const srvObj = requireObject(raw, "predicate.target.server");
  return {
    name: strField(srvObj, "name"),
    version: strField(srvObj, "version"),
    protocolVersion: strField(srvObj, "protocolVersion"),
  };
}

function parseScore(raw: unknown): Score | undefined {
  if (raw === undefined || raw === null) {
    return undefined;
  }
  const scoreObj = requireObject(raw, "predicate.score");
  if (typeof scoreObj.total !== "number" || !Number.isFinite(scoreObj.total)) {
    throw new AttestationError("attestation: score.total must be numeric");
  }
  return {
    total: scoreObj.total,
    grade: strField(scoreObj, "grade"),
    categoriesAssessed: intField(scoreObj, "categoriesAssessed"),
    categoriesTotal: intField(scoreObj, "categoriesTotal"),
  };
}

function parseEvaluation(rawPred: unknown): Evaluation {
  const pred = requireObject(rawPred ?? {}, "predicate");
  const targetObj = requireObject(pred.target ?? {}, "predicate.target");
  const basisObj = requireObject(pred.judgedAgainst ?? {}, "predicate.judgedAgainst");
  const instObj = requireObject(pred.instrument ?? {}, "predicate.instrument");
  const countsObj = requireObject(pred.counts ?? {}, "predicate.counts");
  return {
    subjectKind: strField(pred, "subjectKind"),
    target: {
      transport: strField(targetObj, "transport"),
      endpoint: strField(targetObj, "endpoint"),
      server: parseServerIdentity(targetObj.server),
    },
    judgedAgainst: {
      specRevision: strField(basisObj, "specRevision"),
      rubric: strField(basisObj, "rubric"),
      checkInventory: strField(basisObj, "checkInventory"),
    },
    instrument: {
      name: strField(instObj, "name"),
      version: strField(instObj, "version"),
      reportSchemaVersion: intField(instObj, "reportSchemaVersion"),
    },
    ranAt: strField(pred, "ranAt"),
    took: strField(pred, "took"),
    verdicts: parseVerdicts(pred.verdicts),
    counts: {
      pass: intField(countsObj, "pass"),
      warn: intField(countsObj, "warn"),
      fail: intField(countsObj, "fail"),
      skip: intField(countsObj, "skip"),
      info: intField(countsObj, "info"),
    },
    score: parseScore(pred.score),
    blocked: strField(pred, "blocked"),
    traceId: strField(pred, "traceId"),
  };
}

function validateSubject(
  subjects: readonly Subject[],
  target: Target,
  problems: string[],
): void {
  if (subjects.length === 0) {
    problems.push("no subject: the statement is about nothing");
    return;
  }
  if (subjects.length > 1) {
    problems.push(`${subjects.length} subjects: a passmcp evaluation is about one server`);
    return;
  }
  const sub = subjects[0];
  const want = target.endpoint.trim();
  if (sub.name.trim() === "") {
    problems.push("the subject has no name");
  } else if (sub.name.trim() !== want) {
    problems.push(`the subject is named "${sub.name}" but the predicate is about "${want}"`);
  }
  const { found, mismatch } = checkDigestSet(
    sub.digest,
    targetDescriptor(target.transport, target.endpoint),
  );
  if (!found) {
    problems.push("the subject has no sha256 or sha512 digest");
  } else if (mismatch !== "") {
    problems.push(`the subject ${mismatch} digest does not cover the target it names`);
  }
}

function validateTargetAndInstrument(pred: Evaluation, problems: string[]): void {
  if (pred.subjectKind !== SUBJECT_KIND_DESCRIPTOR) {
    problems.push(`subjectKind is "${pred.subjectKind}", want "${SUBJECT_KIND_DESCRIPTOR}"`);
  }
  if (pred.target.endpoint.trim() === "") {
    problems.push("the target has no endpoint");
  }
  if (pred.target.transport === "") {
    problems.push("the target has no transport");
  } else if (!VALID_TRANSPORTS.has(pred.target.transport)) {
    problems.push(`unknown transport "${pred.target.transport}"`);
  }
  if (pred.instrument.name.trim() === "" || pred.instrument.version.trim() === "") {
    problems.push("the instrument is not identified");
  }
}

function validatePredicateFields(pred: Evaluation, problems: string[]): void {
  validateTargetAndInstrument(pred, problems);
  if (!isValidTimestamp(pred.ranAt)) {
    problems.push("no run time: a verdict about a live service is a verdict about a moment");
  }
  if (pred.verdicts.length === 0) {
    problems.push("no verdicts");
  }
  if (pred.judgedAgainst.checkInventory.trim() === "") {
    problems.push("judgedAgainst.checkInventory is empty");
  }
  if (pred.score !== undefined && pred.judgedAgainst.rubric.trim() === "") {
    problems.push("a score with no rubric version");
  }
}

function validateVerdicts(pred: Evaluation, problems: string[]): void {
  const tallied = { pass: 0, warn: 0, fail: 0, skip: 0, info: 0 };
  for (let i = 0; i < pred.verdicts.length; i += 1) {
    const verdict = pred.verdicts[i];
    if (verdict.id.trim() === "") {
      problems.push(`verdict ${i} has no id`);
      continue;
    }
    if (!VALID_STATUSES.has(verdict.status)) {
      problems.push(`verdict ${verdict.id} has status "${verdict.status}"`);
    } else {
      const key = verdict.status as keyof Counts;
      tallied[key] += 1;
    }
  }
  const c = pred.counts;
  const countsMatch =
    tallied.pass === c.pass &&
    tallied.warn === c.warn &&
    tallied.fail === c.fail &&
    tallied.skip === c.skip &&
    tallied.info === c.info;
  if (pred.verdicts.length > 0 && !countsMatch) {
    problems.push("the counts disagree with the verdicts");
  }
}

export function parseStatement(raw: string | Uint8Array): Statement {
  let text: string;
  if (typeof raw === "string") {
    text = raw;
  } else {
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch (err) {
      throw new AttestationError(`attestation: not a statement: ${String(err)}`);
    }
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch (err) {
    throw new AttestationError(`attestation: not a statement: ${String(err)}`);
  }
  const root = requireObject(decoded, "not a statement: root");
  const stmt = new Statement(
    strField(root, "_type"),
    parseSubjects(root.subject),
    strField(root, "predicateType"),
    parseEvaluation(root.predicate),
  );
  const problems: string[] = [];
  if (stmt.type !== STATEMENT_TYPE) {
    problems.push(`_type is "${stmt.type}", want "${STATEMENT_TYPE}"`);
  }
  if (stmt.predicateType !== PREDICATE_TYPE) {
    problems.push(`predicateType is "${stmt.predicateType}", want "${PREDICATE_TYPE}"`);
  }
  validateSubject(stmt.subject, stmt.predicate.target, problems);
  validatePredicateFields(stmt.predicate, problems);
  validateVerdicts(stmt.predicate, problems);
  if (problems.length > 0) {
    throw new AttestationError(`attestation: ${problems.join("; ")}`);
  }
  return stmt;
}
