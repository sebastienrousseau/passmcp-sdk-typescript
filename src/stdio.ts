// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { type ChildProcess, spawn } from "node:child_process";
import { createInterface, type Interface as ReadlineInterface } from "node:readline";
import { PassThrough, type Readable, type Writable } from "node:stream";
import type { McpServer } from "./server.ts";
import {
  INTERNAL_ERROR,
  isRecord,
  JsonRpcError,
  type JsonRpcRequest,
  type JsonRpcResponse,
} from "./types.ts";

export async function serveStdio(
  server: McpServer,
  input: Readable = process.stdin,
  output: Writable = process.stdout,
): Promise<void> {
  const rl = createInterface({ input, crlfDelay: Infinity });
  for await (const line of rl) {
    const stripped = line.trim();
    if (stripped === "") {
      continue;
    }
    const response = await server.handleJson(stripped);
    if (response === null) {
      continue;
    }
    const singleLine = response.replace(/[\r\n]+/g, "");
    await new Promise<void>((resolveWrite, rejectWrite) => {
      output.write(`${singleLine}\n`, "utf8", (err) => {
        if (err) {
          rejectWrite(err);
        } else {
          resolveWrite();
        }
      });
    });
  }
}

export interface StdioSpawnOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly cwd?: string;
}

export class StdioTransport {
  private readonly writer: Writable;
  private readonly rl: ReadlineInterface;
  private readonly lineQueue: string[] = [];
  private readonly waiters: Array<{
    resolve: (line: string) => void;
    reject: (err: Error) => void;
  }> = [];
  private readonly child?: ChildProcess;
  private readonly serverTask?: Promise<void>;
  private closed = false;

  constructor(
    writer: Writable,
    reader: Readable,
    options?: { child?: ChildProcess; serverTask?: Promise<void> },
  ) {
    this.writer = writer;
    this.child = options?.child;
    this.serverTask = options?.serverTask;
    this.rl = createInterface({ input: reader, crlfDelay: Infinity });
    this.rl.on("line", (line) => {
      const waiter = this.waiters.shift();
      if (waiter) {
        waiter.resolve(line);
      } else {
        this.lineQueue.push(line);
      }
    });
    this.rl.on("close", () => {
      this.closed = true;
      while (this.waiters.length > 0) {
        this.waiters.shift()?.reject(new JsonRpcError(INTERNAL_ERROR, "Unexpected EOF on stdio"));
      }
    });
  }

  static fromStreams(writer: Writable, reader: Readable): StdioTransport {
    return new StdioTransport(writer, reader);
  }

  static fromInMemoryServer(server: McpServer): StdioTransport {
    const clientToServer = new PassThrough();
    const serverToClient = new PassThrough();
    const task = serveStdio(server, clientToServer, serverToClient).finally(() => {
      serverToClient.end();
    });
    return new StdioTransport(clientToServer, serverToClient, { serverTask: task });
  }

  static spawn(
    command: string,
    args: readonly string[] = [],
    options?: StdioSpawnOptions,
  ): StdioTransport {
    if (command.trim() === "") {
      throw new Error("StdioTransport.spawn requires a non-empty command");
    }
    const child = spawn(command, [...args], {
      stdio: ["pipe", "pipe", "pipe"],
      env: options?.env,
      cwd: options?.cwd,
    });
    if (!child.stdin || !child.stdout) {
      throw new Error("Failed to open stdio pipes on child process");
    }
    return new StdioTransport(child.stdin, child.stdout, { child });
  }

  private readNextLine(): Promise<string> {
    const queued = this.lineQueue.shift();
    if (queued !== undefined) {
      return Promise.resolve(queued);
    }
    if (this.closed) {
      return Promise.reject(new JsonRpcError(INTERNAL_ERROR, "StdioTransport is closed"));
    }
    return new Promise<string>((resolveLine, rejectLine) => {
      this.waiters.push({ resolve: resolveLine, reject: rejectLine });
    });
  }

  readonly send = async (request: JsonRpcRequest): Promise<JsonRpcResponse | null> => {
    if (this.closed) {
      throw new JsonRpcError(INTERNAL_ERROR, "StdioTransport is closed");
    }
    const frame = `${JSON.stringify(request)}\n`;
    await new Promise<void>((resolveWrite, rejectWrite) => {
      this.writer.write(frame, "utf8", (err) => {
        if (err) {
          rejectWrite(err);
        } else {
          resolveWrite();
        }
      });
    });
    if (!Object.hasOwn(request, "id")) {
      return null;
    }
    const line = await this.readNextLine();
    let decoded: unknown;
    try {
      decoded = JSON.parse(line);
    } catch (err) {
      throw new JsonRpcError(INTERNAL_ERROR, `Invalid JSON frame from stdio: ${String(err)}`);
    }
    if (!isRecord(decoded)) {
      throw new JsonRpcError(INTERNAL_ERROR, "Non-object JSON-RPC frame from stdio");
    }
    return decoded as unknown as JsonRpcResponse;
  };

  async close(): Promise<void> {
    this.closed = true;
    this.writer.end();
    this.rl.close();
    if (this.serverTask) {
      await this.serverTask;
    }
    if (this.child && this.child.exitCode === null) {
      await new Promise<void>((resolveExit) => {
        const timer = setTimeout(() => {
          this.child?.kill("SIGTERM");
        }, 1500);
        this.child?.once("exit", () => {
          clearTimeout(timer);
          resolveExit();
        });
      });
    }
  }
}
