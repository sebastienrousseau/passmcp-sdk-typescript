// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = resolve(import.meta.dirname, "..");
const MAX_FILE_LINES = 500;

function collectSourceFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...collectSourceFiles(full));
    } else if (entry.endsWith(".ts") || entry.endsWith(".mjs")) {
      out.push(full);
    }
  }
  return out;
}

const dirs = ["src", "test", "examples", "scripts"].map((d) => join(ROOT, d));
const files = dirs.flatMap((d) => collectSourceFiles(d));

for (const file of files) {
  const content = readFileSync(file, "utf8");
  const lines = content.split("\n");
  if (lines.length > MAX_FILE_LINES) {
    console.error(`lint: ${file} has ${lines.length} lines (max ${MAX_FILE_LINES})`);
    process.exit(1);
  }
  if (file.endsWith(".ts") && /\b:\s*any\b|\bas\s+any\b|@ts-ignore\b/.test(content)) {
    console.error(`lint: ${file} contains forbidden 'any' or '@ts-ignore'`);
    process.exit(1);
  }
}

await import(pathToFileURL(join(ROOT, "src", "index.ts")).href);

if (existsSync(join(ROOT, "node_modules", "@types", "node"))) {
  const tscCheck = spawnSync("tsc", ["--version"], { stdio: "ignore" });
  if (tscCheck.status === 0) {
    const res = spawnSync("tsc", ["--project", join(ROOT, "tsconfig.json")], {
      stdio: "inherit",
    });
    if (res.status !== 0) {
      process.exit(res.status ?? 1);
    }
  }
}

console.log(`lint: ${files.length} source files verified with zero warnings`);
