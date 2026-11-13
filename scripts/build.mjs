// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = resolve(import.meta.dirname, "..");
const SRC_DIR = join(ROOT, "src");
const DIST_DIR = join(ROOT, "dist");

rmSync(DIST_DIR, { recursive: true, force: true });
mkdirSync(DIST_DIR, { recursive: true });

const entries = readdirSync(SRC_DIR).filter((name) => name.endsWith(".ts"));
for (const entry of entries) {
  const source = readFileSync(join(SRC_DIR, entry), "utf8");
  const stripped = stripTypeScriptTypes(source, { mode: "strip" });
  const rewritten = stripped.replace(/(from\s+["']\.\/[^"']+)\.ts(["'])/g, "$1.js$2");
  const outName = entry.replace(/\.ts$/, ".js");
  writeFileSync(join(DIST_DIR, outName), rewritten, "utf8");
}

await import(pathToFileURL(join(DIST_DIR, "index.js")).href);
console.log(`build: emitted ${entries.length} ESM modules to dist/`);
