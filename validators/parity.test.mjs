#!/usr/bin/env node
/**
 * Cross-implementation parity test for the profile validators.
 *
 * Runs every bundled vector through both validators — the JavaScript module
 * directly, and the Python CLI in one subprocess per receipt — and compares
 * three things per vector: the JavaScript classification, the Python
 * classification, and the classification the vector itself declares. Any
 * disagreement in pass/fail, in the error code, or in the non-failing notes is
 * a failure, so the two implementations cannot drift apart silently.
 *
 * Usage: node validators/parity.test.mjs   (exit 0 = agreement, 1 = drift)
 * Set PYTHON to choose the interpreter (default: python3).
 *
 * License: Apache 2.0.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyReceipt } from "./check_profile.mjs";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const REPO = join(HERE, "..");
const VECTORS_PATH = join(REPO, "vectors", "vectors.json");
const PYTHON_VALIDATOR = join(REPO, "validators", "check_profile.py");
const PYTHON = process.env.PYTHON || "python3";

const vectors = JSON.parse(readFileSync(VECTORS_PATH, "utf-8"));
const keys = vectors.keys;
const workspaceId = keys.workspace_id;
const fingerprints = keys.keys.map((key) => key.public_key_fingerprint);
const items = [
  ...vectors.valid.map((item) => ({ ...item, expectation: "valid" })),
  ...vectors.invalid.map((item) => ({ ...item, expectation: "invalid" })),
];
// Chain checks (§8) see every receipt in the bundle, valid and invalid alike:
// that is what a partial export looks like to a verifier.
const scope = new Map(items.map((item) => [item.receipt.receipt_id, item.receipt]));

/** Normalize one implementation's answer to {code, notes} for comparison. */
function outcome(code, notes) {
  return { code: code ?? null, notes: [...notes].sort() };
}

function describe(result) {
  const notes = result.notes.length ? ` notes=[${result.notes.join(",")}]` : "";
  return `${result.code === null ? "pass" : result.code}${notes}`;
}

function same(left, right) {
  return (
    left.code === right.code &&
    left.notes.length === right.notes.length &&
    left.notes.every((note, index) => note === right.notes[index])
  );
}

async function runJavaScript(receipt) {
  const { base, profile } = await verifyReceipt(receipt, { keys, scope, workspaceId });
  const code = base.errors[0] ?? profile.errors[0] ?? null;
  if (code === null && !(base.ok && profile.ok)) {
    throw new Error("JavaScript validator reported failure without an error code");
  }
  return outcome(code, profile.notes);
}

const workDirectory = mkdtempSync(join(tmpdir(), "profile-parity-"));

function runPython(receipt, name) {
  const receiptPath = join(workDirectory, `${name}.json`);
  writeFileSync(receiptPath, JSON.stringify({ receipt, keys }), "utf-8");
  const args = [
    PYTHON_VALIDATOR,
    receiptPath,
    "--workspace-id",
    workspaceId,
    "--scope",
    VECTORS_PATH,
  ];
  for (const fingerprint of fingerprints) args.push("--trusted-key-fingerprint", fingerprint);

  let stdout;
  let stderr = "";
  let status = 0;
  try {
    stdout = execFileSync(PYTHON, args, { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    if (error.status === undefined) {
      throw new Error(`could not run ${PYTHON}: ${error.message}`);
    }
    status = error.status;
    stdout = error.stdout ?? "";
    stderr = error.stderr ?? "";
    if (status !== 1) {
      throw new Error(`${PYTHON} ${PYTHON_VALIDATOR} exited ${status}\n${stderr}`.trim());
    }
  }
  const lines = stdout.split("\n").map((line) => line.trim()).filter(Boolean);
  if (status === 0) {
    if (lines[0] !== "profile receipt passed") {
      throw new Error(`unexpected Python output: ${JSON.stringify(stdout)}`);
    }
    return outcome(
      null,
      lines.slice(1).map((line) => {
        if (!line.startsWith("note:")) {
          throw new Error(`unexpected Python output line: ${JSON.stringify(line)}`);
        }
        return line.slice("note:".length);
      }),
    );
  }
  if (lines.length !== 1) {
    throw new Error(
      `expected one Python failure code, got ${JSON.stringify(stdout)}\n${stderr}`.trim(),
    );
  }
  return outcome(lines[0], []);
}

const failures = [];
try {
  for (const item of items) {
    const declared =
      item.expectation === "valid"
        ? outcome(null, item.notes ?? [])
        : outcome(item.reason, []);
    const javascript = await runJavaScript(item.receipt);
    const python = runPython(item.receipt, item.receipt.receipt_id);

    if (!same(javascript, python)) {
      failures.push(
        `${item.name}: implementations disagree — js ${describe(javascript)}, ` +
          `python ${describe(python)}`,
      );
      continue;
    }
    if (!same(javascript, declared)) {
      failures.push(
        `${item.name}: both implementations returned ${describe(javascript)}, ` +
          `vector declares ${describe(declared)}`,
      );
    }
  }
} finally {
  rmSync(workDirectory, { recursive: true, force: true });
}

if (failures.length) {
  for (const failure of failures) console.error(failure);
  console.error(`\n${failures.length} of ${items.length} vectors disagree`);
  process.exit(1);
}
console.log(`profile validators agree on ${items.length} vectors`);
