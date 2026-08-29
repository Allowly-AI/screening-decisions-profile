/**
 * Screening Decisions Profile validator — JavaScript.
 *
 * A single self-contained ES module with no dependencies. It runs unmodified
 * in a modern browser and in Node 20+ (WebCrypto: `globalThis.crypto.subtle`;
 * Ed25519 must be available there).
 *
 * Two layers, in the order the profile requires (spec §9):
 *   1. a base-format precheck for wire version "4" — canonicalization per the
 *      base spec §4 rules, then Ed25519 signature verification against a
 *      caller-supplied key document, with key_id selection and public-key
 *      fingerprint trust;
 *   2. the profile layer — vocabulary and decision-tier mapping, per-action
 *      context requirements, subject/resource equality, knockout shape, the
 *      single permitted candidate-value location, the provenance gate, the PII
 *      deny-list, the extension-key prefix rule, and the §8 chain checks.
 *
 * Trust rules are the same as the Python validator's: the workspace identity
 * and the trusted signing-key fingerprints MUST come from caller-trusted
 * configuration, never from the receipt being checked.
 *
 * Error codes are the profile's stable strings and match the Python validator
 * exactly; both layers report the first failing check, so a receipt's
 * classification does not depend on which implementation ran it.
 *
 * License: Apache 2.0.
 */

// --------------------------------------------------------------------------
// Base format (wire "4")
// --------------------------------------------------------------------------

const SPEC_VERSION = "4";
const ACTION_DECISIONS = new Set(["allow", "deny", "confirm", "escalate"]);
const EVENT_DECISIONS = new Map([
  ["authorization.create", new Set(["authorization_granted"])],
  ["authorization.revoke", new Set(["authorization_revoked"])],
  ["budget.settle", new Set(["budget_settled"])],
  ["escalation.resolve", new Set(["escalation_approved", "escalation_rejected"])],
  ["receipt.checkpoint", new Set(["receipt_set_committed"])],
]);
const AUTHORIZATION_LIFECYCLE_EVENTS = new Set([
  "authorization.create",
  "authorization.revoke",
]);
const EVENT_ONLY_DECISIONS = new Set(
  [...EVENT_DECISIONS.values()].flatMap((decisions) => [...decisions]),
);
const REQUIRED_FIELDS = [
  "schema_version",
  "receipt_id",
  "workspace_id",
  "issued_at",
  "decision",
  "reason",
  "user_id",
  "agent_id",
  "resource",
  "context",
  "authorization_id",
  "engine_version",
  "alg",
  "key_id",
  "signature",
];
const OPTIONAL_FIELDS = ["policy_eval"];
const DISCRIMINATOR_FIELDS = ["action", "event"];
const ALL_TOP_LEVEL_FIELDS = new Set([
  ...REQUIRED_FIELDS,
  ...DISCRIMINATOR_FIELDS,
  ...OPTIONAL_FIELDS,
]);
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
// I-JSON / RFC 8785 safe-integer bound (base spec §4.2 rule 6).
const MAX_SAFE_INTEGER_BOUND = Number.MAX_SAFE_INTEGER;
// Depth/node limits, so a hostile receipt fails as a verification error rather
// than exhausting the stack or memory during canonicalization.
const MAX_PAYLOAD_DEPTH = 32;
const MAX_PAYLOAD_NODES = 50000;
const B64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const RFC3339_RE =
  /^(?!0000)([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z$/;
// With the `u` flag this matches only *lone* surrogates: a surrogate pair is a
// single code point above U+FFFF and therefore outside the class. Canonical
// bytes must be reproducible across languages, so lone surrogates are refused.
const LONE_SURROGATE_RE = /[\uD800-\uDFFF]/u;
const CHECKPOINT_ROOT_RE = /^sha256:[0-9a-f]{64}$/;
const CHECKPOINT_CONTEXT_FIELDS = new Set([
  "period_start",
  "period_end",
  "receipt_count",
  "merkle_root",
  "previous_checkpoint_id",
  "previous_merkle_root",
]);
const DAY_MS = 24 * 60 * 60 * 1000;

/** Raised when a receipt fails any base verification step. */
export class VerificationError extends Error {
  constructor(message) {
    super(message);
    this.name = "VerificationError";
  }
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isInteger(value) {
  return typeof value === "number" && Number.isInteger(value);
}

function subtle() {
  const webcrypto = globalThis.crypto;
  if (!webcrypto || !webcrypto.subtle) {
    throw new VerificationError(
      "WebCrypto is unavailable; a secure context (or Node 20+) is required",
    );
  }
  return webcrypto.subtle;
}

/**
 * Decode unpadded base64url, refusing both out-of-alphabet characters and
 * non-canonical encodings (trailing bits that are not zero), as base spec §5.1
 * requires.
 */
export function b64urlDecode(text) {
  if (typeof text !== "string") {
    throw new VerificationError("not unpadded base64url: expected a string");
  }
  if (text.length % 4 === 1) {
    throw new VerificationError(`not unpadded base64url: ${JSON.stringify(text)}`);
  }
  const out = [];
  let accumulator = 0;
  let bits = 0;
  for (const character of text) {
    const value = B64URL_ALPHABET.indexOf(character);
    if (value < 0) {
      throw new VerificationError(`not unpadded base64url: ${JSON.stringify(text)}`);
    }
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((accumulator >> bits) & 0xff);
    }
  }
  if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) {
    throw new VerificationError(`non-canonical base64url: ${JSON.stringify(text)}`);
  }
  return Uint8Array.from(out);
}

function toHex(bytes) {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/** Canonical `sha256:<hex>` fingerprint of raw Ed25519 public-key bytes. */
export async function publicKeyFingerprint(publicKeyBytes) {
  const digest = await subtle().digest("SHA-256", publicKeyBytes);
  return `sha256:${toHex(new Uint8Array(digest))}`;
}

/**
 * Parse the format's exact UTC millisecond timestamp profile and return epoch
 * milliseconds. Shape-valid but impossible dates (Feb 30, hour 25) are
 * rejected by the component round-trip.
 */
function parseTimestamp(text) {
  const match = typeof text === "string" ? RFC3339_RE.exec(text) : null;
  if (!match) {
    throw new VerificationError(
      "timestamp must be UTC millisecond precision YYYY-MM-DDTHH:MM:SS.sssZ, " +
        `got ${JSON.stringify(text)}`,
    );
  }
  const [year, month, day, hour, minute, second, millisecond] = match
    .slice(1)
    .map(Number);
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, millisecond);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second ||
    date.getUTCMilliseconds() !== millisecond
  ) {
    throw new VerificationError(`not a real calendar date/time: ${text}`);
  }
  return date.getTime();
}

/**
 * Iterative pre-walk before encoding: bound depth and size, refuse lone
 * surrogates, and refuse non-integer or unsafe numbers (base spec §4.2 rules 1
 * and 6).
 *
 * Note the one thing JSON text cannot tell a JavaScript reader: `3.0` and `3`
 * parse to the same Number, so a fractional-looking-but-whole value is
 * indistinguishable from an integer here. Every value that is genuinely
 * fractional is still refused, and the canonical bytes are identical either
 * way, so signatures agree across languages.
 */
function validateTree(payload) {
  let nodes = 0;
  const stack = [[payload, 1]];
  while (stack.length) {
    const [value, depth] = stack.pop();
    nodes += 1;
    if (depth > MAX_PAYLOAD_DEPTH) {
      throw new VerificationError(
        `payload nesting exceeds max depth ${MAX_PAYLOAD_DEPTH}`,
      );
    }
    if (nodes > MAX_PAYLOAD_NODES) {
      throw new VerificationError(`payload exceeds max node count ${MAX_PAYLOAD_NODES}`);
    }
    if (value === null || typeof value === "boolean") continue;
    if (typeof value === "number") {
      if (!Number.isInteger(value)) {
        throw new VerificationError("receipts must not contain non-integer numbers");
      }
      if (Math.abs(value) > MAX_SAFE_INTEGER_BOUND) {
        throw new VerificationError(
          `integer ${value} exceeds the safe range ±(2^53-1); receipts must not ` +
            "carry integers that lose precision in IEEE-754 doubles",
        );
      }
    } else if (typeof value === "string") {
      if (LONE_SURROGATE_RE.test(value)) {
        throw new VerificationError("string contains an unpaired Unicode surrogate");
      }
    } else if (Array.isArray(value)) {
      for (const item of value) stack.push([item, depth + 1]);
    } else if (isPlainObject(value)) {
      for (const [key, child] of Object.entries(value)) {
        if (LONE_SURROGATE_RE.test(key)) {
          throw new VerificationError("string contains an unpaired Unicode surrogate");
        }
        stack.push([child, depth + 1]);
      }
    } else {
      throw new VerificationError(`unsupported type in payload: ${typeof value}`);
    }
  }
}

/**
 * Serialize a JSON string per base spec §4.2 rule 5: escape only `"`, `\` and
 * U+0000–U+001F (as lowercase `\uXXXX`); pass non-ASCII through.
 */
function encodeString(text) {
  let out = '"';
  for (const character of text) {
    if (character === '"') out += '\\"';
    else if (character === "\\") out += "\\\\";
    else if (character.codePointAt(0) < 0x20) {
      out += `\\u${character.codePointAt(0).toString(16).padStart(4, "0")}`;
    } else out += character;
  }
  return `${out}"`;
}

function encodeValue(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return encodeString(value);
  if (Array.isArray(value)) return `[${value.map(encodeValue).join(",")}]`;
  if (isPlainObject(value)) {
    // JavaScript compares strings by UTF-16 code unit, which is exactly the
    // order base spec §4.2 rule 3 mandates — unlike a code-point sort, which
    // orders non-BMP keys differently.
    const keys = Object.keys(value).sort();
    return `{${keys
      .map((key) => `${encodeString(key)}:${encodeValue(value[key])}`)
      .join(",")}}`;
  }
  throw new VerificationError(`unsupported type in payload: ${typeof value}`);
}

/** Canonical JSON bytes per base spec §4. */
export function canonicalize(payload) {
  validateTree(payload);
  return new TextEncoder().encode(encodeValue(payload));
}

function checkExactKeys(object, expected, prefix) {
  const present = new Set(Object.keys(object));
  const extra = [...present].filter((key) => !expected.has(key)).sort();
  const missing = [...expected].filter((key) => !present.has(key)).sort();
  if (extra.length) {
    throw new VerificationError(`${prefix} has unknown fields: ${extra.join(", ")}`);
  }
  if (missing.length) {
    throw new VerificationError(`${prefix} missing fields: ${missing.join(", ")}`);
  }
}

function isPolicyScalar(value) {
  return value === null || typeof value === "string" || typeof value === "boolean" ||
    isInteger(value);
}

function isPolicyConditionValue(value) {
  if (isPolicyScalar(value)) return true;
  return Array.isArray(value) && value.every(isPolicyScalar);
}

function checkPolicyEval(value) {
  if (!isPlainObject(value)) throw new VerificationError("policy_eval must be an object");
  checkExactKeys(value, new Set(["matched_condition", "field_value"]), "policy_eval");
  const matched = value.matched_condition;
  if (matched !== null) {
    if (!isPlainObject(matched)) {
      throw new VerificationError("policy_eval.matched_condition must be an object or null");
    }
    checkExactKeys(
      matched,
      new Set(["field", "op", "value"]),
      "policy_eval.matched_condition",
    );
    if (typeof matched.field !== "string") {
      throw new VerificationError("policy_eval.matched_condition.field must be a string");
    }
    if (typeof matched.op !== "string") {
      throw new VerificationError("policy_eval.matched_condition.op must be a string");
    }
    if (!isPolicyConditionValue(matched.value)) {
      throw new VerificationError(
        "policy_eval.matched_condition.value must be string, integer, boolean, null, " +
          "or an array of those",
      );
    }
  }
  if (!isPolicyScalar(value.field_value)) {
    throw new VerificationError(
      "policy_eval.field_value must be string, integer, boolean, or null",
    );
  }
}

function checkSchema(receipt) {
  const present = Object.keys(receipt);
  const extra = present.filter((field) => !ALL_TOP_LEVEL_FIELDS.has(field)).sort();
  if (extra.length) {
    throw new VerificationError(`unknown top-level fields: ${extra.join(", ")}`);
  }
  const missing = REQUIRED_FIELDS.filter((field) => !present.includes(field)).sort();
  if (missing.length) {
    throw new VerificationError(`missing top-level fields: ${missing.join(", ")}`);
  }
  for (const field of [
    "schema_version",
    "receipt_id",
    "workspace_id",
    "issued_at",
    "decision",
    "reason",
    "user_id",
    "agent_id",
    "engine_version",
    "alg",
    "key_id",
    "signature",
  ]) {
    if (typeof receipt[field] !== "string") {
      throw new VerificationError(`${field} must be a string`);
    }
  }
  for (const field of ["resource", "authorization_id"]) {
    if (!(typeof receipt[field] === "string" || receipt[field] === null)) {
      throw new VerificationError(`${field} must be string or null`);
    }
  }
  if (!isPlainObject(receipt.context)) {
    throw new VerificationError("context must be an object");
  }
  // Signature text must be canonical base64url decoding to exactly 64 bytes,
  // which rejects placeholders before verification is attempted.
  let signatureBytes;
  try {
    signatureBytes = b64urlDecode(receipt.signature);
  } catch {
    throw new VerificationError(
      `signature is not valid canonical base64url: ${JSON.stringify(receipt.signature)}`,
    );
  }
  if (signatureBytes.length !== 64) {
    throw new VerificationError(
      `signature must decode to 64 bytes (Ed25519), got ${signatureBytes.length}`,
    );
  }
  if ("policy_eval" in receipt) checkPolicyEval(receipt.policy_eval);
  return signatureBytes;
}

function checkCheckpointContext(value, issuedAt) {
  if (!isPlainObject(value)) {
    throw new VerificationError("receipt.checkpoint context must be an object");
  }
  checkExactKeys(value, CHECKPOINT_CONTEXT_FIELDS, "receipt.checkpoint context");
  const periodStart = parseTimestamp(value.period_start);
  const periodEnd = parseTimestamp(value.period_end);
  const checkpointAt = parseTimestamp(issuedAt);
  if (periodEnd <= periodStart) {
    throw new VerificationError("receipt.checkpoint period_end must be after period_start");
  }
  if (periodStart % DAY_MS !== 0 || periodEnd - periodStart !== DAY_MS) {
    throw new VerificationError("receipt.checkpoint period must be one UTC calendar day");
  }
  if (checkpointAt < periodEnd) {
    throw new VerificationError(
      "receipt.checkpoint issued_at must be at or after period_end",
    );
  }
  const count = value.receipt_count;
  if (!isInteger(count) || count < 0) {
    throw new VerificationError(
      "receipt.checkpoint receipt_count must be a non-negative integer",
    );
  }
  if (typeof value.merkle_root !== "string" || !CHECKPOINT_ROOT_RE.test(value.merkle_root)) {
    throw new VerificationError(
      "receipt.checkpoint merkle_root must be sha256:<64 lowercase hex>",
    );
  }
  const previousId = value.previous_checkpoint_id;
  const previousRoot = value.previous_merkle_root;
  if ((previousId === null) !== (previousRoot === null)) {
    throw new VerificationError(
      "receipt.checkpoint previous id and root must both be null or strings",
    );
  }
  if (previousId !== null && typeof previousId !== "string") {
    throw new VerificationError(
      "receipt.checkpoint previous_checkpoint_id must be string or null",
    );
  }
  if (
    previousRoot !== null &&
    (typeof previousRoot !== "string" || !CHECKPOINT_ROOT_RE.test(previousRoot))
  ) {
    throw new VerificationError(
      "receipt.checkpoint previous_merkle_root must be sha256:<64 lowercase hex> or null",
    );
  }
}

/**
 * Parse the workspace key document (the dashboard download, or the public
 * `GET /v1/workspaces/{workspace_id}/keys` response) into verification keys.
 *
 * Duplicate key ids and duplicate public keys are refused so key lookup is
 * unambiguous and one public key cannot carry two active windows.
 */
export async function loadKeysFromJson(document) {
  if (
    !isPlainObject(document) ||
    typeof document.workspace_id !== "string" ||
    !document.workspace_id ||
    !Array.isArray(document.keys)
  ) {
    throw new VerificationError(
      "keys document must be an object with a non-empty 'workspace_id' and a 'keys' array",
    );
  }
  const out = [];
  const seenIds = new Set();
  const seenPublicKeys = new Set();
  for (const [index, entry] of document.keys.entries()) {
    if (!isPlainObject(entry)) {
      throw new VerificationError(`keys[${index}] must be an object`);
    }
    for (const field of ["key_id", "alg", "public_key", "active_from"]) {
      if (typeof entry[field] !== "string") {
        throw new VerificationError(`keys[${index}].${field} must be a string`);
      }
    }
    if (entry.alg !== "Ed25519") {
      throw new VerificationError(`keys[${index}].alg must be 'Ed25519'`);
    }
    if (
      !("active_until" in entry) ||
      !(entry.active_until === null || typeof entry.active_until === "string")
    ) {
      throw new VerificationError(`keys[${index}].active_until must be a string or null`);
    }
    if (seenIds.has(entry.key_id)) {
      throw new VerificationError(`duplicate key_id in keys document: ${entry.key_id}`);
    }
    if (seenPublicKeys.has(entry.public_key)) {
      throw new VerificationError(`duplicate public key in keys document: ${entry.key_id}`);
    }
    seenIds.add(entry.key_id);
    seenPublicKeys.add(entry.public_key);
    let publicKeyBytes;
    try {
      publicKeyBytes = b64urlDecode(entry.public_key);
    } catch {
      throw new VerificationError(`keys[${index}].public_key is not valid base64url`);
    }
    if (publicKeyBytes.length !== 32) {
      throw new VerificationError(
        `keys[${index}].public_key must decode to 32 bytes, got ${publicKeyBytes.length}`,
      );
    }
    const key = {
      keyId: entry.key_id,
      alg: entry.alg,
      publicKeyBytes,
      activeFrom: parseTimestamp(entry.active_from),
      activeUntil: entry.active_until === null ? null : parseTimestamp(entry.active_until),
    };
    if (
      "public_key_fingerprint" in entry &&
      entry.public_key_fingerprint !== (await publicKeyFingerprint(publicKeyBytes))
    ) {
      throw new VerificationError(
        `keys[${index}].public_key_fingerprint does not match public_key`,
      );
    }
    out.push(key);
  }
  return out;
}

function findKey(keys, keyId, issuedAt) {
  for (const key of keys) {
    if (key.keyId !== keyId) continue;
    if (key.alg !== "Ed25519") {
      throw new VerificationError(`unsupported public key alg: ${key.alg}`);
    }
    if (!(key.publicKeyBytes instanceof Uint8Array) || key.publicKeyBytes.length !== 32) {
      throw new VerificationError("selected Ed25519 public key must contain 32 raw bytes");
    }
    if (key.activeUntil !== null && key.activeUntil <= key.activeFrom) {
      throw new VerificationError("selected public key active window is empty");
    }
    if (issuedAt < key.activeFrom) {
      throw new VerificationError(`key ${keyId} not yet active at issued_at`);
    }
    if (key.activeUntil !== null && issuedAt >= key.activeUntil) {
      throw new VerificationError(`key ${keyId} retired before issued_at`);
    }
    return key;
  }
  throw new VerificationError(`no public key found for key_id=${keyId}`);
}

/**
 * Verify one receipt against the base format (wire "4"). Resolves on success
 * and rejects with a `VerificationError` on any failure.
 *
 * `expectedWorkspaceId` and `trustedKeyFingerprints` are the caller's trust
 * anchors: a key id alone does not bind a receipt to a workspace, and a key
 * document travelling with a receipt vouches for nothing.
 */
export async function verifyBaseReceipt(receipt, keys, options = {}) {
  const { now = Date.now(), expectedWorkspaceId = null, trustedKeyFingerprints = null } =
    options;
  if (!isPlainObject(receipt)) throw new VerificationError("receipt must be an object");

  if (receipt.schema_version !== SPEC_VERSION) {
    throw new VerificationError(
      `unsupported schema_version: ${JSON.stringify(receipt.schema_version)} ` +
        `(want ${JSON.stringify(SPEC_VERSION)})`,
    );
  }
  if (expectedWorkspaceId !== null && receipt.workspace_id !== expectedWorkspaceId) {
    throw new VerificationError(
      `workspace_id mismatch: receipt has ${JSON.stringify(receipt.workspace_id)}, ` +
        `expected ${JSON.stringify(expectedWorkspaceId)}`,
    );
  }

  const signatureBytes = checkSchema(receipt);

  const hasAction = "action" in receipt;
  const hasEvent = "event" in receipt;
  const { decision, authorization_id: authorizationId, resource } = receipt;
  if (hasAction && hasEvent) {
    throw new VerificationError(
      "receipt has both 'action' and 'event'; exactly one must be present",
    );
  }
  if (!hasAction && !hasEvent) {
    throw new VerificationError(
      "receipt has neither 'action' nor 'event'; exactly one must be present",
    );
  }

  if (hasEvent) {
    const event = receipt.event;
    if (typeof event !== "string") throw new VerificationError("event must be a string");
    if (!EVENT_DECISIONS.has(event)) {
      throw new VerificationError(
        `event must be one of ${[...EVENT_DECISIONS.keys()].sort().join(", ")}, ` +
          `got ${JSON.stringify(event)}`,
      );
    }
    const expected = EVENT_DECISIONS.get(event);
    if (!expected.has(decision)) {
      throw new VerificationError(
        `event receipt with event=${JSON.stringify(event)} must have decision in ` +
          `${[...expected].sort().join(", ")}, got ${JSON.stringify(decision)}`,
      );
    }
    if (event === "receipt.checkpoint") {
      if (authorizationId !== null) {
        throw new VerificationError("receipt.checkpoint must have null authorization_id");
      }
      if (resource !== null) {
        throw new VerificationError("receipt.checkpoint must have null resource");
      }
      checkCheckpointContext(receipt.context, receipt.issued_at);
    } else if (authorizationId === null) {
      throw new VerificationError(
        `event receipt with event=${JSON.stringify(event)} must have non-null authorization_id`,
      );
    }
    if (AUTHORIZATION_LIFECYCLE_EVENTS.has(event) && resource !== null) {
      throw new VerificationError(
        `authorization lifecycle receipt with event=${JSON.stringify(event)} must have ` +
          "null resource",
      );
    }
    if ("policy_eval" in receipt) {
      throw new VerificationError("policy_eval must be absent on event receipts");
    }
  } else {
    const action = receipt.action;
    if (typeof action !== "string") throw new VerificationError("action must be a string");
    if (EVENT_ONLY_DECISIONS.has(decision)) {
      throw new VerificationError(
        `decision=${JSON.stringify(decision)} requires an event receipt (event field), ` +
          `got an action receipt with action=${JSON.stringify(action)}`,
      );
    }
    if (!ACTION_DECISIONS.has(decision)) {
      throw new VerificationError(
        `action receipt must have decision in ${[...ACTION_DECISIONS].sort().join(", ")}, ` +
          `got ${JSON.stringify(decision)}`,
      );
    }
  }

  if (receipt.alg !== "Ed25519") {
    throw new VerificationError(`unsupported signature alg: ${JSON.stringify(receipt.alg)}`);
  }

  const issuedAt = parseTimestamp(receipt.issued_at);
  if (issuedAt > now + MAX_FUTURE_SKEW_MS) {
    throw new VerificationError(`receipt issued in the future: ${receipt.issued_at}`);
  }

  const payload = {};
  for (const [key, value] of Object.entries(receipt)) {
    if (key !== "signature") payload[key] = value;
  }
  const canonical = canonicalize(payload);

  const key = findKey(keys, receipt.key_id, issuedAt);
  const fingerprint = await publicKeyFingerprint(key.publicKeyBytes);
  if (trustedKeyFingerprints !== null && !trustedKeyFingerprints.has(fingerprint)) {
    throw new VerificationError(`public key fingerprint is not trusted: ${fingerprint}`);
  }
  const publicKey = await subtle().importKey(
    "raw",
    key.publicKeyBytes,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const valid = await subtle().verify("Ed25519", publicKey, signatureBytes, canonical);
  if (!valid) throw new VerificationError("signature verification failed");
}

// --------------------------------------------------------------------------
// Profile layer
// --------------------------------------------------------------------------

const DIGEST_PREFIX = "sha256:";
const CANDIDATE_PREFIX = "candidate:";

// Profile §6: the producer's knockout attestation is exactly these four keys —
// no fewer (the compared scalar is the evidence) and no more (a fifth key is
// where a second copy of the candidate's data would ride along).
const KNOCKOUT_KEYS = ["field", "op", "value", "field_value"];

// Profile §7: the provenance map is exactly these two keys, each a list of
// field names.
const PROVENANCE_KEYS = ["customer", "cv"];

// Profile §5: a screen's subject is the opaque candidate id plus the digest
// that distinguishes one submitted payload from the next; a scan digest is the
// one permitted addition.
const SUBJECT_KEYS = ["uuid", "payload_digest"];
const SUBJECT_OPTIONAL_KEYS = ["file_digest"];

const PII_KEYS = new Set([
  "address",
  "dob",
  "email",
  "first_name",
  "full_name",
  "last_name",
  "linkedin_url",
  "name",
  "phone",
  "photo_url",
  "ssn",
]);

// `reason` is the ISSUER's machine code (base §3.1); the producer's screening
// semantics live in context (tier, detail_code, knockout, review_*).
const SCREEN_REASONS = new Set([
  "allow authorization_granted_action_active",
  "deny deny_condition_matched",
  "confirm confirm_condition_matched",
  "confirm context_field_missing",
  "escalate escalate_condition_matched",
  "escalate context_field_missing",
]);

// Profile §4: the decision verb and the tier are different vocabularies and are
// resolved through this table, never by comparing the two strings.
const TIER_BY_DECISION = {
  allow: "advance",
  deny: "deny",
  confirm: "confirm",
  escalate: "escalate",
};
const REVIEW_DECISION_BY_DECISION = { allow: "advance", deny: "reject" };
const OPAQUE_SOURCE_ID_RE =
  /^[a-z][a-z0-9_]{1,31}:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const OPAQUE_WORKSPACE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const POLICY_ID_RE =
  /^[A-Za-z0-9][A-Za-z0-9._:-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:-]*)*$/;
const POLICY_VERSION_RE =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const STANDARD_CONTEXT_KEYS = new Map([
  [
    "candidate.screen",
    new Set([
      "subject",
      "requisition_id",
      "fields_supplied_by",
      "tier",
      "criteria_passed",
      "criteria_failed",
      "detail_code",
      "knockout",
      "knockout_id",
      "citation",
      "replaces_receipt",
      "on_behalf_of",
      "organization",
      "operator",
    ]),
  ],
  [
    "candidate.review",
    new Set([
      "review_decision",
      "replaces_receipt",
      "requisition_id",
      "review_basis",
      "subject",
      "on_behalf_of",
      "organization",
      "operator",
    ]),
  ],
  ["adverse_action.issue", new Set(["decision_refs", "subject", "on_behalf_of", "organization", "operator"])],
  ["audit.export", new Set(["manifest_digest", "filter", "on_behalf_of", "organization", "operator"])],
  [
    "authorization.create",
    new Set([
      "policy",
      "replaces",
      "on_behalf_of",
      "organization",
      "operator",
      "approval_schema_version",
      "approval_id",
      "approval_digest",
      "approving_user_id",
      "organization_id",
      "identity_assurance",
      "authentication_credential_id",
      "funnelops_workspace_id",
    ]),
  ],
  ["authorization.revoke", new Set(["revoked_by", "superseded_by", "on_behalf_of", "organization", "operator"])],
]);

function receiptAction(receipt) {
  return receipt.action || receipt.event;
}

function isDigest(value) {
  return typeof value === "string" && value.startsWith(DIGEST_PREFIX) &&
    value.length > DIGEST_PREFIX.length;
}

function isStringList(value) {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function hasExactKeys(object, expected) {
  const keys = Object.keys(object);
  return keys.length === expected.length && expected.every((key) => keys.includes(key));
}

/** The `<uuid>` of a `candidate:<uuid>` resource, else null. */
function candidateUuid(resource) {
  if (typeof resource === "string" && resource.startsWith(CANDIDATE_PREFIX)) {
    return resource.slice(CANDIDATE_PREFIX.length);
  }
  return null;
}

function* walkObjects(value) {
  if (isPlainObject(value)) {
    yield value;
    for (const child of Object.values(value)) yield* walkObjects(child);
  } else if (Array.isArray(value)) {
    for (const child of value) yield* walkObjects(child);
  }
}

/**
 * Profile §6: a knockout denial is a `candidate.screen` receipt deciding
 * `deny`. Agreement between the decision and `context.tier` is a separate
 * check, so a denial carrying the wrong tier is rejected there rather than
 * silently losing its knockout exemption here.
 */
function isKnockoutDenial(receipt) {
  return receiptAction(receipt) === "candidate.screen" && receipt.decision === "deny";
}

/**
 * Profile §7 minimization: one candidate value, in one place.
 *
 * `context.knockout.field_value` is the compared scalar behind a knockout
 * denial, and is the only candidate value permitted anywhere in `context` — and
 * only on a receipt that is a knockout denial. On every other receipt
 * `context.knockout` is an ordinary container with no exemption, so a name, an
 * address or a salary parked there is caught like any other stray value. The
 * top-level `policy_eval.field_value` is outside `context` and outside this
 * check by design: it records the issuer's routing value, not a candidate's
 * data.
 */
function candidateValueCheck(receipt) {
  const context = receipt.context;
  const permitted = isKnockoutDenial(receipt) ? context.knockout : null;
  for (const holder of walkObjects(context)) {
    if ("field_value" in holder && holder !== permitted) {
      return "candidate_value_outside_knockout";
    }
  }
  return null;
}

function piiCheck(value) {
  if (isPlainObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (PII_KEYS.has(key.toLowerCase())) return "pii_in_context";
      const childError = piiCheck(child);
      if (childError !== null) return childError;
    }
  } else if (Array.isArray(value)) {
    for (const child of value) {
      const childError = piiCheck(child);
      if (childError !== null) return childError;
    }
  } else if (typeof value === "string" && value.includes("@")) {
    return "pii_in_context";
  }
  return null;
}

function contextKeyCheck(receipt) {
  const allowed = STANDARD_CONTEXT_KEYS.get(receiptAction(receipt));
  if (allowed === undefined) return null;
  for (const key of Object.keys(receipt.context)) {
    if (!allowed.has(key) && !key.startsWith("x_")) return "unprefixed_extension_context";
  }
  return null;
}

/**
 * Profile §7: `fields_supplied_by` is `{"customer": [...], "cv": [...]}`, each
 * a list of field names.
 *
 * The shape carries the §6 gate. A bare string under `"customer"` would turn
 * the gate's membership test into substring containment, so that a knockout on
 * `work_authorization` would clear a map that supplies only
 * `"work_authorization_asserted_by_vendor"` — the CV-only case §6 declares
 * non-conformant, admitted by a spelling. Both provenance keys are required and
 * no others are accepted, on the same reasoning as the four-key knockout shape:
 * an extra key is where a second copy of the candidate's data rides.
 */
function provenanceMapCheck(supplied) {
  if (!isPlainObject(supplied) || !hasExactKeys(supplied, PROVENANCE_KEYS)) {
    return "invalid_fields_supplied_by";
  }
  for (const names of Object.values(supplied)) {
    if (!isStringList(names)) return "invalid_fields_supplied_by";
  }
  return null;
}

function policyContextCheck(policy) {
  if (!isPlainObject(policy) || !hasExactKeys(policy, ["id", "version", "digest"])) {
    return "missing_policy_context";
  }
  if (
    typeof policy.id !== "string" ||
    policy.id.length < 1 ||
    policy.id.length > 128 ||
    !POLICY_ID_RE.test(policy.id) ||
    hasFunnelOpsSecretComponent(policy.id) ||
    typeof policy.version !== "string" ||
    policy.version.length < 5 ||
    policy.version.length > 32 ||
    !POLICY_VERSION_RE.test(policy.version)
  ) {
    return "missing_policy_context";
  }
  return isDigest(policy.digest) ? null : "missing_policy_context";
}

function hasFunnelOpsSecretComponent(value) {
  // This recognizes FunnelOps API-key-shaped components, not arbitrary semantics.
  return value.split(/[:/]/u).some((component) => component.startsWith("fops_"));
}

function organizationCheck(context) {
  const organization = context.organization;
  if (organization === undefined) return null;
  if (
    !isPlainObject(organization) ||
    !hasExactKeys(organization, ["id", "workspace_id"]) ||
    !OPAQUE_SOURCE_ID_RE.test(organization.id) ||
    typeof organization.workspace_id !== "string" ||
    !OPAQUE_WORKSPACE_ID_RE.test(organization.workspace_id) ||
    hasFunnelOpsSecretComponent(organization.workspace_id)
  ) {
    return "invalid_organization_context";
  }
  if (typeof context.operator !== "string" || !context.operator) {
    return "missing_operator_context";
  }
  return null;
}

function approvalContextCheck(context) {
  const keys = [
    "approval_schema_version",
    "approval_id",
    "approval_digest",
    "approving_user_id",
    "organization_id",
    "identity_assurance",
    "authentication_credential_id",
    "funnelops_workspace_id",
  ];
  const present = keys.filter((key) => key in context);
  if (present.length === 0) return null;
  if (present.length !== keys.length) return "missing_approval_context";
  if (context.approval_schema_version !== "policy_approval.v1") {
    return "unsupported_approval_schema";
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(context.approval_digest)) {
    return "invalid_approval_digest";
  }
  for (const key of [
    "approval_id",
    "approving_user_id",
    "organization_id",
    "authentication_credential_id",
  ]) {
    if (
      typeof context[key] !== "string" ||
      !OPAQUE_SOURCE_ID_RE.test(context[key]) ||
      hasFunnelOpsSecretComponent(context[key])
    ) {
      return "invalid_approval_identity";
    }
  }
  if (
    typeof context.funnelops_workspace_id !== "string" ||
    !OPAQUE_WORKSPACE_ID_RE.test(context.funnelops_workspace_id) ||
    hasFunnelOpsSecretComponent(context.funnelops_workspace_id)
  ) {
    return "invalid_approval_identity";
  }
  if (!new Set(["authenticated_user", "organization_asserted"]).has(
    context.identity_assurance,
  )) {
    return "invalid_identity_assurance";
  }
  if (
    !isPlainObject(context.organization) ||
    context.organization.id !== context.organization_id ||
    context.organization.workspace_id !== context.funnelops_workspace_id
  ) {
    return "organization_approval_mismatch";
  }
  if (context.operator !== "FunnelOps") return "approval_operator_mismatch";
  return null;
}

function candidateScreenCheck(receipt) {
  const context = receipt.context;
  if (!("subject" in context) || !("requisition_id" in context)) {
    return "missing_subject_or_requisition";
  }
  // Profile §5: `resource` is the canonical candidate link, and a screen's
  // subject must name the same candidate.
  const subject = context.subject;
  const resourceUuid = candidateUuid(receipt.resource);
  if (!isPlainObject(subject) || resourceUuid === null) return "subject_resource_mismatch";
  if (subject.uuid !== resourceUuid) return "subject_resource_mismatch";
  // Without `payload_digest` the uuid alone cannot say which submitted payload
  // a screen decided on, so a correction and the screen it corrects become
  // indistinguishable.
  const subjectKeys = Object.keys(subject);
  if (!SUBJECT_KEYS.every((key) => subjectKeys.includes(key))) {
    return "invalid_subject_shape";
  }
  const allowedSubjectKeys = [...SUBJECT_KEYS, ...SUBJECT_OPTIONAL_KEYS];
  if (!subjectKeys.every((key) => allowedSubjectKeys.includes(key))) {
    return "invalid_subject_shape";
  }
  if (!isDigest(subject.payload_digest)) return "invalid_subject_shape";
  if ("file_digest" in subject && !isDigest(subject.file_digest)) {
    return "invalid_subject_shape";
  }
  if (context.tier !== TIER_BY_DECISION[receipt.decision]) return "tier_decision_mismatch";
  if ("fields_supplied_by" in context) {
    const shapeError = provenanceMapCheck(context.fields_supplied_by);
    if (shapeError !== null) return shapeError;
  }
  if (receipt.decision !== "deny") {
    if (!isStringList(context.criteria_passed) || !isStringList(context.criteria_failed)) {
      return "missing_criteria_context";
    }
    if (receipt.decision === "escalate" && !("detail_code" in context)) {
      return "missing_detail_code";
    }
    return null;
  }
  const policyEval = receipt.policy_eval;
  if (!isPlainObject(policyEval)) return "missing_policy_eval";
  const matched = policyEval.matched_condition;
  if (
    !isPlainObject(matched) ||
    !hasExactKeys(matched, ["field", "op", "value"]) ||
    matched.field !== "tier" ||
    matched.op !== "eq" ||
    matched.value !== "deny"
  ) {
    return "missing_policy_eval";
  }
  if (policyEval.field_value !== "deny") return "missing_policy_eval";
  const knockout = context.knockout;
  if (!isPlainObject(knockout)) return "missing_knockout_context";
  if (!hasExactKeys(knockout, KNOCKOUT_KEYS)) return "invalid_knockout_shape";
  if (!("citation" in context)) return "missing_citation";
  // Profile §6: the provenance map is mandatory on knockout denials, so the
  // customer-asserted-field gate is checkable from the receipt alone. Its shape
  // was validated above, so `customer` here is a list of field names and the
  // gate is a membership test.
  if (!("fields_supplied_by" in context)) return "missing_fields_supplied_by";
  if (!context.fields_supplied_by.customer.includes(knockout.field)) {
    return "provenance_gate_violation";
  }
  return null;
}

function reviewCheck(receipt) {
  const context = receipt.context;
  if (context.review_decision !== REVIEW_DECISION_BY_DECISION[receipt.decision]) {
    return "missing_review_decision";
  }
  if (!("replaces_receipt" in context)) return "missing_replaces_receipt";
  if (!("requisition_id" in context)) return "missing_requisition_id";
  return null;
}

/**
 * Run the profile layer (§§4–7) over a base-verified receipt. Returns the first
 * failing check's code, or null.
 */
export function checkProfile(receipt) {
  const context = receipt.context;
  const piiError = piiCheck(context);
  if (piiError !== null) return piiError;
  const valueError = candidateValueCheck(receipt);
  if (valueError !== null) return valueError;
  const extensionError = contextKeyCheck(receipt);
  if (extensionError !== null) return extensionError;
  const organizationError = organizationCheck(context);
  if (organizationError !== null) return organizationError;
  const action = receiptAction(receipt);
  const decision = receipt.decision;
  const reason = receipt.reason;
  if (action === "candidate.screen") {
    if (!SCREEN_REASONS.has(`${decision} ${reason}`)) return "vocabulary_mispairing";
    return candidateScreenCheck(receipt);
  }
  if (action === "candidate.review") {
    const reviewReasons = ["authorization_granted_action_active", "deny_condition_matched"];
    if (!["allow", "deny"].includes(decision) || !reviewReasons.includes(reason)) {
      return "vocabulary_mispairing";
    }
    return reviewCheck(receipt);
  }
  if (action === "adverse_action.issue") {
    if (decision !== "allow" || reason !== "authorization_granted_action_active") {
      return "vocabulary_mispairing";
    }
    return isStringList(context.decision_refs) ? null : "missing_decision_refs";
  }
  if (action === "audit.export") {
    if (decision !== "allow" || reason !== "authorization_granted_action_active") {
      return "vocabulary_mispairing";
    }
    if (!("manifest_digest" in context) || !("filter" in context)) {
      return "missing_audit_context";
    }
    return null;
  }
  if (action === "authorization.create") {
    if (decision !== "authorization_granted") return "vocabulary_mispairing";
    const lifecycleError = policyContextCheck(context.policy) || approvalContextCheck(context);
    if (lifecycleError !== null) return lifecycleError;
    if ("approval_id" in context && receipt.user_id !== context.approving_user_id) {
      return "approval_user_mismatch";
    }
    return null;
  }
  if (action === "authorization.revoke") {
    if (decision !== "authorization_revoked") return "vocabulary_mispairing";
    return "revoked_by" in context ? null : "missing_revoke_context";
  }
  return "vocabulary_mispairing";
}

function scopeToMap(scope) {
  if (scope === null || scope === undefined) return null;
  if (scope instanceof Map) return scope;
  const map = new Map();
  const receipts = Array.isArray(scope) ? scope : Object.values(scope);
  for (const receipt of receipts) {
    if (isPlainObject(receipt) && typeof receipt.receipt_id === "string") {
      map.set(receipt.receipt_id, receipt);
    }
  }
  return map;
}

function replacesReceipt(receipt) {
  const context = isPlainObject(receipt) ? receipt.context : null;
  const value = isPlainObject(context) ? context.replaces_receipt : undefined;
  return value === undefined ? null : value;
}

function cycleCheck(receipt, scope, replaces) {
  const seen = new Set([receipt.receipt_id]);
  let cursor = replaces;
  while (cursor !== null && cursor !== undefined) {
    if (seen.has(cursor)) return "chain_cycle";
    seen.add(cursor);
    const target = scope.get(cursor);
    cursor = target === undefined ? null : replacesReceipt(target);
  }
  return null;
}

/**
 * Profile §8 chain checks, reported one condition at a time.
 *
 * A missing ancestor is a property of the export, not of the receipt: it is
 * noted as `incomplete_chain` and the receipt still verifies. A branch, a
 * cycle, or a target naming a different candidate or authorization is a broken
 * chain and fails.
 */
export function checkChain(receipt, scope, notes = []) {
  const map = scopeToMap(scope);
  if (map === null) return null;
  const replaces = replacesReceipt(receipt);
  if (replaces === null) return null;
  const target = map.get(replaces);
  if (target === undefined) {
    notes.push("incomplete_chain");
    return null;
  }
  if ((target.resource ?? null) !== (receipt.resource ?? null)) {
    return "chain_resource_mismatch";
  }
  if ((target.authorization_id ?? null) !== (receipt.authorization_id ?? null)) {
    return "chain_authorization_mismatch";
  }
  const cycleError = cycleCheck(receipt, map, replaces);
  if (cycleError !== null) return cycleError;
  // At most one direct successor. Every contender is in a branch, but only one
  // of them can be the chain head, so the earliest by (issued_at, receipt_id)
  // keeps the chain and the later ones are the contested successors this
  // reports on.
  const successors = [...map.values()]
    .filter((candidate) => replacesReceipt(candidate) === replaces)
    .sort((left, right) => {
      const leftKey = [left.issued_at ?? "", left.receipt_id];
      const rightKey = [right.issued_at ?? "", right.receipt_id];
      if (leftKey[0] !== rightKey[0]) return leftKey[0] < rightKey[0] ? -1 : 1;
      if (leftKey[1] !== rightKey[1]) return leftKey[1] < rightKey[1] ? -1 : 1;
      return 0;
    });
  if (successors.length > 1 && receipt.receipt_id !== successors[0].receipt_id) {
    return "chain_branch";
  }
  return null;
}

// --------------------------------------------------------------------------
// Public entry point
// --------------------------------------------------------------------------

/**
 * Verify one receipt: base format first, then the profile layer.
 *
 * @param {object} receipt - the receipt, parsed from JSON.
 * @param {object} [options]
 * @param {object} [options.keys] - the workspace key document
 *   (`{workspace_id, keys: [...]}`), from caller-trusted configuration.
 * @param {object|Array|Map} [options.scope] - other receipts available for §8
 *   chain checks, as a map of receipt_id to receipt, an array of receipts, or a
 *   Map. Chain checks are skipped when it is absent.
 * @param {string} [options.workspaceId] - the caller-trusted workspace ID.
 *   Defaults to the key document's, which is only a trust anchor because the
 *   caller supplied that document.
 * @param {Iterable<string>} [options.trustedKeyFingerprints] - caller-trusted
 *   `sha256:<hex>` public-key fingerprints. Defaults to the fingerprints of the
 *   supplied key document's keys.
 * @param {number} [options.now] - epoch milliseconds, for deterministic tests.
 * @returns {Promise<{base: {ok: boolean, errors: string[]},
 *   profile: {ok: boolean, errors: string[], notes: string[]}}>}
 *   Each layer reports the first failing check, so `errors` holds at most one
 *   code. The profile layer does not run when the base layer fails.
 */
export async function verifyReceipt(receipt, options = {}) {
  const base = { ok: true, errors: [] };
  const profile = { ok: true, errors: [], notes: [] };
  const fail = (code) => {
    base.ok = false;
    base.errors.push(code);
    profile.ok = false;
    return { base, profile };
  };

  const keys = options.keys ?? null;
  if (keys === null) return fail("base_keys_required");
  const expectedWorkspaceId =
    options.workspaceId ?? (isPlainObject(keys) ? keys.workspace_id : null) ?? null;
  if (!expectedWorkspaceId) return fail("base_workspace_required");

  // A malformed key document is left for the verification step below, which
  // names it precisely rather than reporting it as a missing fingerprint.
  let loadedKeys = null;
  try {
    loadedKeys = await loadKeysFromJson(keys);
  } catch {
    loadedKeys = null;
  }
  let trusted;
  if (options.trustedKeyFingerprints !== undefined && options.trustedKeyFingerprints !== null) {
    trusted = new Set(options.trustedKeyFingerprints);
  } else if (loadedKeys !== null) {
    trusted = new Set(
      await Promise.all(loadedKeys.map((key) => publicKeyFingerprint(key.publicKeyBytes))),
    );
  } else {
    trusted = new Set();
  }
  if (loadedKeys !== null && trusted.size === 0) return fail("base_key_fingerprint_required");
  if (!isPlainObject(keys) || keys.workspace_id !== expectedWorkspaceId) {
    return fail("base_workspace_mismatch");
  }

  try {
    await verifyBaseReceipt(receipt, loadedKeys ?? (await loadKeysFromJson(keys)), {
      now: options.now ?? Date.now(),
      expectedWorkspaceId,
      trustedKeyFingerprints: trusted,
    });
  } catch (error) {
    // The base layer refuses fractional numbers because they cannot be
    // canonicalized reproducibly; the profile reports that distinctly, since it
    // is a producer mistake rather than a broken signature.
    return fail(
      error instanceof VerificationError && error.message.includes("non-integer numbers")
        ? "float_in_context"
        : "base_verification_failed",
    );
  }

  const profileError = checkProfile(receipt);
  if (profileError !== null) {
    profile.ok = false;
    profile.errors.push(profileError);
    return { base, profile };
  }
  const chainError = checkChain(receipt, options.scope ?? null, profile.notes);
  if (chainError !== null) {
    profile.ok = false;
    profile.errors.push(chainError);
  }
  return { base, profile };
}

export default verifyReceipt;
