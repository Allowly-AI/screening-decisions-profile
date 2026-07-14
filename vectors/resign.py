#!/usr/bin/env python3
"""Deterministically re-sign vectors.json after editing receipt bodies.

Ed25519 key derived from a fixed seed so regeneration is reproducible.
Receipts whose payloads cannot canonicalize (deliberate schema-invalid
vectors) keep their existing signature — they fail base verification
before the signature is ever checked.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from allowly_receipt_format import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SEED = hashlib.sha256(b"screening-decisions-profile/vectors/v0.3").digest()
KEY_ID = "test-key-v03"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main() -> None:
    path = Path(__file__).with_name("vectors.json")
    doc = json.loads(path.read_text())
    private = Ed25519PrivateKey.from_private_bytes(SEED)
    public = private.public_key().public_bytes_raw()

    signed = skipped = 0
    for item in doc["valid"] + doc["invalid"]:
        receipt = item["receipt"]
        payload = {k: v for k, v in receipt.items() if k != "signature"}
        try:
            message = canonicalize(payload)
        except Exception:
            skipped += 1
            continue
        receipt["signature"] = {
            "alg": "Ed25519",
            "key_id": KEY_ID,
            "value": b64u(private.sign(message)),
        }
        signed += 1

    doc["keys"] = {
        "workspace_id": doc["keys"]["workspace_id"],
        "keys": [
            {
                "key_id": KEY_ID,
                "alg": "Ed25519",
                "public_key": b64u(public),
                "active_from": "2026-01-01T00:00:00Z",
                "active_until": None,
            }
        ],
    }
    path.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"signed {signed}, skipped {skipped} (non-canonicalizable by design)")


if __name__ == "__main__":
    main()
