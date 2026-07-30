#!/usr/bin/env python3
"""Download and verify the Galmuri7 BDF used for glyph identification."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import urllib.request


COMMIT = "71e1cacf1437a11220307120e63e30bc275312d4"
URL = (
    "https://raw.githubusercontent.com/quiple/galmuri/"
    f"{COMMIT}/dist/Galmuri7.bdf"
)
BDF_SIZE = 2_092_054
BDF_SHA256 = "0ec6b8707e8c47d85995b5b2b507180aed7bcc724792fe5477e998d41f8b075f"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            Path(__file__).resolve().parents[1]
            / "analysis"
            / "local"
            / "Galmuri7.bdf"
        ),
        help="local BDF destination (analysis/local is ignored)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing unverified file",
    )
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        existing = args.output.read_bytes()
        if len(existing) == BDF_SIZE and digest(existing) == BDF_SHA256:
            print(f"Already verified: {args.output}")
            return 0
        parser.error(f"output exists and is not the verified BDF: {args.output}")

    request = urllib.request.Request(
        URL,
        headers={"User-Agent": "ShiningForceKR/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read()
    if len(data) != BDF_SIZE or digest(data) != BDF_SHA256:
        raise SystemExit("downloaded Galmuri7 BDF identity mismatch")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    print(f"Verified Galmuri7 BDF written to {args.output}")
    print(f"SHA-256: {BDF_SHA256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
