#!/usr/bin/env python3
"""Download and verify the public Final Conflict English reference patch.

Only the IPS translation patch is extracted.  No ROM is downloaded or included.
"""

from __future__ import annotations

import argparse
from io import BytesIO
from pathlib import Path
import hashlib
import urllib.request
import zipfile

URL = "https://fantasyanime.com/shiningforce/fcpatch_070706.zip"
ZIP_SHA256 = "2e218cc5456c7e621517c4a3521c1c462aa66e663d764e3187496757cbf3bc5e"
IPS_NAME = "fcpatch_070706.ips"
IPS_SHA256 = "3cc1085508c7298d5d20fbfefec929cdfdadbcd60340a66ec0e4c2aa92d48c07"
IPS_SIZE = 47290


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "patch" / IPS_NAME,
        help="local IPS destination (ignored by this repository)",
    )
    parser.add_argument("--force", action="store_true", help="replace an existing file")
    args = parser.parse_args()

    if args.output.exists() and not args.force:
        existing = args.output.read_bytes()
        if len(existing) == IPS_SIZE and digest(existing) == IPS_SHA256:
            print(f"Already verified: {args.output}")
            return 0
        parser.error(f"output exists and is not the verified reference patch: {args.output}")

    request = urllib.request.Request(URL, headers={"User-Agent": "ShiningForceKR/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        archive = response.read()
    if digest(archive) != ZIP_SHA256:
        raise SystemExit("downloaded ZIP SHA-256 mismatch; refusing to extract")

    with zipfile.ZipFile(BytesIO(archive)) as bundle:
        names = bundle.namelist()
        if names != [IPS_NAME]:
            raise SystemExit(f"unexpected ZIP contents: {names!r}")
        ips = bundle.read(IPS_NAME)
    if len(ips) != IPS_SIZE or digest(ips) != IPS_SHA256:
        raise SystemExit("extracted IPS identity mismatch; refusing to write")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(ips)
    print(f"Verified IPS written to {args.output}")
    print(f"SHA-256: {IPS_SHA256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
