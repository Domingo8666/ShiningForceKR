#!/usr/bin/env python3
"""Extract and roundtrip the exact visible record without publishing its text."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

try:
    from .patch_io import PatchError, extract_bps_target_literals
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
        analyze_patch,
    )
    from .v5_1_poc_expansion_proof import (
        validate_poc_expansion_proof,
    )
except ImportError:  # direct script execution
    from patch_io import PatchError, extract_bps_target_literals
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
        analyze_patch,
    )
    from v5_1_poc_expansion_proof import validate_poc_expansion_proof


ARTIFACT_KIND = "sanitized-v5-1-visible-script-roundtrip"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_visible_script_roundtrip.json"
)
LOCAL_RELATIVE_PATH = Path(
    "analysis/local/v5_1_visible_script_record.json"
)
EXPANSION_PROOF_PATH = Path(
    "analysis/device/v5_1_latest_poc_expansion_proof.json"
)
PATCH_PATH = Path("patch/Final_Conflict_Japan_to_Korean_v5.1.bps")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "source_expansion_test_sha256",
    "runtime_entry",
    "roundtrip",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
RUNTIME_KEYS = {
    "physical_start",
    "logical_start",
    "mapped_bank",
    "record_length_bytes",
}
ROUNDTRIP_KEYS = {
    "source_independent_bytes",
    "decoded_symbol_count",
    "terminator_count",
    "encoded_bits",
    "storage_capacity_bits",
    "trailing_storage_bits",
    "reencoded_bits",
    "bit_exact",
}


class VisibleScriptRecordNotReady(ValueError):
    """The expansion proof is absent or does not match the record."""


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _bits_equal(left: bytes, right: bytes, bit_count: int) -> bool:
    whole, remainder = divmod(bit_count, 8)
    if left[:whole] != right[:whole]:
        return False
    if remainder == 0:
        return True
    mask = (0xFF << (8 - remainder)) & 0xFF
    return (left[whole] & mask) == (right[whole] & mask)


def validate_visible_script_roundtrip(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("visible script roundtrip fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] != "exact-visible-record-roundtrip-pass"
    ):
        raise ValueError("visible script roundtrip policy is invalid")
    for key in ("baseline_target_sha256", "source_expansion_test_sha256"):
        if not _is_sha256(value[key]):
            raise ValueError(f"{key} must be a lowercase SHA-256")
    if value["baseline_target_sha256"] == value[
        "source_expansion_test_sha256"
    ]:
        raise ValueError("visible script roundtrip identities must differ")

    runtime = value["runtime_entry"]
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_KEYS:
        raise ValueError("visible script runtime fields do not match")
    for key, minimum, maximum in (
        ("physical_start", 0, 0x17BFFF),
        ("logical_start", 0x4000, 0x7FFF),
        ("mapped_bank", 0, 0xFF),
        ("record_length_bytes", 1, 0xFF),
    ):
        if not _bounded_int(runtime[key], minimum, maximum):
            raise ValueError(f"visible script {key} is invalid")

    roundtrip = value["roundtrip"]
    if not isinstance(roundtrip, dict) or set(roundtrip) != ROUNDTRIP_KEYS:
        raise ValueError("visible script roundtrip evidence fields do not match")
    for key, minimum, maximum in (
        ("decoded_symbol_count", 1, 0x1000),
        ("terminator_count", 1, 0x100),
        ("encoded_bits", 1, 0x7FFF),
        ("storage_capacity_bits", 8, 0x7FFF),
        ("trailing_storage_bits", 0, 0x7FFF),
        ("reencoded_bits", 1, 0x7FFF),
    ):
        if not _bounded_int(roundtrip[key], minimum, maximum):
            raise ValueError(f"visible script roundtrip {key} is invalid")
    if (
        roundtrip["source_independent_bytes"] is not True
        or roundtrip["bit_exact"] is not True
        or roundtrip["terminator_count"] != 1
        or roundtrip["encoded_bits"] != roundtrip["reencoded_bits"]
        or roundtrip["storage_capacity_bits"]
        != int(runtime["record_length_bytes"]) * 8
        or roundtrip["trailing_storage_bits"]
        != int(roundtrip["storage_capacity_bits"])
        - int(roundtrip["encoded_bits"])
    ):
        raise ValueError("visible script roundtrip evidence is inconsistent")
    if value["local_payload_policy"] != "symbols-and-text-local-only":
        raise ValueError("visible script local payload policy is invalid")
    if value["translation_build_eligible"] is not False:
        raise ValueError("visible script roundtrip cannot enable translation builds")
    if value["next_checkpoint"] != "map-visible-record-glyphs-to-unicode":
        raise ValueError("visible script next checkpoint is inconsistent")


def extract_visible_script_record(
    patch: bytes,
    expansion_proof: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    validate_poc_expansion_proof(expansion_proof)
    analyze_patch(patch)
    sparse = extract_bps_target_literals(patch)
    runtime = expansion_proof["runtime_entry"]
    assert isinstance(runtime, dict)
    start = int(runtime["physical_start"])
    length = int(runtime["record_length_bytes"])
    end = start + length
    if (
        not 0 <= start < end <= len(sparse.data)
        or any(value == 0 for value in sparse.known[start:end])
    ):
        raise VisibleScriptRecordNotReady(
            "the proven visible record is not source independent"
        )
    trees = load_trees_at(
        sparse.data,
        sparse.known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    symbols, encoded_bits = decode_symbols(
        sparse.data,
        sparse.known,
        trees,
        start,
        initial_symbol=CANDIDATE_END_SYMBOL,
        end_symbol=CANDIDATE_END_SYMBOL,
        max_symbols=0x1000,
        max_bytes=length,
    )
    reencoded, reencoded_bits = encode_symbols(
        trees,
        symbols,
        initial_symbol=CANDIDATE_END_SYMBOL,
        end_symbol=CANDIDATE_END_SYMBOL,
        max_bits=length * 8,
    )
    bit_exact = (
        reencoded_bits == encoded_bits
        and _bits_equal(sparse.data[start:end], reencoded, encoded_bits)
    )
    if (
        encoded_bits != runtime["original_encoded_bits"]
        or not bit_exact
        or symbols.count(CANDIDATE_END_SYMBOL) != 1
    ):
        raise PatchError("visible script record no-change roundtrip failed")

    local = {
        "artifact_kind": "local-v5-1-visible-script-record",
        "schema_version": 1,
        "status": "exact-record-extracted-local-only",
        "baseline_target_sha256": expansion_proof[
            "baseline_target_sha256"
        ],
        "runtime_entry": {
            "physical_start": start,
            "logical_start": runtime["logical_start"],
            "mapped_bank": runtime["mapped_bank"],
            "record_length_bytes": length,
        },
        "symbols_hex": [f"0x{symbol:02X}" for symbol in symbols],
        "symbol_stream_sha256": hashlib.sha256(bytes(symbols)).hexdigest(),
        "encoded_bits": encoded_bits,
        "roundtrip_exact": bit_exact,
        "publication_policy": "never-publish-symbols-or-decoded-text",
    }
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "exact-visible-record-roundtrip-pass",
        "baseline_target_sha256": expansion_proof[
            "baseline_target_sha256"
        ],
        "source_expansion_test_sha256": expansion_proof[
            "test_target_sha256"
        ],
        "runtime_entry": local["runtime_entry"],
        "roundtrip": {
            "source_independent_bytes": True,
            "decoded_symbol_count": len(symbols),
            "terminator_count": symbols.count(CANDIDATE_END_SYMBOL),
            "encoded_bits": encoded_bits,
            "storage_capacity_bits": length * 8,
            "trailing_storage_bits": length * 8 - encoded_bits,
            "reencoded_bits": reencoded_bits,
            "bit_exact": bit_exact,
        },
        "local_payload_policy": "symbols-and-text-local-only",
        "translation_build_eligible": False,
        "next_checkpoint": "map-visible-record-glyphs-to-unicode",
    }
    validate_visible_script_roundtrip(safe)
    return local, safe


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    proof_path = root / EXPANSION_PROOF_PATH
    patch_path = root / PATCH_PATH
    if not proof_path.is_file() or not patch_path.is_file():
        if args.if_ready:
            print("Visible script record is not ready")
            return 0
        raise SystemExit("visible script record input is missing")
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    if not isinstance(proof, dict):
        raise ValueError("expanded PoC proof must be a JSON object")
    try:
        local, safe = extract_visible_script_record(
            patch_path.read_bytes(),
            proof,
        )
    except VisibleScriptRecordNotReady as error:
        if args.if_ready:
            print(f"Visible script record is not ready: {error}")
            return 0
        raise
    local_path = root / LOCAL_RELATIVE_PATH
    safe_path = root / PUBLISH_RELATIVE_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote local visible script record: {local_path}")
    print(f"Wrote sanitized roundtrip proof: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
