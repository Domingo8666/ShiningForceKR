#!/usr/bin/env python3
"""Diagnose the first runtime Huffman-context divergence without recapture.

The phone-local trace contains exact context and symbol values.  This stage
uses them only on the device, then publishes a fixed-schema receipt containing
counts and byte-boundary booleans.  No text, symbols, encoded bytes, or ROM
coordinates leave the private report directory.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .sfgfc_huffman import _symbol_codes, load_trees_at
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from .v5_1_first_context_consumer_trace import (
        LOCAL_REPORT_PATH as LOCAL_TRACE_PATH,
        PUBLISH_RELATIVE_PATH as CONSUMER_TRACE_PATH,
        validate_first_context_consumer_trace,
    )
    from .v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
        PUBLISH_RELATIVE_PATH as ENCODING_PATH,
        validate_first_context_translation_encoding,
    )
    from .v5_1_first_context_translation_runtime_capture import TEST_ROM_PATH
    from .v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from sfgfc_huffman import _symbol_codes, load_trees_at
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from v5_1_first_context_consumer_trace import (
        LOCAL_REPORT_PATH as LOCAL_TRACE_PATH,
        PUBLISH_RELATIVE_PATH as CONSUMER_TRACE_PATH,
        validate_first_context_consumer_trace,
    )
    from v5_1_first_context_translation_encoding import (
        LOCAL_REPORT_PATH as LOCAL_ENCODING_PATH,
        PUBLISH_RELATIVE_PATH as ENCODING_PATH,
        validate_first_context_translation_encoding,
    )
    from v5_1_first_context_translation_runtime_capture import TEST_ROM_PATH
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH as TEST_BUILD_PATH,
        validate_first_context_translation_test_build,
    )


ARTIFACT_KIND = "sanitized-v5-1-first-context-bit-alignment"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_first_context_bit_alignment.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_first_context_bit_alignment.json"
)
ANALYSIS_KEYS = {
    "expected_context_count",
    "observed_context_count",
    "context_prefix_match_count",
    "confirmed_symbol_count",
    "confirmed_prefix_bit_count",
    "confirmed_prefix_bit_modulo_8",
    "next_expected_code_bit_count",
}
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "baseline_target_sha256",
    "test_target_sha256",
    "consumer_trace_sha256",
    "local_consumer_trace_sha256",
    "local_encoding_sha256",
    "test_build_sha256",
    "captured_utc",
    "analysis",
    "context_mismatch_observed",
    "next_expected_code_crosses_byte_boundary",
    "next_expected_code_ends_on_byte_boundary",
    "source_and_target_text_local_only",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_utc_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return timestamp.utcoffset() == timezone.utc.utcoffset(timestamp)


def summarize_expected_bit_alignment(
    *,
    trees: dict[int, object],
    expected_symbols: list[int],
    initial_context: int,
    observed_contexts: list[int],
) -> tuple[dict[str, int], bool, bool, bool]:
    """Summarize the first mismatch while keeping exact values private."""

    if (
        not expected_symbols
        or not 0 <= initial_context <= 0xFF
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= 0xFF
            for value in [*expected_symbols, *observed_contexts]
        )
    ):
        raise ValueError("first context bit-alignment inputs are invalid")
    expected_contexts = [initial_context, *expected_symbols[:-1]]
    prefix_count = 0
    for observed, expected in zip(observed_contexts, expected_contexts):
        if observed != expected:
            break
        prefix_count += 1
    mismatch_observed = (
        prefix_count < len(observed_contexts)
        and prefix_count < len(expected_contexts)
        and observed_contexts[prefix_count] != expected_contexts[prefix_count]
    )
    # Matching context N proves symbol N-1.  The mismatching context was
    # selected only after the first wrong symbol had already been decoded.
    confirmed_symbol_count = max(0, prefix_count - 1)
    previous = initial_context
    code_lengths: list[int] = []
    for symbol in expected_symbols:
        tree = trees.get(previous)
        root = getattr(tree, "root", None)
        if root is None:
            raise ValueError("first context Huffman tree is missing")
        code = _symbol_codes(root).get(symbol)
        if code is None:
            raise ValueError("first context Huffman transition is missing")
        code_lengths.append(len(code))
        previous = symbol
    prefix_bits = sum(code_lengths[:confirmed_symbol_count])
    next_bits = (
        code_lengths[confirmed_symbol_count]
        if mismatch_observed and confirmed_symbol_count < len(code_lengths)
        else 0
    )
    crosses = bool(next_bits and prefix_bits % 8 + next_bits > 8)
    ends = bool(next_bits and (prefix_bits + next_bits) % 8 == 0)
    analysis = {
        "expected_context_count": len(expected_contexts),
        "observed_context_count": len(observed_contexts),
        "context_prefix_match_count": prefix_count,
        "confirmed_symbol_count": confirmed_symbol_count,
        "confirmed_prefix_bit_count": prefix_bits,
        "confirmed_prefix_bit_modulo_8": prefix_bits % 8,
        "next_expected_code_bit_count": next_bits,
    }
    return analysis, mismatch_observed, crosses, ends


def build_first_context_bit_alignment(
    *,
    baseline_target_sha256: str,
    test_target_sha256: str,
    consumer_trace_sha256: str,
    local_consumer_trace_sha256: str,
    local_encoding_sha256: str,
    test_build_sha256: str,
    captured_utc: str,
    analysis: dict[str, int],
    context_mismatch_observed: bool,
    next_expected_code_crosses_byte_boundary: bool,
    next_expected_code_ends_on_byte_boundary: bool,
) -> dict[str, object]:
    if not context_mismatch_observed:
        status = "consumer-context-divergence-not-observed"
        checkpoint = "retain-current-consumer-trace"
    elif next_expected_code_crosses_byte_boundary:
        status = "consumer-context-divergence-crosses-byte-boundary"
        checkpoint = "trace-runtime-huffman-byte-reload"
    elif next_expected_code_ends_on_byte_boundary:
        status = "consumer-context-divergence-ends-byte-boundary"
        checkpoint = "trace-runtime-huffman-byte-reload"
    else:
        status = "consumer-context-divergence-within-byte"
        checkpoint = "trace-runtime-huffman-bit-cursor"
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "baseline_target_sha256": baseline_target_sha256,
        "test_target_sha256": test_target_sha256,
        "consumer_trace_sha256": consumer_trace_sha256,
        "local_consumer_trace_sha256": local_consumer_trace_sha256,
        "local_encoding_sha256": local_encoding_sha256,
        "test_build_sha256": test_build_sha256,
        "captured_utc": captured_utc,
        "analysis": analysis,
        "context_mismatch_observed": context_mismatch_observed,
        "next_expected_code_crosses_byte_boundary":
            next_expected_code_crosses_byte_boundary,
        "next_expected_code_ends_on_byte_boundary":
            next_expected_code_ends_on_byte_boundary,
        "source_and_target_text_local_only": True,
        "translation_build_eligible": False,
        "next_checkpoint": checkpoint,
    }
    validate_first_context_bit_alignment(value)
    return value


def validate_first_context_bit_alignment(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("first context bit-alignment fields do not match")
    analysis = value.get("analysis")
    if (
        value.get("artifact_kind") != ARTIFACT_KIND
        or value.get("schema_version") != SCHEMA_VERSION
        or not all(
            _is_sha256(value.get(key))
            for key in (
                "baseline_target_sha256",
                "test_target_sha256",
                "consumer_trace_sha256",
                "local_consumer_trace_sha256",
                "local_encoding_sha256",
                "test_build_sha256",
            )
        )
        or value.get("baseline_target_sha256")
        == value.get("test_target_sha256")
        or not _is_utc_timestamp(value.get("captured_utc"))
        or not isinstance(analysis, dict)
        or set(analysis) != ANALYSIS_KEYS
        or any(
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 0 <= count <= 32768
            for count in analysis.values()
        )
    ):
        raise ValueError("first context bit-alignment identity is invalid")
    assert isinstance(analysis, dict)
    mismatch = value.get("context_mismatch_observed")
    crosses = value.get("next_expected_code_crosses_byte_boundary")
    ends = value.get("next_expected_code_ends_on_byte_boundary")
    if (
        not all(isinstance(flag, bool) for flag in (mismatch, crosses, ends))
        or analysis["context_prefix_match_count"]
        > min(
            analysis["expected_context_count"],
            analysis["observed_context_count"],
        )
        or analysis["confirmed_symbol_count"]
        != max(0, analysis["context_prefix_match_count"] - 1)
        or analysis["confirmed_prefix_bit_modulo_8"]
        != analysis["confirmed_prefix_bit_count"] % 8
        or (crosses or ends) and not mismatch
        or not mismatch and analysis["next_expected_code_bit_count"] != 0
    ):
        raise ValueError("first context bit-alignment counts are inconsistent")
    expected_status = (
        "consumer-context-divergence-not-observed"
        if not mismatch
        else "consumer-context-divergence-crosses-byte-boundary"
        if crosses
        else "consumer-context-divergence-ends-byte-boundary"
        if ends
        else "consumer-context-divergence-within-byte"
    )
    expected_checkpoint = (
        "retain-current-consumer-trace"
        if not mismatch
        else "trace-runtime-huffman-byte-reload"
        if crosses or ends
        else "trace-runtime-huffman-bit-cursor"
    )
    if (
        value.get("status") != expected_status
        or value.get("source_and_target_text_local_only") is not True
        or value.get("translation_build_eligible") is not False
        or value.get("next_checkpoint") != expected_checkpoint
    ):
        raise ValueError("first context bit-alignment result is inconsistent")


def _load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    paths = {
        "rom": root / TEST_ROM_PATH,
        "build": root / TEST_BUILD_PATH,
        "encoding_safe": root / ENCODING_PATH,
        "encoding_local": root / LOCAL_ENCODING_PATH,
        "trace_safe": root / CONSUMER_TRACE_PATH,
        "trace_local": root / LOCAL_TRACE_PATH,
    }
    if any(not path.is_file() for path in paths.values()):
        raise FileNotFoundError("first context bit-alignment input is missing")
    build = _load_object(paths["build"])
    encoding_safe = _load_object(paths["encoding_safe"])
    encoding_local = _load_object(paths["encoding_local"])
    trace_safe = _load_object(paths["trace_safe"])
    trace_local = _load_object(paths["trace_local"])
    validate_first_context_translation_test_build(build)
    validate_first_context_translation_encoding(encoding_safe)
    validate_first_context_consumer_trace(trace_safe)
    rows = encoding_local.get("rows")
    observed_contexts = trace_local.get("observed_contexts")
    if (
        not isinstance(rows, list)
        or not rows
        or not isinstance(rows[0], dict)
        or not isinstance(observed_contexts, list)
    ):
        raise ValueError("first context bit-alignment local rows are missing")
    first_row = rows[0]
    expected_symbols = first_row.get("symbols")
    initial_context = first_row.get("initial_context")
    if not isinstance(expected_symbols, list) or not isinstance(initial_context, int):
        raise ValueError("first context bit-alignment first row is invalid")
    if (
        sha256_file(paths["rom"]) != build["test_target_sha256"]
        or trace_safe["test_target_sha256"] != build["test_target_sha256"]
        or trace_local.get("test_target_sha256") != build["test_target_sha256"]
        or trace_safe["local_trace_sha256"] != sha256_file(paths["trace_local"])
        or encoding_safe["local_encoding_sha256"]
        != sha256_file(paths["encoding_local"])
    ):
        raise ValueError("first context bit-alignment identity disagrees")
    rom = paths["rom"].read_bytes()
    trees = load_trees_at(
        rom,
        bytes((1,)) * len(rom),
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    analysis, mismatch, crosses, ends = summarize_expected_bit_alignment(
        trees=trees,
        expected_symbols=expected_symbols,
        initial_context=initial_context,
        observed_contexts=observed_contexts,
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind": "local-v5-1-first-context-bit-alignment",
        "schema_version": SCHEMA_VERSION,
        "test_target_sha256": build["test_target_sha256"],
        "captured_utc": captured_utc,
        "initial_context": initial_context,
        "expected_symbols": expected_symbols,
        "observed_contexts": observed_contexts,
        "analysis": analysis,
        "publication_policy": (
            "never-publish-symbols-context-values-encoded-bytes-or-text"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_first_context_bit_alignment(
        baseline_target_sha256=str(build["baseline_target_sha256"]),
        test_target_sha256=str(build["test_target_sha256"]),
        consumer_trace_sha256=sha256_file(paths["trace_safe"]),
        local_consumer_trace_sha256=sha256_file(paths["trace_local"]),
        local_encoding_sha256=sha256_file(paths["encoding_local"]),
        test_build_sha256=sha256_file(paths["build"]),
        captured_utc=captured_utc,
        analysis=analysis,
        context_mismatch_observed=mismatch,
        next_expected_code_crosses_byte_boundary=crosses,
        next_expected_code_ends_on_byte_boundary=ends,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR first context bit alignment: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
