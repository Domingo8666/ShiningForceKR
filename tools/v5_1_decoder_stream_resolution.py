#!/usr/bin/env python3
"""Resolve runtime-observed decoder reads to bounded Korean Huffman streams."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

try:
    from .patch_io import (
        PatchError,
        extract_bps_target_literals,
        sha256_bytes,
    )
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_engine import (
        EXPECTED_PATCH_SHA256,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from .v5_1_renderer_observation import validate_renderer_observation
    from .v5_1_test_display_comparison import validate_display_comparison
    from .v5_1_test_display_review import validate_display_review
    from .v5_1_test_phrase import build_test_phrase_plan
except ImportError:  # direct script execution
    from patch_io import PatchError, extract_bps_target_literals, sha256_bytes
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_engine import (
        EXPECTED_PATCH_SHA256,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from v5_1_renderer_observation import validate_renderer_observation
    from v5_1_test_display_comparison import validate_display_comparison
    from v5_1_test_display_review import validate_display_review
    from v5_1_test_phrase import build_test_phrase_plan


ARTIFACT_KIND = "sanitized-runtime-decoder-stream-resolution"
SCHEMA_VERSION = 1
DEFAULT_PATCH = Path("patch/Final_Conflict_Japan_to_Korean_v5.1.bps")
DEFAULT_OBSERVATION = Path(
    "analysis/device/v5_1_latest_renderer_observation.json"
)
DEFAULT_DISPLAY_REVIEW = Path(
    "analysis/device/v5_1_latest_display_review.json"
)
DEFAULT_DISPLAY_COMPARISON = Path(
    "analysis/device/v5_1_latest_display_comparison.json"
)
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_decoder_stream_resolution.json"
)
MAX_ENTRY_SYMBOLS = 256
MAX_ENTRY_BYTES = 256

TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "target_sha256",
    "status",
    "streams",
    "selected_stream_index",
    "huffman_vector_read_count",
    "huffman_tree_read_count",
    "consumer_evidence_confirmed",
    "translation_build_eligible",
    "next_checkpoint",
}
STREAM_KEYS = {
    "physical_start",
    "logical_start",
    "mapped_bank",
    "instruction_bank",
    "instruction_pc",
    "operand_kind",
    "decoded_end_exclusive",
    "next_stream_start",
    "symbol_count",
    "encoded_bits",
    "roundtrip_exact",
}


def _bits_equal(left: bytes, right: bytes, bits: int) -> bool:
    return all(
        ((left[index >> 3] >> (7 - (index & 7))) & 1)
        == ((right[index >> 3] >> (7 - (index & 7))) & 1)
        for index in range(bits)
    )


def _require_int(
    value: object,
    label: str,
    minimum: int = 0,
    maximum: int | None = None,
) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} must be <= {maximum}")


def validate_decoder_stream_resolution(
    resolution: dict[str, object],
) -> None:
    if set(resolution) != TOP_LEVEL_KEYS:
        raise ValueError("decoder stream resolution fields do not match")
    if resolution["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected decoder stream resolution artifact")
    if resolution["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected decoder stream resolution schema")
    target_sha256 = resolution["target_sha256"]
    if (
        not isinstance(target_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", target_sha256) is None
    ):
        raise ValueError("target_sha256 must be a lowercase SHA-256")
    streams = resolution["streams"]
    if not isinstance(streams, list) or len(streams) > 64:
        raise ValueError("streams must contain at most 64 entries")
    previous_start = -1
    for index, stream in enumerate(streams):
        if not isinstance(stream, dict) or set(stream) != STREAM_KEYS:
            raise ValueError(f"streams[{index}] fields do not match")
        for key in (
            "physical_start",
            "logical_start",
            "mapped_bank",
            "instruction_bank",
            "instruction_pc",
            "decoded_end_exclusive",
            "symbol_count",
            "encoded_bits",
        ):
            maximum = 0x17BFFF if key in {
                "physical_start",
                "decoded_end_exclusive",
            } else 0xFFFF
            if key in {"mapped_bank", "instruction_bank"}:
                maximum = 0xFF
            _require_int(stream[key], f"streams[{index}].{key}", 0, maximum)
        next_start = stream["next_stream_start"]
        if next_start is not None:
            _require_int(
                next_start,
                f"streams[{index}].next_stream_start",
                0,
                0x17BFFF,
            )
            if next_start <= stream["physical_start"]:
                raise ValueError("next stream start must follow the stream")
            if stream["decoded_end_exclusive"] > next_start:
                raise ValueError("decoded stream overlaps the next stream")
        if stream["physical_start"] <= previous_start:
            raise ValueError("streams must be ordered by physical start")
        previous_start = stream["physical_start"]
        if stream["decoded_end_exclusive"] <= stream["physical_start"]:
            raise ValueError("decoded stream must consume at least one byte")
        if stream["roundtrip_exact"] is not True:
            raise ValueError("published streams must roundtrip exactly")
        operand_kind = stream["operand_kind"]
        if (
            not isinstance(operand_kind, str)
            or re.fullmatch(r"[a-z-]{1,40}", operand_kind) is None
        ):
            raise ValueError("operand_kind must be a safe token")
    for key in ("huffman_vector_read_count", "huffman_tree_read_count"):
        _require_int(resolution[key], key, 0, 64)
    confirmed = resolution["consumer_evidence_confirmed"]
    if not isinstance(confirmed, bool):
        raise ValueError("consumer_evidence_confirmed must be boolean")
    if resolution["translation_build_eligible"] is not False:
        raise ValueError("stream resolution cannot enable translation builds")
    selected = resolution["selected_stream_index"]
    if confirmed:
        _require_int(selected, "selected_stream_index", 0, len(streams) - 1)
        if (
            not streams
            or resolution["huffman_vector_read_count"] == 0
            or resolution["huffman_tree_read_count"] == 0
            or resolution["status"] != "decoder-stream-resolved"
        ):
            raise ValueError("confirmed stream evidence is incomplete")
    elif selected is not None:
        raise ValueError("unconfirmed resolution cannot select a stream")
    for key in ("status", "next_checkpoint"):
        value = resolution[key]
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[a-z0-9-]{1,80}", value) is None
        ):
            raise ValueError(f"{key} must be a safe token")


def build_decoder_stream_resolution(
    patch: bytes,
    observation: dict[str, object],
    *,
    rejected_physical_starts: set[int] | None = None,
    minimum_selected_bits: int = 1,
) -> dict[str, object]:
    validate_renderer_observation(observation)
    if minimum_selected_bits <= 0:
        raise ValueError("minimum selected bit budget must be positive")
    if sha256_bytes(patch) != EXPECTED_PATCH_SHA256:
        raise PatchError("v5.1 BPS identity mismatch")
    sparse = extract_bps_target_literals(patch)
    trees = load_trees_at(
        sparse.data,
        sparse.known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    reads = observation["decoder_reads"]
    assert isinstance(reads, list)
    source_reads = sorted(
        {
            int(item["physical_file_offset"]): item
            for item in reads
            if isinstance(item, dict)
            and item.get("classification") == "source-region"
        }.items()
    )
    streams: list[dict[str, object]] = []
    for position, (start, read) in enumerate(source_reads):
        next_start = (
            source_reads[position + 1][0]
            if position + 1 < len(source_reads)
            else None
        )
        try:
            symbols, bits = decode_symbols(
                sparse.data,
                sparse.known,
                trees,
                start,
                initial_symbol=CANDIDATE_END_SYMBOL,
                end_symbol=CANDIDATE_END_SYMBOL,
                max_symbols=MAX_ENTRY_SYMBOLS,
                max_bytes=MAX_ENTRY_BYTES,
            )
            encoded, reencoded_bits = encode_symbols(
                trees,
                symbols,
                initial_symbol=CANDIDATE_END_SYMBOL,
                end_symbol=CANDIDATE_END_SYMBOL,
                max_bits=MAX_ENTRY_BYTES * 8,
            )
        except PatchError:
            continue
        decoded_end = start + (bits + 7) // 8
        if (
            reencoded_bits != bits
            or not _bits_equal(sparse.data[start:], encoded, bits)
            or (next_start is not None and decoded_end > next_start)
        ):
            continue
        streams.append(
            {
                "physical_start": start,
                "logical_start": int(read["logical_access"]),
                "mapped_bank": int(read["mapped_bank"]),
                "instruction_bank": int(read["instruction_bank"]),
                "instruction_pc": int(read["instruction_pc"]),
                "operand_kind": str(read["operand_kind"]),
                "decoded_end_exclusive": decoded_end,
                "next_stream_start": next_start,
                "symbol_count": len(symbols),
                "encoded_bits": bits,
                "roundtrip_exact": True,
            }
        )
    vector_reads = sum(
        isinstance(item, dict)
        and item.get("classification") == "korean-huffman-vector"
        for item in reads
    )
    tree_reads = sum(
        isinstance(item, dict)
        and item.get("classification") == "korean-huffman-tree"
        for item in reads
    )
    rejected = rejected_physical_starts or set()
    selectable = [
        index
        for index, stream in enumerate(streams)
        if int(stream["physical_start"]) not in rejected
        and int(stream["encoded_bits"]) >= minimum_selected_bits
    ]
    confirmed = bool(selectable and vector_reads and tree_reads)
    resolution: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": observation["target_sha256"],
        "status": (
            "decoder-stream-resolved"
            if confirmed
            else "decoder-stream-ambiguous"
        ),
        "streams": streams,
        "selected_stream_index": selectable[0] if confirmed else None,
        "huffman_vector_read_count": vector_reads,
        "huffman_tree_read_count": tree_reads,
        "consumer_evidence_confirmed": confirmed,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "build-runtime-selected-test-phrase"
            if confirmed
            else "capture-more-decoder-stream-reads"
        ),
    }
    validate_decoder_stream_resolution(resolution)
    return resolution


def write_decoder_stream_resolution(
    root: Path,
    resolution: dict[str, object],
) -> Path:
    validate_decoder_stream_resolution(resolution)
    path = root.resolve() / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(resolution, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH)
    parser.add_argument("--observation", type=Path, default=DEFAULT_OBSERVATION)
    parser.add_argument(
        "--display-review",
        type=Path,
        default=DEFAULT_DISPLAY_REVIEW,
    )
    parser.add_argument(
        "--display-comparison",
        type=Path,
        default=DEFAULT_DISPLAY_COMPARISON,
    )
    args = parser.parse_args()

    def absolute(path: Path) -> Path:
        return path if path.is_absolute() else (root / path).resolve()

    observation = json.loads(
        absolute(args.observation).read_text(encoding="utf-8")
    )
    if not isinstance(observation, dict):
        raise ValueError("renderer observation must be a JSON object")
    rejected_physical_starts: set[int] = set()
    display_review_path = absolute(args.display_review)
    if display_review_path.is_file():
        display_review = json.loads(
            display_review_path.read_text(encoding="utf-8")
        )
        if not isinstance(display_review, dict):
            raise ValueError("display review must be a JSON object")
        validate_display_review(display_review)
        if (
            display_review["result"] == "phrase-absent-fail"
            and display_review["baseline_target_sha256"]
            == observation["target_sha256"]
        ):
            rejected = display_review["rejected_physical_starts"]
            assert isinstance(rejected, list)
            rejected_physical_starts.update(int(value) for value in rejected)
    display_comparison_path = absolute(args.display_comparison)
    if display_comparison_path.is_file():
        display_comparison = json.loads(
            display_comparison_path.read_text(encoding="utf-8")
        )
        if not isinstance(display_comparison, dict):
            raise ValueError("display comparison must be a JSON object")
        validate_display_comparison(display_comparison)
        if (
            display_comparison["baseline_target_sha256"]
            == observation["target_sha256"]
        ):
            rejected = display_comparison[
                "automatic_rejected_physical_starts"
            ]
            assert isinstance(rejected, list)
            rejected_physical_starts.update(int(value) for value in rejected)
    patch_bytes = absolute(args.patch).read_bytes()
    phrase_plan = build_test_phrase_plan(patch_bytes)
    encoding = phrase_plan["encoding"]
    assert isinstance(encoding, dict)
    resolution = build_decoder_stream_resolution(
        patch_bytes,
        observation,
        rejected_physical_starts=rejected_physical_starts,
        minimum_selected_bits=int(encoding["encoded_bits"]),
    )
    path = write_decoder_stream_resolution(root, resolution)
    print(
        "SFKR decoder streams: "
        f"{resolution['status']} ({len(resolution['streams'])} exact stream(s))"
    )
    print(f"Safe decoder stream resolution: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
