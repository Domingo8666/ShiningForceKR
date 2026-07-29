#!/usr/bin/env python3
"""Rank v5.1 script-consumer candidates from a verified locally built ROM.

This scanner deliberately reports only coordinates and aggregate metrics. Byte
signatures and pointer-shaped runs are hypotheses until an emulator trace proves
which runtime consumer reads them.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import zlib

try:
    from .patch_io import PatchError, sha256_bytes
    from .sfgfc_huffman import CANDIDATE_END_SYMBOL, decode_symbols, load_trees_at
    from .v5_1_engine import (
        EXPECTED_CONTEXTS,
        EXPECTED_TARGET_CRC32,
        EXPECTED_TARGET_SIZE,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
except ImportError:  # direct script execution
    from patch_io import PatchError, sha256_bytes
    from sfgfc_huffman import CANDIDATE_END_SYMBOL, decode_symbols, load_trees_at
    from v5_1_engine import (
        EXPECTED_CONTEXTS,
        EXPECTED_TARGET_CRC32,
        EXPECTED_TARGET_SIZE,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )

BANK_SIZE = 0x4000
MAX_RANKED_TABLES = 24
MAX_DECODED_TABLES = 96
DECODE_SAMPLES = 24
FULL_DECODED_TABLES = 4


def _hex(value: int, width: int = 6) -> str:
    return f"0x{value:0{width}X}"


def verify_target_identity(rom: bytes) -> None:
    if len(rom) != EXPECTED_TARGET_SIZE:
        raise PatchError(
            f"v5.1 target size mismatch: expected {_hex(EXPECTED_TARGET_SIZE)}, "
            f"found {_hex(len(rom))}"
        )
    actual_crc = zlib.crc32(rom) & 0xFFFFFFFF
    if actual_crc != EXPECTED_TARGET_CRC32:
        raise PatchError(
            f"v5.1 target CRC32 mismatch: expected {EXPECTED_TARGET_CRC32:08X}, "
            f"found {actual_crc:08X}"
        )


def mapper_file_offset(bank: int, address: int, rom_size: int) -> int | None:
    """Map a candidate 16 KiB slot pointer; runtime mapper state is not implied."""

    bank_count = (rom_size + BANK_SIZE - 1) // BANK_SIZE
    if not (0 <= bank < bank_count):
        return None
    if not (0x4000 <= address < 0xC000):
        return None
    target = bank * BANK_SIZE + (address & 0x3FFF)
    return target if target < rom_size else None


def _find_all(data: bytes, pattern: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        at = data.find(pattern, start)
        if at < 0:
            return hits
        hits.append(at)
        start = at + 1


def find_literal_references(rom: bytes, max_examples: int = 32) -> dict[str, object]:
    """Find exact Z80-shaped literals without claiming disassembly coverage."""

    specs = (
        ("korean_tree_vector", 0x4100, 0x20),
        ("korean_runtime_primary", 0x7000, 0x21),
        ("korean_runtime_secondary", 0x7A00, 0x21),
        ("slot1_mapper_register", 0xFFFE, None),
        ("slot2_mapper_register", 0xFFFF, None),
    )
    ordinary = (
        ("ld_bc_nn", b"\x01"),
        ("ld_de_nn", b"\x11"),
        ("ld_hl_nn", b"\x21"),
        ("ld_sp_nn", b"\x31"),
        ("jp_nn", b"\xC3"),
        ("call_nn", b"\xCD"),
        ("ld_mem_a", b"\x32"),
        ("ld_a_mem", b"\x3A"),
        ("ld_mem_hl", b"\x22"),
        ("ld_hl_mem", b"\x2A"),
    )
    indexed = (("ld_ix_nn", b"\xDD\x21"), ("ld_iy_nn", b"\xFD\x21"))
    result: dict[str, object] = {}
    for label, address, bank in specs:
        encoded = address.to_bytes(2, "little")
        examples: list[dict[str, object]] = []
        total = 0
        for instruction, prefix in ordinary + indexed:
            for at in _find_all(rom, prefix + encoded):
                total += 1
                if len(examples) >= max_examples:
                    continue
                nearby_bank = False
                if bank is not None:
                    left = max(0, at - 24)
                    right = min(len(rom), at + len(prefix) + 2 + 24)
                    nearby_bank = rom.find(bytes((0x3E, bank)), left, right) >= 0
                examples.append(
                    {
                        "file_offset": at,
                        "instruction_shape": instruction,
                        "nearby_ld_a_bank_literal": nearby_bank,
                    }
                )
        result[label] = {
            "logical_address": address,
            "expected_bank": bank,
            "candidate_count": total,
            "examples": examples,
            "examples_truncated": total > len(examples),
        }
    return result


def _decode_metrics(
    rom: bytes,
    known: bytes,
    trees: dict[int, object],
    target_offsets: list[int],
) -> dict[str, object]:
    if not target_offsets:
        return {
            "attempted": 0,
            "bounded_terminations": 0,
            "termination_ratio": 0.0,
            "median_symbols": None,
        }
    count = min(DECODE_SAMPLES, len(target_offsets))
    if count == 1:
        indices = [0]
    else:
        indices = sorted(
            {round(index * (len(target_offsets) - 1) / (count - 1)) for index in range(count)}
        )
    lengths: list[int] = []
    for index in indices:
        try:
            symbols, _ = decode_symbols(
                rom,
                known,
                trees,
                target_offsets[index],
                initial_symbol=CANDIDATE_END_SYMBOL,
                end_symbol=CANDIDATE_END_SYMBOL,
                max_symbols=256,
                max_bytes=256,
            )
        except PatchError:
            continue
        lengths.append(len(symbols))
    return {
        "attempted": len(indices),
        "bounded_terminations": len(lengths),
        "termination_ratio": round(len(lengths) / len(indices), 4),
        "median_symbols": None if not lengths else statistics.median(lengths),
    }


def _full_decode_metrics(
    rom: bytes,
    known: bytes,
    trees: dict[int, object],
    target_offsets: list[int],
) -> dict[str, object]:
    """Decode every entry while returning aggregate, ROM-safe metrics only."""

    lengths: list[int] = []
    for target in target_offsets:
        try:
            symbols, _ = decode_symbols(
                rom,
                known,
                trees,
                target,
                initial_symbol=CANDIDATE_END_SYMBOL,
                end_symbol=CANDIDATE_END_SYMBOL,
                max_symbols=256,
                max_bytes=256,
            )
        except PatchError:
            continue
        lengths.append(len(symbols))
    attempted = len(target_offsets)
    distinct_targets = len(set(target_offsets))
    return {
        "attempted": attempted,
        "bounded_terminations": len(lengths),
        "termination_ratio": (
            0.0 if not attempted else round(len(lengths) / attempted, 4)
        ),
        "min_symbols": None if not lengths else min(lengths),
        "median_symbols": None if not lengths else statistics.median(lengths),
        "max_symbols": None if not lengths else max(lengths),
        "distinct_targets": distinct_targets,
        "distinct_target_ratio": (
            0.0 if not attempted else round(distinct_targets / attempted, 4)
        ),
        "target_span": (
            0 if not target_offsets else max(target_offsets) - min(target_offsets)
        ),
    }


def _append_triplet_run(
    output: list[dict[str, object]],
    start: int,
    order: str,
    targets: list[int],
) -> None:
    if len(targets) < 8:
        return
    unique_ratio = len(set(targets)) / len(targets)
    if unique_ratio < 0.25:
        return
    monotonic = sum(
        1 for left, right in zip(targets, targets[1:]) if 0 <= right - left <= 0x4000
    )
    monotonic_ratio = monotonic / max(1, len(targets) - 1)
    source_region_ratio = sum(target < 0x80000 for target in targets) / len(targets)
    output.append(
        {
            "file_offset": start,
            "end_exclusive": start + len(targets) * 3,
            "format": order,
            "entries": len(targets),
            "unique_target_ratio": round(unique_ratio, 4),
            "monotonic_ratio": round(monotonic_ratio, 4),
            "original_512k_target_ratio": round(source_region_ratio, 4),
            "_targets": targets,
            "_pre_score": (
                min(len(targets), 256) * 3
                + unique_ratio * 20
                + monotonic_ratio * 35
            ),
        }
    )


def find_triplet_tables(
    rom: bytes,
    trees: dict[int, object] | None = None,
    minimum_run: int = 8,
) -> tuple[list[dict[str, object]], int]:
    """Rank bank/address triplet runs in both common field orders."""

    candidates: list[dict[str, object]] = []
    for order in ("bank_addr_le", "addr_le_bank"):
        for phase in range(3):
            run_start = phase
            targets: list[int] = []
            at = phase
            while at + 3 <= len(rom):
                if order == "bank_addr_le":
                    bank = rom[at]
                    address = rom[at + 1] | (rom[at + 2] << 8)
                else:
                    address = rom[at] | (rom[at + 1] << 8)
                    bank = rom[at + 2]
                target = mapper_file_offset(bank, address, len(rom))
                if target is None:
                    if len(targets) >= minimum_run:
                        _append_triplet_run(candidates, run_start, order, targets)
                    targets = []
                    run_start = at + 3
                else:
                    if not targets:
                        run_start = at
                    targets.append(target)
                    if len(targets) == 4096:
                        _append_triplet_run(candidates, run_start, order, targets)
                        targets = []
                        run_start = at + 3
                at += 3
            if len(targets) >= minimum_run:
                _append_triplet_run(candidates, run_start, order, targets)

    raw_count = len(candidates)
    candidates.sort(key=lambda item: item["_pre_score"], reverse=True)
    candidates = candidates[:MAX_DECODED_TABLES]
    known = bytes((1,)) * len(rom)
    for candidate in candidates:
        targets = candidate["_targets"]
        metrics = _decode_metrics(rom, known, trees or {}, targets)
        candidate["decode_probe"] = metrics
        candidate["score"] = round(
            candidate["_pre_score"]
            + metrics["termination_ratio"] * 120
            + metrics["bounded_terminations"] * 4,
            2,
        )
    candidates.sort(key=lambda item: item["score"], reverse=True)
    for candidate in candidates[:FULL_DECODED_TABLES]:
        candidate["full_decode_probe"] = _full_decode_metrics(
            rom, known, trees or {}, candidate["_targets"]
        )
    for candidate in candidates:
        del candidate["_targets"]
        del candidate["_pre_score"]
    return candidates[:MAX_RANKED_TABLES], raw_count


def _append_pair_run(
    output: list[dict[str, object]],
    start: int,
    addresses: list[int],
) -> None:
    if len(addresses) < 12:
        return
    slot = addresses[0] >> 14
    if any((address >> 14) != slot for address in addresses):
        return
    unique_ratio = len(set(addresses)) / len(addresses)
    monotonic = sum(
        1 for left, right in zip(addresses, addresses[1:]) if 0 <= right - left <= 0x1000
    )
    monotonic_ratio = monotonic / max(1, len(addresses) - 1)
    if unique_ratio < 0.75 or monotonic_ratio < 0.70:
        return
    output.append(
        {
            "file_offset": start,
            "end_exclusive": start + len(addresses) * 2,
            "format": "addr_le_bank_unresolved",
            "entries": len(addresses),
            "logical_slot": 1 if slot == 1 else 2,
            "unique_address_ratio": round(unique_ratio, 4),
            "monotonic_ratio": round(monotonic_ratio, 4),
            "score": round(min(len(addresses), 256) * 2 + monotonic_ratio * 40, 2),
        }
    )


def find_pair_tables(rom: bytes) -> tuple[list[dict[str, object]], int]:
    """Find conservative same-slot 16-bit runs; their runtime bank stays unknown."""

    candidates: list[dict[str, object]] = []
    for phase in range(2):
        addresses: list[int] = []
        run_start = phase
        at = phase
        while at + 2 <= len(rom):
            address = rom[at] | (rom[at + 1] << 8)
            if 0x4000 <= address < 0xC000:
                if addresses and (address >> 14) != (addresses[0] >> 14):
                    _append_pair_run(candidates, run_start, addresses)
                    addresses = []
                    run_start = at
                if not addresses:
                    run_start = at
                addresses.append(address)
                if len(addresses) == 4096:
                    _append_pair_run(candidates, run_start, addresses)
                    addresses = []
                    run_start = at + 2
            else:
                _append_pair_run(candidates, run_start, addresses)
                addresses = []
                run_start = at + 2
            at += 2
        _append_pair_run(candidates, run_start, addresses)
    raw_count = len(candidates)
    candidates.sort(key=lambda item: item["score"], reverse=True)
    return candidates[:MAX_RANKED_TABLES], raw_count


def analyze_rom(rom: bytes) -> dict[str, object]:
    verify_target_identity(rom)
    known = bytes((1,)) * len(rom)
    trees = load_trees_at(
        rom,
        known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    contexts = tuple(sorted(trees))
    if contexts != EXPECTED_CONTEXTS:
        raise PatchError("full-ROM Korean Huffman vector does not match v5.1")

    references = find_literal_references(rom)
    triplets, triplet_count = find_triplet_tables(rom, trees)
    pairs, pair_count = find_pair_tables(rom)
    return {
        "schema_version": 1,
        "status": "candidate-scan-complete",
        "input": {
            "size": len(rom),
            "sha256": sha256_bytes(rom),
            "crc32": f"{zlib.crc32(rom) & 0xFFFFFFFF:08X}",
        },
        "confirmed_static_inputs": {
            "korean_huffman_contexts": len(trees),
            "korean_tree_vector_offset": KO_VECTOR_OFFSET,
        },
        "literal_reference_candidates": references,
        "pointer_table_candidates": {
            "triplet_runs_found": triplet_count,
            "ranked_triplet_runs": triplets,
            "pair_runs_found": pair_count,
            "ranked_pair_runs": pairs,
        },
        "consumer_evidence_confirmed": False,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "trace the highest-ranked candidate at runtime and record mapper state "
            "before promoting any lookup coordinates"
        ),
    }


def to_markdown(result: dict[str, object]) -> str:
    refs = result["literal_reference_candidates"]
    tables = result["pointer_table_candidates"]
    assert isinstance(refs, dict) and isinstance(tables, dict)
    lines = [
        "# v5.1 script lookup candidate report",
        "",
        "Status: candidate scan complete; runtime consumer not yet confirmed",
        "",
        "This report contains coordinates and aggregate metrics only. Exact byte",
        "signatures and pointer-shaped runs are hypotheses, not disassembly proof.",
        "",
        "## Exact literal shapes",
        "",
        "| Target | Logical | Candidate shapes | Nearby bank literal examples |",
        "|---|---:|---:|---:|",
    ]
    for label, item in refs.items():
        assert isinstance(item, dict)
        nearby = sum(
            bool(example["nearby_ld_a_bank_literal"])
            for example in item["examples"]
        )
        lines.append(
            f"| {label} | {_hex(item['logical_address'], 4)} | "
            f"{item['candidate_count']} | {nearby} |"
        )

    triplets = tables["ranked_triplet_runs"]
    assert isinstance(triplets, list)
    lines.extend(
        [
            "",
            "## Ranked bank/address triplet runs",
            "",
            f"Runs meeting the structural filter: {tables['triplet_runs_found']}",
            "",
            "| Rank | File offset | Format | Entries | Monotonic | Decode terminations | Score |",
            "|---:|---:|---|---:|---:|---:|---:|",
        ]
    )
    if triplets:
        for rank, item in enumerate(triplets, 1):
            probe = item["decode_probe"]
            lines.append(
                f"| {rank} | {_hex(item['file_offset'])} | {item['format']} | "
                f"{item['entries']} | {item['monotonic_ratio']:.2f} | "
                f"{probe['bounded_terminations']}/{probe['attempted']} | "
                f"{item['score']:.2f} |"
            )
    else:
        lines.append("| - | - | none | 0 | - | - | - |")

    pairs = tables["ranked_pair_runs"]
    assert isinstance(pairs, list)
    lines.extend(
        [
            "",
            "## Ranked 16-bit address runs",
            "",
            f"Runs meeting the conservative filter: {tables['pair_runs_found']}",
            "",
            "| Rank | File offset | Slot | Entries | Monotonic | Score |",
            "|---:|---:|---:|---:|---:|---:|",
        ]
    )
    if pairs:
        for rank, item in enumerate(pairs, 1):
            lines.append(
                f"| {rank} | {_hex(item['file_offset'])} | {item['logical_slot']} | "
                f"{item['entries']} | {item['monotonic_ratio']:.2f} | "
                f"{item['score']:.2f} |"
            )
    else:
        lines.append("| - | - | - | 0 | - | - |")

    lines.extend(
        [
            "",
            "## Guardrail and next checkpoint",
            "",
            "- Consumer evidence confirmed: no",
            "- Translation build eligible: no",
            "- Next: trace the highest-ranked candidate while the game displays a known message,",
            "  then record PC, mapper bank, lookup entry, compressed target, and first bounded decode.",
            "",
        ]
    )
    return "\n".join(lines)


def to_korean_summary(result: dict[str, object]) -> str:
    tables = result["pointer_table_candidates"]
    assert isinstance(tables, dict)
    triplets = tables["ranked_triplet_runs"]
    pairs = tables["ranked_pair_runs"]
    top = "없음"
    if triplets:
        top = _hex(triplets[0]["file_offset"])
    elif pairs:
        top = _hex(pairs[0]["file_offset"])
    return "\n".join(
        [
            "샤이닝 포스 외전 파이널 컨플릭트 한글화 자동 작업 결과",
            "",
            "[완료]",
            "- 깨끗한 일본판 ROM 및 v5.1 BPS 신원 확인",
            "- v5.1 한글 ROM 로컬 빌드",
            "- 한글 허프만 트리와 폰트 런타임 검증",
            "- 스크립트 조회용 코드/포인터 후보 자동 탐색",
            "",
            "[이번 탐색]",
            f"- 3바이트 포인터 구조 후보: {tables['triplet_runs_found']}개",
            f"- 2바이트 주소 구조 후보: {tables['pair_runs_found']}개",
            f"- 현재 최상위 후보 위치: {top}",
            "",
            "[아직 확정하지 않은 것]",
            "- 후보 위치가 실제 대사 표시 루틴에서 소비되는지는 실행 추적이 필요합니다.",
            "- 오탐 방지를 위해 아직 번역 데이터를 빌드 가능 상태로 표시하지 않았습니다.",
            "",
            "[다음 자동화 체크포인트]",
            "- 최상위 후보를 기준으로 에뮬레이터 실행 추적 좌표를 확정합니다.",
            "- PC, 매퍼 뱅크, 조회 항목, 압축 데이터 시작점이 연결되면 추출 단계로 승격합니다.",
            "",
            "상세 파일: v5_1_script_lookup_candidates.md, pipeline_status.json",
            "ROM과 원문 데이터는 GitHub에 저장되지 않습니다.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, required=True, help="locally built v5.1 ROM")
    parser.add_argument("--json", type=Path, help="optional JSON report")
    parser.add_argument("--markdown", type=Path, help="optional Markdown report")
    parser.add_argument("--summary", type=Path, help="optional Korean text summary")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()

    result = analyze_rom(args.rom.read_bytes())
    for path, text in (
        (args.json, json.dumps(result, ensure_ascii=False, indent=2) + "\n"),
        (args.markdown, to_markdown(result)),
        (args.summary, to_korean_summary(result)),
    ):
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"Wrote report: {path}")
    if args.stdout or not any((args.json, args.markdown, args.summary)):
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
