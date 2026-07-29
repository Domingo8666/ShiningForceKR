#!/usr/bin/env python3
"""Turn ranked v5.1 lookup candidates into a reproducible emucap watch plan.

The output is still a hypothesis record. Exact byte-shaped references are not
promoted to consumer evidence until a Game Gear runtime read breakpoint fires
with matching mapper state.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .v5_1_consumer import analyze_rom
except ImportError:  # direct script execution
    from v5_1_consumer import analyze_rom

BANK_SIZE = 0x4000
MAX_HYPOTHESES = 12
MAX_REFERENCE_EXAMPLES = 16

REFERENCE_SHAPES = (
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
    ("ld_ix_nn", b"\xDD\x21"),
    ("ld_iy_nn", b"\xFD\x21"),
)


def _hex(value: int, width: int = 6) -> str:
    return f"0x{value:0{width}X}"


def _find_all(data: bytes, pattern: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        at = data.find(pattern, start)
        if at < 0:
            return hits
        hits.append(at)
        start = at + 1


def logical_mapping_hypotheses(file_offset: int, extent: int) -> list[dict[str, object]]:
    """Return standard-Sega-mapper hypotheses for one physical ROM extent."""

    bank = file_offset // BANK_SIZE
    in_bank = file_offset % BANK_SIZE
    watched = min(max(1, extent), BANK_SIZE - in_bank)
    mappings: list[dict[str, object]] = []

    # The first 1 KiB of slot 0 is fixed to bank 0. Above it, mapper state is
    # required; bank 0 remains a valid hypothesis for the observed top result.
    if bank == 0 or in_bank >= 0x0400:
        mappings.append(
            {
                "slot": 0,
                "bank": bank,
                "logical_start": in_bank,
                "logical_end": in_bank + watched - 1,
                "mapping_note": (
                    "fixed-first-1k" if in_bank < 0x0400 else "slot0-mapper-state-required"
                ),
                "extent_truncated_at_bank_end": watched != extent,
            }
        )
    for slot, base in ((1, 0x4000), (2, 0x8000)):
        mappings.append(
            {
                "slot": slot,
                "bank": bank,
                "logical_start": base + in_bank,
                "logical_end": base + in_bank + watched - 1,
                "mapping_note": f"slot{slot}-mapper-state-required",
                "extent_truncated_at_bank_end": watched != extent,
            }
        )
    return mappings


def _reference_shapes(
    rom: bytes,
    logical_address: int,
    expected_bank: int,
) -> dict[str, object]:
    encoded = logical_address.to_bytes(2, "little")
    examples: list[dict[str, object]] = []
    count = 0
    coupled = 0
    for shape, prefix in REFERENCE_SHAPES:
        for at in _find_all(rom, prefix + encoded):
            count += 1
            left = max(0, at - 24)
            right = min(len(rom), at + len(prefix) + 2 + 24)
            has_bank_literal = rom.find(bytes((0x3E, expected_bank)), left, right) >= 0
            coupled += int(has_bank_literal)
            if len(examples) < MAX_REFERENCE_EXAMPLES:
                examples.append(
                    {
                        "code_file_offset": at,
                        "instruction_shape": shape,
                        "nearby_ld_a_bank_literal": has_bank_literal,
                    }
                )
    return {
        "candidate_count": count,
        "nearby_bank_literal_count": coupled,
        "examples": examples,
        "examples_truncated": count > len(examples),
    }


def _table_hypotheses(consumer: dict[str, object]) -> list[dict[str, object]]:
    tables = consumer["pointer_table_candidates"]
    assert isinstance(tables, dict)
    output: list[dict[str, object]] = []
    for family, entries, width in (
        ("triplet", tables["ranked_triplet_runs"], 3),
        ("pair", tables["ranked_pair_runs"], 2),
    ):
        assert isinstance(entries, list)
        for original_rank, item in enumerate(entries, 1):
            output.append(
                {
                    "family": family,
                    "original_rank": original_rank,
                    "file_offset": item["file_offset"],
                    "end_exclusive": item["end_exclusive"],
                    "format": item["format"],
                    "entries": item["entries"],
                    "entry_width": width,
                    "scanner_score": item["score"],
                }
            )
    return output


def build_trace_plan(rom: bytes, consumer: dict[str, object]) -> dict[str, object]:
    ranked: list[dict[str, object]] = []
    for item in _table_hypotheses(consumer):
        extent = int(item["end_exclusive"]) - int(item["file_offset"])
        mappings = logical_mapping_hypotheses(int(item["file_offset"]), extent)
        reference_total = 0
        coupled_total = 0
        for mapping in mappings:
            refs = _reference_shapes(
                rom,
                int(mapping["logical_start"]),
                int(mapping["bank"]),
            )
            mapping["reference_shapes"] = refs
            reference_total += int(refs["candidate_count"])
            coupled_total += int(refs["nearby_bank_literal_count"])
        score = (
            float(item["scanner_score"])
            + reference_total * 100
            + coupled_total * 50
        )
        ranked.append(
            {
                **item,
                "logical_mappings": mappings,
                "reference_shape_count": reference_total,
                "nearby_bank_literal_count": coupled_total,
                "combined_candidate_score": round(score, 2),
            }
        )

    ranked.sort(
        key=lambda item: (
            item["combined_candidate_score"],
            item["reference_shape_count"],
            -item["file_offset"],
        ),
        reverse=True,
    )
    ranked = ranked[:MAX_HYPOTHESES]
    selected = ranked[0] if ranked else None

    arm_steps: list[dict[str, object]] = []
    if selected:
        for mapping in selected["logical_mappings"]:
            arm_steps.append(
                {
                    "tool": "set_breakpoint",
                    "purpose": (
                        f"candidate {_hex(selected['file_offset'])}, "
                        f"slot {mapping['slot']}, expected bank 0x{mapping['bank']:02X}"
                    ),
                    "args": {
                        "kind": "read",
                        "memory_type": "smsMemory",
                        "start": mapping["logical_start"],
                        "end": mapping["logical_end"],
                        "pause_on_hit": True,
                        "auto_savestate": True,
                        "snapshot": ["smsMemory:65532:4"],
                    },
                }
            )

    return {
        "schema_version": 1,
        "status": "runtime-trace-plan-ready",
        "source_analysis_sha256": consumer["input"]["sha256"],
        "ranked_consumer_hypotheses": ranked,
        "selected_hypothesis": selected,
        "emucap": {
            "required_system": "gamegear",
            "required_memory_type": "smsMemory",
            "preconditions": [
                "emucap status reports connected=true",
                "status methods include read breakpoints, poll_events, disassemble, and trace",
                "get_rom_info identifies the same locally built v5.1 ROM",
            ],
            "before_resume": [
                {"tool": "set_trace", "args": {"enabled": True}},
                *arm_steps,
            ],
            "on_first_hit": [
                {"tool": "poll_events", "args": {}},
                {"tool": "get_state", "args": {}},
                {"tool": "get_trace", "args": {"count": 64}},
                {
                    "tool": "disassemble",
                    "args_from_hit": {"address": "event.pc", "count": 16},
                },
                {"tool": "call_stack", "args": {}},
            ],
            "mapper_snapshot": {
                "memory": "smsMemory",
                "start": 0xFFFC,
                "length": 4,
                "meaning": "Sega mapper control and slot bank registers",
            },
        },
        "consumer_evidence_confirmed": False,
        "promotion_gate": (
            "a read hit must connect hit PC, bank tag, mapper registers, selected "
            "entry bytes, compressed target, and a bounded decode"
        ),
    }


def to_markdown(plan: dict[str, object]) -> str:
    ranked = plan["ranked_consumer_hypotheses"]
    selected = plan["selected_hypothesis"]
    assert isinstance(ranked, list)
    lines = [
        "# v5.1 emucap runtime trace plan",
        "",
        "Status: plan ready; runtime consumer not yet confirmed",
        "",
        "Byte-shaped references only adjust candidate priority. They are not",
        "disassembly or runtime-consumption proof.",
        "",
        "## Ranked consumer hypotheses",
        "",
        "| Rank | File offset | Family | Entries | Reference shapes | Bank-coupled | Score |",
        "|---:|---:|---|---:|---:|---:|---:|",
    ]
    if ranked:
        for rank, item in enumerate(ranked, 1):
            lines.append(
                f"| {rank} | {_hex(item['file_offset'])} | {item['family']} | "
                f"{item['entries']} | {item['reference_shape_count']} | "
                f"{item['nearby_bank_literal_count']} | "
                f"{item['combined_candidate_score']:.2f} |"
            )
    else:
        lines.append("| - | - | none | 0 | 0 | 0 | - |")

    lines.extend(["", "## Selected watch ranges", ""])
    if selected:
        lines.extend(
            [
                f"- Physical ROM candidate: {_hex(selected['file_offset'])}",
                f"- Format: {selected['format']}, {selected['entries']} entries",
                "",
                "| Slot | Expected bank | CPU read range | Mapping note |",
                "|---:|---:|---:|---|",
            ]
        )
        for mapping in selected["logical_mappings"]:
            lines.append(
                f"| {mapping['slot']} | 0x{mapping['bank']:02X} | "
                f"{_hex(mapping['logical_start'], 4)}..{_hex(mapping['logical_end'], 4)} | "
                f"{mapping['mapping_note']} |"
            )
    else:
        lines.append("- No structural candidate survived the scanner.")

    lines.extend(
        [
            "",
            "## emucap sequence",
            "",
            "1. Launch the locally built ROM as system gamegear and verify its identity.",
            "2. Enable trace and arm every listed smsMemory read range.",
            "3. Resume from a state immediately before a known message is drawn.",
            "4. On the first hit, capture the event, Z80 state, bank tag, mapper bytes",
            "   at 0xFFFC..0xFFFF, 64 trace entries, disassembly, and call stack.",
            "5. Promote coordinates only if the hit also identifies the selected entry,",
            "   compressed target, and a bounded decode.",
            "",
            "## Guardrail",
            "",
            "- Consumer evidence confirmed: no",
            "- Translation build eligible: no",
            "",
        ]
    )
    return "\n".join(lines)


def to_korean_summary(plan: dict[str, object]) -> str:
    selected = plan["selected_hypothesis"]
    if not selected:
        return "\n".join(
            [
                "[소비 코드 2차 분석]",
                "- 실행 추적 대상으로 승격할 후보가 없습니다.",
                "- 후보 필터를 다시 설계해야 합니다.",
                "",
            ]
        )
    mappings = ", ".join(
        f"{_hex(item['logical_start'], 4)}..{_hex(item['logical_end'], 4)}"
        for item in selected["logical_mappings"]
    )
    return "\n".join(
        [
            "[소비 코드 2차 분석]",
            f"- 선택된 물리 ROM 후보: {_hex(selected['file_offset'])}",
            f"- 구조: {selected['family']} / {selected['entries']}개 항목",
            f"- 코드 리터럴 모양 참조: {selected['reference_shape_count']}개",
            f"- 실행 읽기 감시 범위: {mappings}",
            "- 아직 실행 중 읽기 증거가 없으므로 확정 조회표가 아닙니다.",
            "",
            "[다음 실행 추적]",
            "- emucap Game Gear 연결에서 위 범위의 read breakpoint를 사용합니다.",
            "- 첫 히트의 PC, bank 태그, 0xFFFC..0xFFFF 매퍼 값과 trace를 함께 기록합니다.",
            "",
            "상세 파일: v5_1_emucap_trace_plan.md, v5_1_emucap_trace_plan.json",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, required=True, help="locally built v5.1 ROM")
    parser.add_argument("--json", type=Path, help="optional JSON plan")
    parser.add_argument("--markdown", type=Path, help="optional Markdown plan")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()

    rom = args.rom.read_bytes()
    plan = build_trace_plan(rom, analyze_rom(rom))
    for path, text in (
        (args.json, json.dumps(plan, ensure_ascii=False, indent=2) + "\n"),
        (args.markdown, to_markdown(plan)),
    ):
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"Wrote trace plan: {path}")
    if args.stdout or not any((args.json, args.markdown)):
        print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
