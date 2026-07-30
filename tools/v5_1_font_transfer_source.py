#!/usr/bin/env python3
"""Trace candidate font ROM reads through RAM to confirmed VDP writes.

The renderer trace already captured on the S25U contains enough information
for this stage.  Exact pages, banks, addresses, opcodes, registers, and trace
lines remain in ignored local reports.  The publishable artifact contains
only counts, identity links, and promotion-gate booleans.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

try:
    from .patch_io import sha256_file
    from .v5_1_initial_font_page_trace import (
        PUBLISH_RELATIVE_PATH as INITIAL_TRACE_PATH,
        runtime_entry_matches,
        validate_initial_font_page_trace,
    )
    from .v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        LOCAL_REPORT_PATH as LOCAL_RENDERER_PATH,
        PUBLISH_RELATIVE_PATH as RENDERER_TRACE_PATH,
        _classify_vdp_output,
        _load_json_object,
        validate_renderer_output_trace,
    )
    from .v5_1_runtime_hit_resolver import (
        _parse_trace_line,
        _read_addresses,
    )
    from .v5_1_test_phrase import (
        FONT_DATA_FIRST_BANK,
        FONT_PAGES_PER_BANK,
    )
    from .v5_1_visible_unicode_mapping import (
        LOCAL_REPORT_PATH as LOCAL_MAPPING_PATH,
        PUBLISH_RELATIVE_PATH as MAPPING_PATH,
        validate_visible_unicode_mapping,
    )
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_initial_font_page_trace import (
        PUBLISH_RELATIVE_PATH as INITIAL_TRACE_PATH,
        runtime_entry_matches,
        validate_initial_font_page_trace,
    )
    from v5_1_renderer_output_trace import (
        DEFAULT_ROM,
        LOCAL_REPORT_PATH as LOCAL_RENDERER_PATH,
        PUBLISH_RELATIVE_PATH as RENDERER_TRACE_PATH,
        _classify_vdp_output,
        _load_json_object,
        validate_renderer_output_trace,
    )
    from v5_1_runtime_hit_resolver import _parse_trace_line, _read_addresses
    from v5_1_test_phrase import (
        FONT_DATA_FIRST_BANK,
        FONT_PAGES_PER_BANK,
    )
    from v5_1_visible_unicode_mapping import (
        LOCAL_REPORT_PATH as LOCAL_MAPPING_PATH,
        PUBLISH_RELATIVE_PATH as MAPPING_PATH,
        validate_visible_unicode_mapping,
    )


ARTIFACT_KIND = "sanitized-s25u-font-transfer-source"
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_font_transfer_source.json"
)
LOCAL_REPORT_PATH = Path("reports/local/v5_1_font_transfer_source.json")
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_mapping_sha256",
    "source_renderer_trace_sha256",
    "source_initial_trace_sha256",
    "captured_utc",
    "runtime_entry",
    "candidate_page_count_before",
    "candidate_page_count_after",
    "candidate_bank_count_before",
    "observed_candidate_bank_count",
    "mapper_write_count",
    "candidate_font_read_count",
    "ram_buffer_link_count",
    "font_transfer_source_confirmed",
    "local_payload_policy",
    "translation_build_eligible",
    "next_checkpoint",
}
RUNTIME_ENTRY_KEYS = {
    "physical_start",
    "logical_start",
    "mapped_bank",
    "record_length_bytes",
}
_A_LOADS_FROM_MEMORY = {0x0A, 0x1A, 0x3A, 0x7E}
_A_ORIGIN_CLEARED_BY = (
    {0x07, 0x0F, 0x17, 0x1F, 0x27, 0x2F, 0x37, 0x3C, 0x3D, 0x3E, 0x3F}
    | set(range(0x78, 0x7E))
    | set(range(0x80, 0xC0))
    | {0xC6, 0xCE, 0xD6, 0xDE, 0xE6, 0xEE, 0xF6, 0xFE}
)


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


def _font_bank(page: int) -> int:
    return FONT_DATA_FIRST_BANK + page // FONT_PAGES_PER_BANK


def _candidate_pages_by_bank(
    candidate_pages: list[int],
) -> dict[int, list[int]]:
    if (
        not candidate_pages
        or candidate_pages != sorted(set(candidate_pages))
        or any(not 0 <= page < 244 for page in candidate_pages)
    ):
        raise ValueError("font transfer page candidates are invalid")
    grouped: dict[int, list[int]] = {}
    for page in candidate_pages:
        grouped.setdefault(_font_bank(page), []).append(page)
    return grouped


def _coerce_int(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} is invalid")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ValueError(f"{field} is invalid") from error
    raise ValueError(f"{field} is invalid")


def _mapped_bank_for_address(
    address: int,
    slot1_bank: int,
    slot2_bank: int,
) -> int | None:
    if 0x4000 <= address <= 0x7FFF:
        return slot1_bank
    if 0x8000 <= address <= 0xBFFF:
        return slot2_bank
    return None


def _physical_address(bank: int, logical: int) -> int:
    return bank * 0x4000 + (logical & 0x3FFF)


def _write_a_address(
    opcodes: bytes,
    registers: dict[str, int],
) -> int | None:
    if not opcodes:
        return None
    first = opcodes[0]
    if first == 0x02:
        return registers.get("bc", 0) & 0xFFFF
    if first == 0x12:
        return registers.get("de", 0) & 0xFFFF
    if first == 0x32 and len(opcodes) >= 3:
        return opcodes[1] | (opcodes[2] << 8)
    if first == 0x77:
        return registers.get("hl", 0) & 0xFFFF
    return None


def _block_copy_addresses(
    opcodes: bytes,
    registers: dict[str, int],
) -> tuple[int, int] | None:
    if len(opcodes) < 2 or opcodes[0] != 0xED:
        return None
    second = opcodes[1]
    hl = registers.get("hl", 0) & 0xFFFF
    de = registers.get("de", 0) & 0xFFFF
    if second in {0xA0, 0xB0}:  # LDI / LDIR, registers are post-step.
        return (hl - 1) & 0xFFFF, (de - 1) & 0xFFFF
    if second in {0xA8, 0xB8}:  # LDD / LDDR.
        return (hl + 1) & 0xFFFF, (de + 1) & 0xFFFF
    return None


def _output_memory_address(
    opcodes: bytes,
    registers: dict[str, int],
) -> int | None:
    if len(opcodes) < 2 or opcodes[0] != 0xED:
        return None
    second = opcodes[1]
    hl = registers.get("hl", 0) & 0xFFFF
    if second in {0xA3, 0xB3}:  # OUTI / OTIR.
        return (hl - 1) & 0xFFFF
    if second in {0xAB, 0xBB}:  # OUTD / OTDR.
        return (hl + 1) & 0xFFFF
    return None


def _origin_for_address(
    *,
    address: int,
    slot1_bank: int,
    slot2_bank: int,
    candidate_banks: set[int],
    ram_origins: dict[int, dict[str, int]],
    trace_index: int,
) -> dict[str, int] | None:
    bank = _mapped_bank_for_address(address, slot1_bank, slot2_bank)
    if bank in candidate_banks:
        assert bank is not None
        return {
            "font_bank": bank,
            "logical_address": address,
            "physical_address": _physical_address(bank, address),
            "trace_index": trace_index,
        }
    if 0xC000 <= address <= 0xFFFF:
        return ram_origins.get(address)
    return None


def analyze_font_transfer_trace(
    *,
    lines: list[str],
    candidate_pages: list[int],
    initial_slot1_bank: int,
    initial_slot2_bank: int,
) -> tuple[dict[str, object], dict[str, object]]:
    pages_by_bank = _candidate_pages_by_bank(candidate_pages)
    candidate_banks = set(pages_by_bank)
    slot1_bank = initial_slot1_bank
    slot2_bank = initial_slot2_bank
    if not 0 <= slot1_bank <= 0xFF or not 0 <= slot2_bank <= 0xFF:
        raise ValueError("initial mapper bank is invalid")

    mapper_writes: list[dict[str, int]] = []
    candidate_reads: list[dict[str, int]] = []
    ram_links: list[dict[str, int]] = []
    observed_banks: set[int] = set()
    ram_origins: dict[int, dict[str, int]] = {}
    a_origin: dict[str, int] | None = None
    parsed_instruction_count = 0
    vdp_output_count = 0

    for trace_index, line in enumerate(lines):
        parsed = _parse_trace_line(line)
        if parsed is None:
            continue
        parsed_instruction_count += 1
        opcodes = parsed["opcodes"]
        raw_registers = parsed["registers"]
        assert isinstance(opcodes, bytes)
        assert isinstance(raw_registers, dict)
        registers = {
            key: int(value)
            for key, value in raw_registers.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }

        read_origins: list[dict[str, int]] = []
        for address in _read_addresses(opcodes, registers):
            origin = _origin_for_address(
                address=address,
                slot1_bank=slot1_bank,
                slot2_bank=slot2_bank,
                candidate_banks=candidate_banks,
                ram_origins=ram_origins,
                trace_index=trace_index,
            )
            if origin is None:
                continue
            read_origins.append(origin)
            if _mapped_bank_for_address(
                address, slot1_bank, slot2_bank
            ) in candidate_banks:
                candidate_reads.append(
                    {
                        **origin,
                        "instruction_bank": int(parsed["bank"]),
                        "instruction_pc": int(parsed["pc"]),
                    }
                )
                observed_banks.add(origin["font_bank"])

        output = _classify_vdp_output(parsed)
        if output is not None:
            vdp_output_count += 1
            output_source = _output_memory_address(opcodes, registers)
            output_origin = (
                _origin_for_address(
                    address=output_source,
                    slot1_bank=slot1_bank,
                    slot2_bank=slot2_bank,
                    candidate_banks=candidate_banks,
                    ram_origins=ram_origins,
                    trace_index=trace_index,
                )
                if output_source is not None
                else a_origin
                if (
                    opcodes
                    and (
                        opcodes[0] == 0xD3
                        or (
                            len(opcodes) >= 2
                            and opcodes[0] == 0xED
                            and opcodes[1] == 0x79
                        )
                    )
                )
                else None
            )
            if output_origin is not None:
                observed_banks.add(output_origin["font_bank"])
                if (
                    output_source is None
                    or 0xC000 <= output_source <= 0xFFFF
                ):
                    ram_links.append(
                        {
                            **output_origin,
                            "output_trace_index": trace_index,
                            "output_port": int(output["port"]),
                        }
                    )

        block_copy = _block_copy_addresses(opcodes, registers)
        if block_copy is not None:
            source, destination = block_copy
            origin = _origin_for_address(
                address=source,
                slot1_bank=slot1_bank,
                slot2_bank=slot2_bank,
                candidate_banks=candidate_banks,
                ram_origins=ram_origins,
                trace_index=trace_index,
            )
            if 0xC000 <= destination <= 0xFFFF:
                if origin is None:
                    ram_origins.pop(destination, None)
                else:
                    ram_origins[destination] = origin

        write_address = _write_a_address(opcodes, registers)
        if write_address is not None and 0xC000 <= write_address <= 0xFFFF:
            if a_origin is None:
                ram_origins.pop(write_address, None)
            else:
                ram_origins[write_address] = a_origin

        if opcodes and (
            opcodes[0] in _A_LOADS_FROM_MEMORY
            or (
                len(opcodes) >= 2
                and opcodes[0] in {0xDD, 0xFD}
                and opcodes[1] == 0x7E
            )
        ):
            a_origin = read_origins[0] if read_origins else None
        elif opcodes and opcodes[0] in _A_ORIGIN_CLEARED_BY:
            a_origin = None

        if write_address in {0xFFFE, 0xFFFF}:
            mapped_bank = registers.get("a", 0) & 0xFF
            if write_address == 0xFFFE:
                slot1_bank = mapped_bank
                slot = 1
            else:
                slot2_bank = mapped_bank
                slot = 2
            mapper_writes.append(
                {
                    "slot": slot,
                    "mapped_bank": mapped_bank,
                    "trace_index": trace_index,
                    "instruction_bank": int(parsed["bank"]),
                    "instruction_pc": int(parsed["pc"]),
                }
            )

    remaining_pages = (
        [
            page
            for page in candidate_pages
            if _font_bank(page) in observed_banks
        ]
        if observed_banks
        else list(candidate_pages)
    )
    safe_counts: dict[str, object] = {
        "candidate_page_count_before": len(candidate_pages),
        "candidate_page_count_after": len(remaining_pages),
        "candidate_bank_count_before": len(candidate_banks),
        "observed_candidate_bank_count": len(observed_banks),
        "mapper_write_count": len(mapper_writes),
        "candidate_font_read_count": len(candidate_reads),
        "ram_buffer_link_count": len(ram_links),
    }
    local: dict[str, object] = {
        "candidate_pages_before": candidate_pages,
        "candidate_pages_after": remaining_pages,
        "candidate_banks": sorted(candidate_banks),
        "observed_candidate_banks": sorted(observed_banks),
        "mapper_writes": mapper_writes,
        "candidate_font_reads": candidate_reads,
        "ram_buffer_links": ram_links,
        "parsed_instruction_count": parsed_instruction_count,
        "vdp_output_count": vdp_output_count,
    }
    return safe_counts, local


def build_font_transfer_source(
    *,
    target_sha256: str,
    source_mapping_sha256: str,
    source_renderer_trace_sha256: str,
    source_initial_trace_sha256: str,
    runtime_entry: dict[str, object],
    analysis: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    before = int(analysis["candidate_page_count_before"])
    after = int(analysis["candidate_page_count_after"])
    observed = int(analysis["observed_candidate_bank_count"])
    confirmed = after == 1 and observed > 0
    status = (
        "font-transfer-source-confirmed"
        if confirmed
        else "font-transfer-bank-narrowed"
        if observed > 0 and after < before
        else "font-transfer-bank-observed-without-narrowing"
        if observed > 0
        else "font-transfer-source-not-yet-observed"
    )
    next_checkpoint = (
        "extract-full-script-record-set"
        if confirmed
        else "trace-font-transfer-buffer-producer"
        if observed > 0
        else "extend-font-transfer-trace-window"
    )
    safe = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_mapping_sha256": source_mapping_sha256,
        "source_renderer_trace_sha256": source_renderer_trace_sha256,
        "source_initial_trace_sha256": source_initial_trace_sha256,
        "captured_utc": captured_utc,
        "runtime_entry": {
            key: runtime_entry[key]
            for key in RUNTIME_ENTRY_KEYS
        },
        "candidate_page_count_before": before,
        "candidate_page_count_after": after,
        "candidate_bank_count_before": int(
            analysis["candidate_bank_count_before"]
        ),
        "observed_candidate_bank_count": observed,
        "mapper_write_count": int(analysis["mapper_write_count"]),
        "candidate_font_read_count": int(
            analysis["candidate_font_read_count"]
        ),
        "ram_buffer_link_count": int(analysis["ram_buffer_link_count"]),
        "font_transfer_source_confirmed": confirmed,
        "local_payload_policy": (
            "pages-banks-addresses-opcodes-registers-and-trace-local-only"
        ),
        "translation_build_eligible": False,
        "next_checkpoint": next_checkpoint,
    }
    validate_font_transfer_source(safe)
    return safe


def validate_font_transfer_source(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("font transfer source fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "font-transfer-source-confirmed",
            "font-transfer-bank-narrowed",
            "font-transfer-bank-observed-without-narrowing",
            "font-transfer-source-not-yet-observed",
        }
        or not all(
            _is_sha256(value[key])
            for key in (
                "target_sha256",
                "source_mapping_sha256",
                "source_renderer_trace_sha256",
                "source_initial_trace_sha256",
            )
        )
    ):
        raise ValueError("font transfer source policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("font transfer timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("font transfer timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("font transfer timestamp must include UTC")

    runtime = value["runtime_entry"]
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_ENTRY_KEYS:
        raise ValueError("font transfer runtime fields do not match")
    for key, minimum, maximum in (
        ("physical_start", 0, 0x17BFFF),
        ("logical_start", 0x4000, 0x7FFF),
        ("mapped_bank", 0, 0xFF),
        ("record_length_bytes", 1, 0xFF),
    ):
        if not _bounded_int(runtime[key], minimum, maximum):
            raise ValueError(f"font transfer {key} is invalid")

    before = value["candidate_page_count_before"]
    after = value["candidate_page_count_after"]
    bank_before = value["candidate_bank_count_before"]
    observed = value["observed_candidate_bank_count"]
    if (
        not _bounded_int(before, 1, 244)
        or not _bounded_int(after, 1, before)
        or not _bounded_int(bank_before, 1, 61)
        or not _bounded_int(observed, 0, bank_before)
        or not _bounded_int(value["mapper_write_count"], 0, 0x100000)
        or not _bounded_int(
            value["candidate_font_read_count"], 0, 0x100000
        )
        or not _bounded_int(value["ram_buffer_link_count"], 0, 0x100000)
    ):
        raise ValueError("font transfer counts are invalid")
    confirmed = after == 1 and observed > 0
    expected_status = (
        "font-transfer-source-confirmed"
        if confirmed
        else "font-transfer-bank-narrowed"
        if observed > 0 and after < before
        else "font-transfer-bank-observed-without-narrowing"
        if observed > 0
        else "font-transfer-source-not-yet-observed"
    )
    expected_checkpoint = (
        "extract-full-script-record-set"
        if confirmed
        else "trace-font-transfer-buffer-producer"
        if observed > 0
        else "extend-font-transfer-trace-window"
    )
    if (
        value["status"] != expected_status
        or value["font_transfer_source_confirmed"] is not confirmed
        or value["next_checkpoint"] != expected_checkpoint
    ):
        raise ValueError("font transfer result is inconsistent")
    if value["local_payload_policy"] != (
        "pages-banks-addresses-opcodes-registers-and-trace-local-only"
    ):
        raise ValueError("font transfer local policy is invalid")
    if value["translation_build_eligible"] is not False:
        raise ValueError("font transfer source cannot enable release builds")


def _existing_capture_is_current(
    path: Path,
    *,
    target_sha256: str,
    source_mapping_sha256: str,
    source_renderer_trace_sha256: str,
    source_initial_trace_sha256: str,
) -> bool:
    if not path.is_file():
        return False
    try:
        value = _load_json_object(path)
        validate_font_transfer_source(value)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        value["target_sha256"] == target_sha256
        and value["source_mapping_sha256"] == source_mapping_sha256
        and value["source_renderer_trace_sha256"]
        == source_renderer_trace_sha256
        and value["source_initial_trace_sha256"] == source_initial_trace_sha256
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    args = parser.parse_args()
    rom_path = args.rom if args.rom.is_absolute() else root / args.rom
    mapping_path = root / MAPPING_PATH
    local_mapping_path = root / LOCAL_MAPPING_PATH
    renderer_path = root / RENDERER_TRACE_PATH
    local_renderer_path = root / LOCAL_RENDERER_PATH
    initial_path = root / INITIAL_TRACE_PATH
    publish_path = root / PUBLISH_RELATIVE_PATH
    prerequisites = (
        rom_path,
        mapping_path,
        local_mapping_path,
        renderer_path,
        local_renderer_path,
        initial_path,
    )
    if not all(path.is_file() for path in prerequisites):
        if args.if_ready:
            print("Font transfer source trace is not ready")
            return 0
        raise SystemExit("font transfer source input is missing")

    mapping = _load_json_object(mapping_path)
    validate_visible_unicode_mapping(mapping)
    renderer = _load_json_object(renderer_path)
    validate_renderer_output_trace(renderer)
    initial = _load_json_object(initial_path)
    validate_initial_font_page_trace(initial)
    target_sha256 = sha256_file(rom_path)
    if (
        mapping["target_sha256"] != target_sha256
        or renderer["target_sha256"] != target_sha256
        or initial["target_sha256"] != target_sha256
        or not runtime_entry_matches(
            renderer["runtime_entry"], mapping["runtime_entry"]
        )
        or initial["runtime_entry"] != mapping["runtime_entry"]
        or renderer["consumer_chain_confirmed"] is not True
        or initial["next_checkpoint"] != "trace-font-transfer-source"
    ):
        if args.if_ready and initial["runtime_initial_page_confirmed"] is True:
            print("Font transfer source trace is no longer required")
            return 0
        raise ValueError("font transfer source identities disagree")

    source_mapping_sha256 = sha256_file(mapping_path)
    source_renderer_sha256 = sha256_file(renderer_path)
    source_initial_sha256 = sha256_file(initial_path)
    if _existing_capture_is_current(
        publish_path,
        target_sha256=target_sha256,
        source_mapping_sha256=source_mapping_sha256,
        source_renderer_trace_sha256=source_renderer_sha256,
        source_initial_trace_sha256=source_initial_sha256,
    ):
        print("Font transfer source trace is already current")
        return 0

    local_mapping = _load_json_object(local_mapping_path)
    raw_candidates = local_mapping.get("mapping", {}).get(
        "initial_page_candidates"
    )
    if not isinstance(raw_candidates, list):
        raise ValueError("local font transfer candidates are missing")
    candidate_pages = sorted(
        int(item["page"])
        for item in raw_candidates
        if isinstance(item, dict) and isinstance(item.get("page"), int)
    )
    mapping_counts = mapping["mapping"]
    assert isinstance(mapping_counts, dict)
    if (
        len(candidate_pages)
        != int(mapping_counts["initial_page_candidate_count"])
        or len(candidate_pages)
        != int(initial["candidate_page_count_before"])
    ):
        raise ValueError("font transfer candidate counts disagree")

    local_renderer = _load_json_object(local_renderer_path)
    if local_renderer.get("target_sha256") != target_sha256:
        raise ValueError("local font transfer renderer identity disagrees")
    ready_state = local_renderer.get("ready_state")
    trace_analysis = local_renderer.get("trace_analysis")
    if not isinstance(ready_state, dict) or not isinstance(
        trace_analysis, dict
    ):
        raise ValueError("local font transfer renderer state is missing")
    lines = trace_analysis.get("raw_trace_lines")
    if not isinstance(lines, list) or not all(
        isinstance(line, str) for line in lines
    ):
        raise ValueError("local font transfer trace lines are invalid")

    safe_counts, local_analysis = analyze_font_transfer_trace(
        lines=lines,
        candidate_pages=candidate_pages,
        initial_slot1_bank=_coerce_int(
            ready_state.get("slot1_bank"), "ready slot1 bank"
        ),
        initial_slot2_bank=_coerce_int(
            ready_state.get("slot2_bank"), "ready slot2 bank"
        ),
    )
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    runtime = mapping["runtime_entry"]
    assert isinstance(runtime, dict)
    safe = build_font_transfer_source(
        target_sha256=target_sha256,
        source_mapping_sha256=source_mapping_sha256,
        source_renderer_trace_sha256=source_renderer_sha256,
        source_initial_trace_sha256=source_initial_sha256,
        runtime_entry=runtime,
        analysis=safe_counts,
        captured_utc=captured_utc,
    )
    local = {
        "artifact_kind": "local-s25u-font-transfer-source",
        "schema_version": 1,
        "target_sha256": target_sha256,
        "captured_utc": captured_utc,
        "runtime_entry": runtime,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-pages-banks-addresses-opcodes-registers-or-trace"
        ),
    }
    publish_path.parent.mkdir(parents=True, exist_ok=True)
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    publish_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR font transfer source: {publish_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
