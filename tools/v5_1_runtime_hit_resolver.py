#!/usr/bin/env python3
"""Resolve a Gearsystem read hit to a v5.1 pointer entry and bounded decode."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

try:
    from .patch_io import PatchError, sha256_file
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from .v5_1_consumer import mapper_file_offset, verify_target_identity
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from .v5_1_safe_observation import _git, _normalized_remote
except ImportError:  # direct script execution
    from patch_io import PatchError, sha256_file
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        decode_symbols,
        encode_symbols,
        load_trees_at,
    )
    from v5_1_consumer import mapper_file_offset, verify_target_identity
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
    from v5_1_safe_observation import _git, _normalized_remote

ARTIFACT_KIND = "sanitized-runtime-consumer-resolution"
SCHEMA_VERSION = 2
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_consumer_resolution.json"
)
LOCAL_REPORT = Path("reports/local/v5_1_gearsystem_probe.json")
DEFAULT_ROM = Path("build/Final_Conflict_Korean_v5.1.gg")
DEFAULT_TRACE_PLAN = Path("reports/v5_1_emucap_trace_plan.json")
EXPECTED_REMOTE = "github.com/Domingo8666/ShiningForceKR"
DEFAULT_GIT_NAME = "Domingo8666"
DEFAULT_GIT_EMAIL = "145947995+Domingo8666@users.noreply.github.com"

TRACE_PREFIX = re.compile(
    r"^(?P<bank>[0-9A-Fa-f]{2}):(?P<pc>[0-9A-Fa-f]{4})"
    r"\s+A:(?P<a>[0-9A-Fa-f]{2})"
    r"\s+BC:(?P<bc>[0-9A-Fa-f]{4})"
    r"\s+DE:(?P<de>[0-9A-Fa-f]{4})"
    r"\s+HL:(?P<hl>[0-9A-Fa-f]{4})"
    r"\s+SP:(?P<sp>[0-9A-Fa-f]{4})"
)
OPCODE_SUFFIX = re.compile(
    r"\s{2,}(?P<opcodes>[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)\s*$"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "target_sha256",
    "status",
    "hit",
    "alignment_resolutions",
    "target_read",
    "selected_alignment_format",
    "selected_entry_index",
    "consumer_evidence_confirmed",
    "translation_build_eligible",
    "next_checkpoint",
}
HIT_KEYS = {
    "slot",
    "logical_access",
    "physical_table_byte",
    "instruction_bank",
    "instruction_pc",
    "pc_after",
    "physical_pc_after",
    "expected_bank",
    "mapped_bank",
}
ALIGNMENT_KEYS = {
    "format",
    "alignment_file_offset",
    "entry_index",
    "entry_byte_index",
    "target_file_offset",
    "bounded_decode",
    "symbol_count",
    "roundtrip_exact",
    "encoded_bits",
}
TARGET_READ_KEYS = {
    "slot",
    "logical_access",
    "physical_target_byte",
    "instruction_bank",
    "instruction_pc",
    "pc_after",
    "physical_pc_after",
    "expected_bank",
    "mapped_bank",
}


def _parse_trace_line(line: str) -> dict[str, object] | None:
    prefix = TRACE_PREFIX.search(line)
    suffix = OPCODE_SUFFIX.search(line)
    if prefix is None or suffix is None:
        return None
    try:
        opcodes = bytes(
            int(token, 16) for token in suffix.group("opcodes").split()
        )
    except ValueError:
        return None
    return {
        "bank": int(prefix.group("bank"), 16),
        "pc": int(prefix.group("pc"), 16),
        "opcodes": opcodes,
        "registers": {
            key: int(prefix.group(key), 16)
            for key in ("a", "bc", "de", "hl", "sp")
        },
    }


def _signed_byte(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _read_addresses(
    opcodes: bytes, registers: dict[str, int]
) -> list[int]:
    """Return logical data-read addresses for common Z80 read forms.

    This is intentionally not advertised as an ISA-complete decoder. Unknown
    forms return an empty list and keep the promotion gate closed.
    """

    if not opcodes:
        return []
    first = opcodes[0]
    hl = registers.get("hl", 0) & 0xFFFF
    if first == 0x0A:
        return [registers.get("bc", 0) & 0xFFFF]
    if first == 0x1A:
        return [registers.get("de", 0) & 0xFFFF]
    if first == 0x3A and len(opcodes) >= 3:
        return [opcodes[1] | (opcodes[2] << 8)]
    if first == 0x2A and len(opcodes) >= 3:
        address = opcodes[1] | (opcodes[2] << 8)
        return [address, (address + 1) & 0xFFFF]
    if first in {
        0x34,
        0x35,
        0x46,
        0x4E,
        0x56,
        0x5E,
        0x66,
        0x6E,
        0x7E,
        0x86,
        0x8E,
        0x96,
        0x9E,
        0xA6,
        0xAE,
        0xB6,
        0xBE,
    }:
        return [hl]
    if first == 0xCB and len(opcodes) >= 2 and opcodes[1] & 0x07 == 0x06:
        return [hl]
    if first in (0xDD, 0xFD) and len(opcodes) >= 3:
        base = (
            registers.get("ix", 0)
            if first == 0xDD
            else registers.get("iy", 0)
        )
        second = opcodes[1]
        if second == 0xCB and len(opcodes) >= 4:
            return [(base + _signed_byte(opcodes[2])) & 0xFFFF]
        if second in {
            0x34,
            0x35,
            0x46,
            0x4E,
            0x56,
            0x5E,
            0x66,
            0x6E,
            0x7E,
            0x86,
            0x8E,
            0x96,
            0x9E,
            0xA6,
            0xAE,
            0xB6,
            0xBE,
        }:
            return [(base + _signed_byte(opcodes[2])) & 0xFFFF]
    if first == 0xED and len(opcodes) >= 2:
        second = opcodes[1]
        if second in (0x4B, 0x5B, 0x6B, 0x7B) and len(opcodes) >= 4:
            address = opcodes[2] | (opcodes[3] << 8)
            return [address, (address + 1) & 0xFFFF]
        if second in (0xA0, 0xA1, 0xB0, 0xB1):
            return [(hl - 1) & 0xFFFF]
        if second in (0xA8, 0xA9, 0xB8, 0xB9):
            return [(hl + 1) & 0xFFFF]
    return []


def _read_operand_kind(opcodes: bytes) -> str:
    """Describe a supported ROM-read operand without publishing opcodes."""

    if not opcodes:
        return "unknown"
    first = opcodes[0]
    if first == 0x0A:
        return "bc-indirect"
    if first == 0x1A:
        return "de-indirect"
    if first == 0x3A and len(opcodes) >= 3:
        return "absolute-byte"
    if first == 0x2A and len(opcodes) >= 3:
        return "absolute-word"
    if first in {
        0x34,
        0x35,
        0x46,
        0x4E,
        0x56,
        0x5E,
        0x66,
        0x6E,
        0x7E,
        0x86,
        0x8E,
        0x96,
        0x9E,
        0xA6,
        0xAE,
        0xB6,
        0xBE,
    }:
        return "hl-indirect"
    if first == 0xCB and len(opcodes) >= 2 and opcodes[1] & 0x07 == 0x06:
        return "hl-bit"
    if first in (0xDD, 0xFD) and len(opcodes) >= 3:
        second = opcodes[1]
        if second == 0xCB and len(opcodes) >= 4:
            return "ix-indexed-bit" if first == 0xDD else "iy-indexed-bit"
        if second in {
            0x34,
            0x35,
            0x46,
            0x4E,
            0x56,
            0x5E,
            0x66,
            0x6E,
            0x7E,
            0x86,
            0x8E,
            0x96,
            0x9E,
            0xA6,
            0xAE,
            0xB6,
            0xBE,
        }:
            return "ix-indexed" if first == 0xDD else "iy-indexed"
    if first == 0xED and len(opcodes) >= 2:
        second = opcodes[1]
        if second in (0x4B, 0x5B, 0x6B, 0x7B) and len(opcodes) >= 4:
            return "absolute-word"
        if second in (0xA0, 0xA1, 0xB0, 0xB1):
            return "block-forward"
        if second in (0xA8, 0xA9, 0xB8, 0xB9):
            return "block-backward"
    return "unknown"


def _actual_slot_bank(hit: dict[str, object]) -> int:
    slot = int(hit["slot"])
    return int(hit[f"slot{slot}_bank"])


def _candidate_access_is_valid(
    pointer_address: int,
    pointer_bank: int,
    target_slot: int,
    logical_access: int,
    mapped_bank: int,
) -> bool:
    return (
        target_slot in {1, 2}
        and pointer_address // 0x4000 == target_slot
        and pointer_address == logical_access
        and pointer_bank == mapped_bank
    )


def _find_access(
    attempt: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], int] | None:
    hit = attempt.get("hit")
    evidence = attempt.get("evidence")
    if not isinstance(hit, dict) or not isinstance(evidence, dict):
        return None
    trace = evidence.get("trace")
    z80 = evidence.get("z80")
    if not isinstance(trace, dict) or not isinstance(z80, dict):
        return None
    lines = trace.get("lines")
    if not isinstance(lines, list):
        return None
    logical_start = int(hit["logical_start"])
    logical_end = int(hit["logical_end"])
    for line in reversed(lines):
        if not isinstance(line, str):
            continue
        parsed = _parse_trace_line(line)
        if parsed is None:
            continue
        registers = parsed["registers"]
        assert isinstance(registers, dict)
        for name in ("IX", "IY"):
            value = z80.get(name)
            if isinstance(value, str):
                registers[name.lower()] = int(value, 16)
        for address in _read_addresses(parsed["opcodes"], registers):
            if logical_start <= address <= logical_end:
                return hit, parsed, address
    return None


def _alignment_pointer(
    rom: bytes,
    item: dict[str, object],
    physical_table_byte: int,
) -> dict[str, object] | None:
    start = int(item["file_offset"])
    end = int(item["end_exclusive"])
    entries = int(item["entries"])
    format_name = str(item["format"])
    if not start <= physical_table_byte < end:
        return None
    relative = physical_table_byte - start
    entry_index = relative // 3
    entry_byte_index = relative % 3
    if not 0 <= entry_index < entries:
        return None
    at = start + entry_index * 3
    if at + 3 > len(rom):
        return None
    first, second, third = rom[at : at + 3]
    if format_name == "addr_le_bank":
        address = first | (second << 8)
        bank = third
    elif format_name == "bank_addr_le":
        bank = first
        address = second | (third << 8)
    else:
        return None
    target = mapper_file_offset(bank, address, len(rom))
    return {
        "format": format_name,
        "alignment_file_offset": start,
        "entry_index": entry_index,
        "entry_byte_index": entry_byte_index,
        "pointer_bank": bank,
        "pointer_address": address,
        "target_slot": address // 0x4000 if 0x4000 <= address < 0xC000 else None,
        "target_file_offset": target,
    }


def _alignment_resolutions(
    rom: bytes,
    plan: dict[str, object],
    physical_table_byte: int,
    trees: dict[int, object],
) -> list[dict[str, object]]:
    cluster = plan.get("selected_alignment_cluster")
    if not isinstance(cluster, list):
        raise ValueError("trace plan has no alignment cluster")
    known = bytes((1,)) * len(rom)
    output: list[dict[str, object]] = []
    for item in cluster:
        if not isinstance(item, dict):
            continue
        pointer = _alignment_pointer(rom, item, physical_table_byte)
        if pointer is None:
            continue
        target = pointer["target_file_offset"]
        bounded = False
        symbol_count: int | None = None
        roundtrip_exact = False
        encoded_bits: int | None = None
        if target is not None:
            try:
                symbols, decoded_bits = decode_symbols(
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
                pass
            else:
                bounded = True
                symbol_count = len(symbols)
                try:
                    encoded, encoded_bits = encode_symbols(
                        trees,
                        symbols,
                        initial_symbol=CANDIDATE_END_SYMBOL,
                        end_symbol=CANDIDATE_END_SYMBOL,
                        max_bits=256 * 8,
                    )
                except PatchError:
                    encoded_bits = None
                else:
                    if encoded_bits == decoded_bits:
                        roundtrip_exact = all(
                            (
                                (rom[target + (bit >> 3)] >> (7 - (bit & 7)))
                                & 1
                            )
                            == (
                                (encoded[bit >> 3] >> (7 - (bit & 7))) & 1
                            )
                            for bit in range(encoded_bits)
                        )
        output.append(
            {
                "format": pointer["format"],
                "alignment_file_offset": pointer["alignment_file_offset"],
                "entry_index": pointer["entry_index"],
                "entry_byte_index": pointer["entry_byte_index"],
                "target_file_offset": target,
                "bounded_decode": bounded,
                "symbol_count": symbol_count,
                "roundtrip_exact": roundtrip_exact,
                "encoded_bits": encoded_bits,
            }
        )
    return output


def _require_int(
    value: object, label: str, minimum: int = 0, maximum: int | None = None
) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} must be <= {maximum}")


def validate_consumer_resolution(resolution: dict[str, object]) -> None:
    if set(resolution) != TOP_LEVEL_KEYS:
        raise ValueError("consumer resolution top-level fields do not match")
    if resolution["artifact_kind"] != ARTIFACT_KIND:
        raise ValueError("unexpected consumer resolution artifact")
    if resolution["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected consumer resolution schema")
    sha = resolution["target_sha256"]
    if not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{64}", sha) is None:
        raise ValueError("target_sha256 must be a lowercase SHA-256")
    if resolution["status"] not in {
        "consumer-entry-resolved",
        "runtime-hit-entry-ambiguous",
    }:
        raise ValueError("unexpected consumer resolution status")
    hit = resolution["hit"]
    if not isinstance(hit, dict) or set(hit) != HIT_KEYS:
        raise ValueError("resolved hit fields do not match")
    for key, value in hit.items():
        maximum = 0xFFFFFF if key in {
            "physical_table_byte",
            "physical_pc_after",
        } else 0xFFFF
        if key in {"slot", "instruction_bank", "expected_bank", "mapped_bank"}:
            maximum = 255
        _require_int(value, key, 0, maximum)
    alignments = resolution["alignment_resolutions"]
    if not isinstance(alignments, list) or not 1 <= len(alignments) <= 6:
        raise ValueError("alignment_resolutions must contain 1..6 items")
    for item in alignments:
        if not isinstance(item, dict) or set(item) != ALIGNMENT_KEYS:
            raise ValueError("alignment resolution fields do not match")
        if item["format"] not in {"addr_le_bank", "bank_addr_le"}:
            raise ValueError("unexpected alignment format")
        for key in (
            "alignment_file_offset",
            "entry_index",
            "entry_byte_index",
        ):
            _require_int(item[key], key)
        if item["target_file_offset"] is not None:
            _require_int(item["target_file_offset"], "target_file_offset")
        if not isinstance(item["bounded_decode"], bool):
            raise ValueError("bounded_decode must be boolean")
        if item["symbol_count"] is not None:
            _require_int(item["symbol_count"], "symbol_count")
        if not isinstance(item["roundtrip_exact"], bool):
            raise ValueError("roundtrip_exact must be boolean")
        if item["encoded_bits"] is not None:
            _require_int(item["encoded_bits"], "encoded_bits")
        if item["bounded_decode"] != (item["symbol_count"] is not None):
            raise ValueError("bounded_decode and symbol_count disagree")
        if item["roundtrip_exact"] and (
            not item["bounded_decode"] or item["encoded_bits"] is None
        ):
            raise ValueError("exact roundtrip requires bounded decode and bits")
    target_read = resolution["target_read"]
    if target_read is not None:
        if not isinstance(target_read, dict) or set(target_read) != TARGET_READ_KEYS:
            raise ValueError("target read fields do not match")
        for key, value in target_read.items():
            maximum = 0xFFFFFF if key in {
                "physical_target_byte",
                "physical_pc_after",
            } else 0xFFFF
            if key in {
                "slot",
                "instruction_bank",
                "expected_bank",
                "mapped_bank",
            }:
                maximum = 255
            _require_int(value, key, 0, maximum)
        if target_read["slot"] not in {1, 2}:
            raise ValueError("target read must use a banked ROM slot")
        if target_read["logical_access"] // 0x4000 != target_read["slot"]:
            raise ValueError("target read logical address and slot disagree")
        expected_physical = (
            target_read["expected_bank"] * 0x4000
            + (target_read["logical_access"] & 0x3FFF)
        )
        if target_read["physical_target_byte"] != expected_physical:
            raise ValueError("target read physical address and mapper bank disagree")
    confirmed = resolution["consumer_evidence_confirmed"]
    if not isinstance(confirmed, bool):
        raise ValueError("consumer_evidence_confirmed must be boolean")
    if resolution["translation_build_eligible"] is not False:
        raise ValueError("entry resolution cannot enable translation builds")
    selected_format = resolution["selected_alignment_format"]
    selected_index = resolution["selected_entry_index"]
    if confirmed:
        if selected_format not in {"addr_le_bank", "bank_addr_le"}:
            raise ValueError("confirmed resolution requires a selected format")
        _require_int(selected_index, "selected_entry_index")
        if resolution["status"] != "consumer-entry-resolved":
            raise ValueError("confirmed resolution status mismatch")
        if target_read is None:
            raise ValueError("confirmed resolution requires a target read")
        if target_read["expected_bank"] != target_read["mapped_bank"]:
            raise ValueError("confirmed target read mapper bank mismatch")
    else:
        if selected_format is not None or selected_index is not None:
            raise ValueError("ambiguous resolution cannot select an entry")
        if resolution["status"] != "runtime-hit-entry-ambiguous":
            raise ValueError("ambiguous resolution status mismatch")
    checkpoint = resolution["next_checkpoint"]
    if (
        not isinstance(checkpoint, str)
        or re.fullmatch(r"[a-z0-9-]{1,80}", checkpoint) is None
    ):
        raise ValueError("next_checkpoint must be a short safe token")


def build_consumer_resolution(
    *,
    target_sha256: str,
    plan: dict[str, object],
    hit: dict[str, object],
    trace_record: dict[str, object],
    logical_access: int,
    alignments: list[dict[str, object]],
    target_followup: dict[str, object] | None = None,
) -> dict[str, object]:
    watch = plan.get("selected_watch")
    if not isinstance(watch, dict):
        raise ValueError("trace plan has no selected watch")
    mapping_start = int(hit["logical_start"])
    file_start = int(watch["file_start"])
    physical_table_byte = file_start + logical_access - mapping_start
    selected_resolution: dict[str, object] | None = None
    safe_target_read: dict[str, int] | None = None
    if isinstance(target_followup, dict):
        candidate = target_followup.get("matching_candidate")
        target_hit = target_followup.get("hit")
        target_trace = target_followup.get("trace_record")
        target_access = target_followup.get("logical_access")
        if (
            isinstance(candidate, dict)
            and isinstance(target_hit, dict)
            and isinstance(target_trace, dict)
            and isinstance(target_access, int)
        ):
            try:
                candidate_format = str(candidate["format"])
                candidate_start = int(candidate["alignment_file_offset"])
                candidate_index = int(candidate["entry_index"])
                candidate_address = int(candidate["pointer_address"])
                candidate_bank = int(candidate["pointer_bank"])
                candidate_slot = int(candidate["target_slot"])
                candidate_target = int(candidate["target_file_offset"])
                target_mapped_bank = int(target_hit[f"slot{candidate_slot}_bank"])
                target_instruction_bank = int(target_trace["bank"])
                target_instruction_pc = int(target_trace["pc"])
                target_pc_after = int(target_hit["pc_after"])
                target_physical_pc_after = int(target_hit["physical_pc_after"])
            except (KeyError, TypeError, ValueError):
                pass
            else:
                selected_resolution = next(
                    (
                        item
                        for item in alignments
                        if item["format"] == candidate_format
                        and item["alignment_file_offset"] == candidate_start
                        and item["entry_index"] == candidate_index
                        and item["target_file_offset"] == candidate_target
                    ),
                    None,
                )
                if (
                    selected_resolution is not None
                    and candidate_slot in {1, 2}
                    and _candidate_access_is_valid(
                        candidate_address,
                        candidate_bank,
                        candidate_slot,
                        target_access,
                        target_mapped_bank,
                    )
                ):
                    safe_target_read = {
                        "slot": candidate_slot,
                        "logical_access": target_access,
                        "physical_target_byte": candidate_target,
                        "instruction_bank": target_instruction_bank,
                        "instruction_pc": target_instruction_pc,
                        "pc_after": target_pc_after,
                        "physical_pc_after": target_physical_pc_after,
                        "expected_bank": candidate_bank,
                        "mapped_bank": target_mapped_bank,
                    }
                else:
                    selected_resolution = None
    mapped_bank = _actual_slot_bank(hit)
    confirmed = bool(
        selected_resolution
        and selected_resolution["bounded_decode"]
        and mapped_bank == int(hit["expected_bank"])
        and safe_target_read is not None
    )
    roundtrip_exact = bool(
        selected_resolution
        and selected_resolution["roundtrip_exact"]
    )
    safe_hit = {
        "slot": int(hit["slot"]),
        "logical_access": logical_access,
        "physical_table_byte": physical_table_byte,
        "instruction_bank": int(trace_record["bank"]),
        "instruction_pc": int(trace_record["pc"]),
        "pc_after": int(hit["pc_after"]),
        "physical_pc_after": int(hit["physical_pc_after"]),
        "expected_bank": int(hit["expected_bank"]),
        "mapped_bank": mapped_bank,
    }
    resolution: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "target_sha256": target_sha256,
        "status": (
            "consumer-entry-resolved"
            if confirmed
            else "runtime-hit-entry-ambiguous"
        ),
        "hit": safe_hit,
        "alignment_resolutions": alignments,
        "target_read": safe_target_read,
        "selected_alignment_format": (
            str(selected_resolution["format"])
            if confirmed and selected_resolution is not None
            else None
        ),
        "selected_entry_index": (
            int(selected_resolution["entry_index"])
            if confirmed and selected_resolution is not None
            else None
        ),
        "consumer_evidence_confirmed": confirmed,
        "translation_build_eligible": False,
        "next_checkpoint": (
            "identify-intro-line-and-build-test-translation"
            if confirmed and roundtrip_exact
            else "repair-selected-entry-roundtrip"
            if confirmed
            else "collect-additional-runtime-read-hits"
        ),
    }
    validate_consumer_resolution(resolution)
    return resolution


def write_consumer_resolution(
    root: Path, resolution: dict[str, object]
) -> Path:
    validate_consumer_resolution(resolution)
    path = root.resolve() / PUBLISH_RELATIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(resolution, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def publish_consumer_resolution(
    root: Path, path: Path
) -> dict[str, object]:
    root = root.resolve()
    expected = root / PUBLISH_RELATIVE_PATH
    if path.resolve() != expected:
        raise ValueError(f"consumer resolution path must be {expected}")
    resolution = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(resolution, dict):
        raise ValueError("consumer resolution must be a JSON object")
    validate_consumer_resolution(resolution)
    top = Path(_git(root, "rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top != root:
        raise ValueError("repository root mismatch")
    if _git(root, "branch", "--show-current").stdout.strip() != "main":
        raise ValueError("consumer resolution may only be published from main")
    remote = _normalized_remote(_git(root, "remote", "get-url", "origin").stdout)
    if EXPECTED_REMOTE not in remote:
        raise ValueError("origin is not the canonical repository")
    relative = str(PUBLISH_RELATIVE_PATH).replace("\\", "/")
    porcelain = _git(root, "status", "--porcelain").stdout.splitlines()
    unrelated = [
        line
        for line in porcelain
        if line[3:].replace("\\", "/") != relative
    ]
    if unrelated:
        raise ValueError("refusing to publish with unrelated working tree changes")
    changed = any(
        line[3:].replace("\\", "/") == relative for line in porcelain
    )
    if changed:
        if not _git(root, "config", "user.name").stdout.strip():
            _git(root, "config", "user.name", DEFAULT_GIT_NAME)
        if not _git(root, "config", "user.email").stdout.strip():
            _git(root, "config", "user.email", DEFAULT_GIT_EMAIL)
        _git(root, "add", "--", relative)
        _git(
            root,
            "commit",
            "-m",
            "Resolve sanitized S25U consumer hit",
            "--",
            relative,
        )
    _git(root, "push", "origin", "HEAD:main")
    return {
        "changed": changed,
        "commit": _git(root, "rev-parse", "HEAD").stdout.strip(),
        "path": relative,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--trace-plan", type=Path, default=DEFAULT_TRACE_PLAN)
    parser.add_argument("--local-report", type=Path, default=LOCAL_REPORT)
    parser.add_argument("--publish-safe-resolution", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]

    def absolute(path: Path) -> Path:
        return path if path.is_absolute() else (root / path).resolve()

    rom_path = absolute(args.rom)
    plan_path = absolute(args.trace_plan)
    report_path = absolute(args.local_report)
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(plan, dict) or not isinstance(report, dict):
        raise ValueError("trace plan and local report must be JSON objects")
    if plan.get("source_analysis_sha256") != target_sha256:
        raise ValueError("trace plan identity does not match the local ROM")
    attempts = report.get("attempts")
    if not isinstance(attempts, list):
        raise ValueError("local runtime report has no attempts")
    found_record = next(
        (
            (attempt, access)
            for attempt in attempts
            if isinstance(attempt, dict)
            for access in [_find_access(attempt)]
            if access is not None
        ),
        None,
    )
    if found_record is None:
        print("No resolvable runtime read hit; safe resolution was not written.")
        return 0
    attempt, found = found_record
    hit, trace_record, logical_access = found
    watch = attempt.get("watch")
    cluster = attempt.get("alignment_cluster")
    if not isinstance(watch, dict):
        watch = plan.get("selected_watch")
    if not isinstance(cluster, list):
        cluster = plan.get("selected_alignment_cluster")
    if not isinstance(watch, dict) or not isinstance(cluster, list):
        raise ValueError("runtime attempt has no candidate watch context")
    candidate_plan = {
        "selected_watch": watch,
        "selected_alignment_cluster": cluster,
    }
    physical_table_byte = (
        int(watch["file_start"])
        + logical_access
        - int(hit["logical_start"])
    )
    known = bytes((1,)) * len(rom)
    trees = load_trees_at(
        rom,
        known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    alignments = _alignment_resolutions(
        rom, candidate_plan, physical_table_byte, trees
    )
    if not alignments:
        raise ValueError("runtime access did not resolve to an alignment entry")
    resolution = build_consumer_resolution(
        target_sha256=target_sha256,
        plan=candidate_plan,
        hit=hit,
        trace_record=trace_record,
        logical_access=logical_access,
        alignments=alignments,
        target_followup=(
            attempt.get("target_followup")
            if isinstance(attempt.get("target_followup"), dict)
            else None
        ),
    )
    path = write_consumer_resolution(root, resolution)
    print(
        "SFKR consumer resolution: "
        f"{resolution['status']} access=0x{logical_access:04X}"
    )
    if args.publish_safe_resolution:
        result = publish_consumer_resolution(root, path)
        print(f"Published consumer resolution: {result['path']} @ {result['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
