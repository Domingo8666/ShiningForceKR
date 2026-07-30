#!/usr/bin/env python3
"""Resolve one Final Conflict indexed string inside a continuous Huffman group."""

from __future__ import annotations

try:
    from .patch_io import PatchError
    from .sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        ParsedTree,
        decode_symbol_entries,
        encode_symbol_entries,
        load_trees_at,
    )
    from .v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )
except ImportError:  # direct script execution
    from patch_io import PatchError
    from sfgfc_huffman import (
        CANDIDATE_END_SYMBOL,
        ParsedTree,
        decode_symbol_entries,
        encode_symbol_entries,
        load_trees_at,
    )
    from v5_1_engine import (
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
        KO_VECTOR_OFFSET,
    )


LOOKUP_TABLE_BASE = 0x3FE8
LOOKUP_TABLE_END = 0x4000
SLOT_1_BASE = 0x4000
SLOT_1_END = 0x8000


def _bits_equal(
    left: bytes,
    right: bytes,
    bits: int,
) -> bool:
    return all(
        ((left[index >> 3] >> (7 - (index & 7))) & 1)
        == ((right[index >> 3] >> (7 - (index & 7))) & 1)
        for index in range(bits)
    )


def resolve_group_entry_with_trees(
    data: bytes,
    known: bytes,
    trees: dict[int, ParsedTree],
    *,
    group_physical_start: int,
    group_pointer_address: int,
    entry_ordinal: int,
    target_logical_byte: int,
) -> dict[str, object]:
    """Compare the observed B register with entries in one Huffman group.

    The patched routine increments B, but the surrounding source-ROM code is
    not yet statically available. Decode B+1 terminator-delimited strings while
    preserving the shared bit cursor, then independently locate every decoded
    entry whose byte range overlaps the confirmed runtime target read. This
    keeps the observed register value separate from its still-unproven meaning.
    """

    if not 0 <= entry_ordinal <= 0xFF:
        raise PatchError("script group entry ordinal is out of range")
    if not SLOT_1_BASE <= group_pointer_address < SLOT_1_END:
        raise PatchError("script group pointer is outside slot 1")
    if not SLOT_1_BASE <= target_logical_byte < SLOT_1_END:
        raise PatchError("script target byte is outside slot 1")
    if not 0 <= group_physical_start < len(data):
        raise PatchError("script group physical start is outside the ROM")

    prefix_entries, prefix_bits = decode_symbol_entries(
        data,
        known,
        trees,
        group_physical_start,
        entry_ordinal + 1,
        initial_symbol=CANDIDATE_END_SYMBOL,
        end_symbol=CANDIDATE_END_SYMBOL,
        max_symbols_per_entry=4096,
        max_total_bytes=SLOT_1_END - group_pointer_address,
    )
    encoded_prefix, encoded_prefix_bits = encode_symbol_entries(
        trees,
        prefix_entries,
        initial_symbol=CANDIDATE_END_SYMBOL,
        end_symbol=CANDIDATE_END_SYMBOL,
        max_bits=(SLOT_1_END - group_pointer_address) * 8,
    )
    if (
        encoded_prefix_bits != prefix_bits
        or not _bits_equal(
            data[group_physical_start:],
            encoded_prefix,
            prefix_bits,
        )
    ):
        raise PatchError("script group prefix no-change roundtrip is not exact")

    entry_ranges: list[dict[str, int]] = []
    consumed_bits = 0
    for ordinal, symbols in enumerate(prefix_entries):
        _, encoded_bits = encode_symbol_entries(
            trees,
            [symbols],
            initial_symbol=CANDIDATE_END_SYMBOL,
            end_symbol=CANDIDATE_END_SYMBOL,
            max_bits=prefix_bits,
        )
        start_bit = consumed_bits
        end_bit = start_bit + encoded_bits
        start_byte = group_pointer_address + start_bit // 8
        end_byte = group_pointer_address + (end_bit - 1) // 8
        entry_ranges.append(
            {
                "entry_ordinal": ordinal,
                "entry_start_bit": start_bit,
                "entry_end_bit_exclusive": end_bit,
                "entry_encoded_bits": encoded_bits,
                "entry_symbol_count": len(symbols),
                "entry_start_logical_byte": start_byte,
                "entry_end_logical_byte_inclusive": end_byte,
            }
        )
        consumed_bits = end_bit
    if consumed_bits != prefix_bits:
        raise PatchError("script group entry bit ranges do not cover the prefix")

    selected_range = entry_ranges[-1]
    selected_bits = selected_range["entry_encoded_bits"]
    entry_start_bit = selected_range["entry_start_bit"]
    entry_end_bit = selected_range["entry_end_bit_exclusive"]
    entry_start_byte = group_pointer_address + entry_start_bit // 8
    entry_end_byte = group_pointer_address + (entry_end_bit - 1) // 8
    if entry_end_byte >= SLOT_1_END:
        raise PatchError("selected script group entry crosses the slot boundary")
    target_byte_candidates = [
        item
        for item in entry_ranges
        if item["entry_start_logical_byte"]
        <= target_logical_byte
        <= item["entry_end_logical_byte_inclusive"]
    ]
    candidate_ordinals = {
        item["entry_ordinal"] for item in target_byte_candidates
    }
    observed_b_matches_target_candidates = entry_ordinal in candidate_ordinals

    return {
        "status": (
            "resolved"
            if entry_start_byte <= target_logical_byte <= entry_end_byte
            else "target-outside-selected-entry"
        ),
        "entry_ordinal": entry_ordinal,
        "decoded_prefix_entry_count": entry_ordinal + 1,
        "group_pointer_address": group_pointer_address,
        "entry_start_bit": entry_start_bit,
        "entry_end_bit_exclusive": entry_end_bit,
        "entry_encoded_bits": selected_bits,
        "entry_symbol_count": selected_range["entry_symbol_count"],
        "entry_start_logical_byte": entry_start_byte,
        "entry_end_logical_byte_inclusive": entry_end_byte,
        "target_logical_byte": target_logical_byte,
        "target_within_entry_bytes": (
            entry_start_byte <= target_logical_byte <= entry_end_byte
        ),
        "prefix_roundtrip_exact": True,
        "target_byte_candidates": target_byte_candidates,
        "observed_b_matches_target_candidates": (
            observed_b_matches_target_candidates
        ),
    }


def resolve_group_entry(
    baseline_rom: bytes,
    *,
    selector_offset: int,
    entry_ordinal: int,
    target_logical_byte: int,
    mapped_bank: int,
) -> dict[str, object]:
    if (
        not 0 <= selector_offset < LOOKUP_TABLE_END - LOOKUP_TABLE_BASE
        or selector_offset % 2
    ):
        raise PatchError("script group selector offset is invalid")
    pointer_offset = LOOKUP_TABLE_BASE + selector_offset
    if pointer_offset + 2 > len(baseline_rom):
        raise PatchError("script group lookup is outside the ROM")
    group_pointer_address = int.from_bytes(
        baseline_rom[pointer_offset : pointer_offset + 2],
        "little",
    )
    if not SLOT_1_BASE <= group_pointer_address < SLOT_1_END:
        raise PatchError("script group lookup contains an invalid pointer")
    group_physical_start = (
        mapped_bank * 0x4000 + (group_pointer_address - SLOT_1_BASE)
    )
    known = bytes((1,)) * len(baseline_rom)
    trees = load_trees_at(
        baseline_rom,
        known,
        KO_VECTOR_OFFSET,
        KO_TREE_BANK_BASE,
        KO_VECTOR_ENTRIES,
    )
    return resolve_group_entry_with_trees(
        baseline_rom,
        known,
        trees,
        group_physical_start=group_physical_start,
        group_pointer_address=group_pointer_address,
        entry_ordinal=entry_ordinal,
        target_logical_byte=target_logical_byte,
    )
