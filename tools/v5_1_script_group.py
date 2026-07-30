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
    """Resolve the zero-based B-register ordinal selected by the decoder.

    The patched routine increments B before its skip loop.  Therefore an entry
    ordinal of N requires decoding N+1 terminator-delimited strings from the
    group's byte-aligned pointer, while preserving the bit cursor between them.
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

    selected_symbols = prefix_entries[-1]
    _, selected_bits = encode_symbol_entries(
        trees,
        [selected_symbols],
        initial_symbol=CANDIDATE_END_SYMBOL,
        end_symbol=CANDIDATE_END_SYMBOL,
        max_bits=prefix_bits,
    )
    entry_start_bit = prefix_bits - selected_bits
    entry_end_bit = prefix_bits
    entry_start_byte = group_pointer_address + entry_start_bit // 8
    entry_end_byte = group_pointer_address + (entry_end_bit - 1) // 8
    if entry_end_byte >= SLOT_1_END:
        raise PatchError("selected script group entry crosses the slot boundary")

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
        "entry_symbol_count": len(selected_symbols),
        "entry_start_logical_byte": entry_start_byte,
        "entry_end_logical_byte_inclusive": entry_end_byte,
        "target_logical_byte": target_logical_byte,
        "target_within_entry_bytes": (
            entry_start_byte <= target_logical_byte <= entry_end_byte
        ),
        "prefix_roundtrip_exact": True,
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
