#!/usr/bin/env python3
"""Inspect Final Conflict's context-dependent Huffman trees from the English IPS.

This is an independent format parser.  It verifies every byte it consumes came
from an IPS record, so the clean copyrighted ROM is not needed for tree study.
Actual script entry lookup and dictionary expansion are intentionally separate
checkpoints and are not claimed complete here.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path

try:
    from .patch_io import PatchError, parse_ips, sha256_bytes
except ImportError:  # direct script execution
    from patch_io import PatchError, parse_ips, sha256_bytes

VECTOR_OFFSET = 0x29C3F
VECTOR_ENTRIES = 256
VECTOR_SIZE = VECTOR_ENTRIES * 2
BANK_BASE = 0x28000
EXPECTED_IPS_SIZE = 47290
EXPECTED_IPS_SHA256 = "3cc1085508c7298d5d20fbfefec929cdfdadbcd60340a66ec0e4c2aa92d48c07"
EXPECTED_NONEMPTY_TREES = 221
EXPECTED_EMPTY_TREES = 35
CANDIDATE_END_SYMBOL = 0xC9


@dataclass
class HuffmanNode:
    left: "HuffmanNode | None" = None
    right: "HuffmanNode | None" = None
    symbol: int | None = None

    @property
    def is_leaf(self) -> bool:
        return self.symbol is not None


@dataclass(frozen=True)
class ParsedTree:
    previous_symbol: int
    pointer: int
    structure_offset: int
    structure_bits: int
    leaf_count: int
    symbol_offset: int
    root: HuffmanNode


def build_ips_overlay(patch: bytes, minimum_size: int = 0x80000) -> tuple[bytes, bytes]:
    parsed = parse_ips(patch)
    required = minimum_size
    for record in parsed.records:
        required = max(required, record.offset + len(record.data))
    overlay = bytearray(required)
    known = bytearray(required)
    for record in parsed.records:
        end = record.offset + len(record.data)
        overlay[record.offset:end] = record.data
        known[record.offset:end] = b"\x01" * len(record.data)
    return bytes(overlay), bytes(known)


def _require_known(known: bytes, start: int, end: int, description: str) -> None:
    if start < 0 or end > len(known) or any(value == 0 for value in known[start:end]):
        raise PatchError(
            f"{description} depends on bytes not supplied by the IPS: "
            f"0x{start:x}..0x{end:x}"
        )


def _bit_at(data: bytes, known: bytes, base: int, bit_index: int) -> int:
    offset = base + (bit_index >> 3)
    _require_known(known, offset, offset + 1, "Huffman bit stream")
    return (data[offset] >> (7 - (bit_index & 7))) & 1


def parse_tree(
    data: bytes,
    known: bytes,
    previous_symbol: int,
    pointer: int,
    bank_base: int = BANK_BASE,
) -> ParsedTree:
    structure_offset = bank_base + (pointer & 0x3FFF)
    bit_index = 0
    leaves: list[HuffmanNode] = []
    node_count = 0

    def descend(depth: int) -> HuffmanNode:
        nonlocal bit_index, node_count
        node_count += 1
        if depth > 64 or node_count > 511:
            raise PatchError("invalid or cyclic-looking Huffman tree")
        marker = _bit_at(data, known, structure_offset, bit_index)
        bit_index += 1
        if marker:
            node = HuffmanNode()
            leaves.append(node)
            return node
        return HuffmanNode(left=descend(depth + 1), right=descend(depth + 1))

    root = descend(0)
    symbol_offset = structure_offset - len(leaves)
    _require_known(known, symbol_offset, structure_offset, "Huffman leaf symbols")
    symbols = list(data[symbol_offset:structure_offset])[::-1]
    for node, symbol in zip(leaves, symbols):
        node.symbol = symbol
    return ParsedTree(
        previous_symbol=previous_symbol,
        pointer=pointer,
        structure_offset=structure_offset,
        structure_bits=bit_index,
        leaf_count=len(leaves),
        symbol_offset=symbol_offset,
        root=root,
    )


def load_trees_at(
    data: bytes,
    known: bytes,
    vector_offset: int,
    bank_base: int,
    entries: int = VECTOR_ENTRIES,
) -> dict[int, ParsedTree]:
    """Load a context vector located in any 16 KiB ROM bank."""

    _require_known(
        known,
        vector_offset,
        vector_offset + entries * 2,
        "Huffman vector",
    )
    trees: dict[int, ParsedTree] = {}
    for previous_symbol in range(entries):
        at = vector_offset + previous_symbol * 2
        pointer = int.from_bytes(data[at : at + 2], "little")
        if pointer != 0xFFFF:
            trees[previous_symbol] = parse_tree(
                data,
                known,
                previous_symbol,
                pointer,
                bank_base=bank_base,
            )
    return trees


def load_trees(data: bytes, known: bytes) -> dict[int, ParsedTree]:
    return load_trees_at(data, known, VECTOR_OFFSET, BANK_BASE)


def decode_symbols(
    data: bytes,
    known: bytes,
    trees: dict[int, ParsedTree],
    start_offset: int,
    initial_symbol: int = CANDIDATE_END_SYMBOL,
    end_symbol: int = CANDIDATE_END_SYMBOL,
    max_symbols: int = 4096,
    max_bytes: int = 4096,
) -> tuple[list[int], int]:
    output: list[int] = []
    previous = initial_symbol
    bit_index = 0
    for _ in range(max_symbols):
        tree = trees.get(previous)
        if tree is None:
            raise PatchError(f"no Huffman tree for previous symbol 0x{previous:02x}")
        node = tree.root
        while not node.is_leaf:
            if (bit_index >> 3) >= max_bytes:
                raise PatchError("candidate entry exceeded byte limit")
            bit = _bit_at(data, known, start_offset, bit_index)
            bit_index += 1
            node = node.right if bit else node.left
            if node is None:
                raise PatchError("malformed Huffman branch")
        symbol = node.symbol
        assert symbol is not None
        output.append(symbol)
        previous = symbol
        if symbol == end_symbol:
            return output, bit_index
    raise PatchError("candidate entry did not terminate within symbol limit")


def decode_symbol_count(
    data: bytes,
    known: bytes,
    trees: dict[int, ParsedTree],
    start_offset: int,
    symbol_count: int,
    initial_symbol: int = CANDIDATE_END_SYMBOL,
    max_bytes: int = 4096,
) -> tuple[list[int], int]:
    """Decode an exact number of symbols without treating a value as a stop.

    Some Final Conflict callers decompress a fixed-size output block.  A
    terminator byte inside that block belongs to the decoded payload, while the
    caller's fixed output count determines when decoding finishes.
    """

    if not isinstance(symbol_count, int) or isinstance(symbol_count, bool):
        raise PatchError("Huffman symbol count must be an integer")
    if not 0 <= symbol_count <= 4096:
        raise PatchError("Huffman symbol count must be between 0 and 4096")
    if max_bytes <= 0:
        raise PatchError("Huffman byte limit must be positive")

    output: list[int] = []
    previous = initial_symbol
    bit_index = 0
    for _ in range(symbol_count):
        tree = trees.get(previous)
        if tree is None:
            raise PatchError(f"no Huffman tree for previous symbol 0x{previous:02x}")
        node = tree.root
        while not node.is_leaf:
            if (bit_index >> 3) >= max_bytes:
                raise PatchError("fixed-count Huffman block exceeded byte limit")
            bit = _bit_at(data, known, start_offset, bit_index)
            bit_index += 1
            node = node.right if bit else node.left
            if node is None:
                raise PatchError("malformed Huffman branch")
        symbol = node.symbol
        assert symbol is not None
        output.append(symbol)
        previous = symbol
    return output, bit_index


def decode_symbol_entries(
    data: bytes,
    known: bytes,
    trees: dict[int, ParsedTree],
    start_offset: int,
    entry_count: int,
    initial_symbol: int = CANDIDATE_END_SYMBOL,
    end_symbol: int = CANDIDATE_END_SYMBOL,
    max_symbols_per_entry: int = 4096,
    max_total_bytes: int = 0x4000,
) -> tuple[list[list[int]], int]:
    """Decode consecutive entries from one unpadded Huffman bit stream.

    Final Conflict groups many indexed strings behind one byte-aligned pointer.
    Each string resets the previous-symbol context, but the following string
    starts at the very next bit rather than at the next byte.
    """

    if not isinstance(entry_count, int) or isinstance(entry_count, bool):
        raise PatchError("entry count must be an integer")
    if not 0 <= entry_count <= 256:
        raise PatchError("entry count must be between 0 and 256")
    if max_symbols_per_entry <= 0 or max_total_bytes <= 0:
        raise PatchError("Huffman entry limits must be positive")

    entries: list[list[int]] = []
    bit_index = 0
    for _ in range(entry_count):
        output: list[int] = []
        previous = initial_symbol
        for _ in range(max_symbols_per_entry):
            tree = trees.get(previous)
            if tree is None:
                raise PatchError(
                    f"no Huffman tree for previous symbol 0x{previous:02x}"
                )
            node = tree.root
            while not node.is_leaf:
                if (bit_index >> 3) >= max_total_bytes:
                    raise PatchError("Huffman entry group exceeded byte limit")
                bit = _bit_at(data, known, start_offset, bit_index)
                bit_index += 1
                node = node.right if bit else node.left
                if node is None:
                    raise PatchError("malformed Huffman branch")
            symbol = node.symbol
            assert symbol is not None
            output.append(symbol)
            previous = symbol
            if symbol == end_symbol:
                entries.append(output)
                break
        else:
            raise PatchError(
                "Huffman group entry did not terminate within symbol limit"
            )
    return entries, bit_index


def _symbol_codes(root: HuffmanNode) -> dict[int, tuple[int, ...]]:
    codes: dict[int, tuple[int, ...]] = {}

    def visit(node: HuffmanNode | None, path: tuple[int, ...]) -> None:
        if node is None:
            raise PatchError("malformed Huffman branch")
        if node.is_leaf:
            symbol = node.symbol
            assert symbol is not None
            if symbol in codes:
                raise PatchError(
                    f"duplicate Huffman leaf symbol 0x{symbol:02x}"
                )
            codes[symbol] = path
            return
        visit(node.left, path + (0,))
        visit(node.right, path + (1,))

    visit(root, ())
    return codes


def encode_symbols(
    trees: dict[int, ParsedTree],
    symbols: list[int],
    initial_symbol: int = CANDIDATE_END_SYMBOL,
    end_symbol: int = CANDIDATE_END_SYMBOL,
    max_bits: int = 32768,
) -> tuple[bytes, int]:
    """Encode one terminated context-dependent Huffman symbol sequence."""

    if not symbols or symbols[-1] != end_symbol:
        raise PatchError("Huffman symbol sequence must end with the terminator")
    bits: list[int] = []
    previous = initial_symbol
    code_cache: dict[int, dict[int, tuple[int, ...]]] = {}
    for symbol in symbols:
        tree = trees.get(previous)
        if tree is None:
            raise PatchError(
                f"no Huffman tree for previous symbol 0x{previous:02x}"
            )
        codes = code_cache.setdefault(previous, _symbol_codes(tree.root))
        code = codes.get(symbol)
        if code is None:
            raise PatchError(
                f"symbol 0x{symbol:02x} is absent after 0x{previous:02x}"
            )
        bits.extend(code)
        if len(bits) > max_bits:
            raise PatchError("encoded Huffman entry exceeded bit limit")
        previous = symbol
    output = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit:
            output[index >> 3] |= 1 << (7 - (index & 7))
    return bytes(output), len(bits)


def encode_symbol_count(
    trees: dict[int, ParsedTree],
    symbols: list[int],
    initial_symbol: int = CANDIDATE_END_SYMBOL,
    max_bits: int = 32768,
) -> tuple[bytes, int]:
    """Encode a fixed-count block while preserving context across terminators."""

    if len(symbols) > 4096:
        raise PatchError("Huffman fixed-count block exceeds 4096 symbols")
    bits: list[int] = []
    previous = initial_symbol
    code_cache: dict[int, dict[int, tuple[int, ...]]] = {}
    for symbol in symbols:
        tree = trees.get(previous)
        if tree is None:
            raise PatchError(
                f"no Huffman tree for previous symbol 0x{previous:02x}"
            )
        codes = code_cache.setdefault(previous, _symbol_codes(tree.root))
        code = codes.get(symbol)
        if code is None:
            raise PatchError(
                f"symbol 0x{symbol:02x} is absent after 0x{previous:02x}"
            )
        bits.extend(code)
        if len(bits) > max_bits:
            raise PatchError("encoded fixed-count Huffman block exceeded bit limit")
        previous = symbol
    output = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit:
            output[index >> 3] |= 1 << (7 - (index & 7))
    return bytes(output), len(bits)


def encode_symbol_entries(
    trees: dict[int, ParsedTree],
    entries: list[list[int]],
    initial_symbol: int = CANDIDATE_END_SYMBOL,
    end_symbol: int = CANDIDATE_END_SYMBOL,
    max_bits: int = 0x4000 * 8,
) -> tuple[bytes, int]:
    """Encode consecutive entries without inserting per-entry byte padding."""

    if len(entries) > 256:
        raise PatchError("Huffman entry group exceeds 256 entries")
    bits: list[int] = []
    code_cache: dict[int, dict[int, tuple[int, ...]]] = {}
    for entry in entries:
        if not entry or entry[-1] != end_symbol:
            raise PatchError(
                "every Huffman group entry must end with the terminator"
            )
        previous = initial_symbol
        for symbol in entry:
            tree = trees.get(previous)
            if tree is None:
                raise PatchError(
                    f"no Huffman tree for previous symbol 0x{previous:02x}"
                )
            codes = code_cache.setdefault(previous, _symbol_codes(tree.root))
            code = codes.get(symbol)
            if code is None:
                raise PatchError(
                    f"symbol 0x{symbol:02x} is absent after 0x{previous:02x}"
                )
            bits.extend(code)
            if len(bits) > max_bits:
                raise PatchError("encoded Huffman entry group exceeded bit limit")
            previous = symbol
    output = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit:
            output[index >> 3] |= 1 << (7 - (index & 7))
    return bytes(output), len(bits)


def render_basic(symbols: list[int]) -> str:
    rendered: list[str] = []
    for symbol in symbols:
        if symbol == 0x01:
            rendered.append(" ")
        elif 0x02 <= symbol <= 0x0B:
            rendered.append(chr(ord("0") + symbol - 0x02))
        elif 0x0C <= symbol <= 0x25:
            rendered.append(chr(ord("A") + symbol - 0x0C))
        elif 0x26 <= symbol <= 0x3F:
            rendered.append(chr(ord("a") + symbol - 0x26))
        elif symbol == 0xD0:
            rendered.append("\n")
        elif symbol == CANDIDATE_END_SYMBOL:
            rendered.append("<END>")
        else:
            rendered.append(f"<{symbol:02X}>")
    return "".join(rendered)


def verified_overlay(path: Path) -> tuple[bytes, bytes, dict[int, ParsedTree]]:
    patch = path.read_bytes()
    if len(patch) != EXPECTED_IPS_SIZE or sha256_bytes(patch) != EXPECTED_IPS_SHA256:
        raise PatchError("English IPS identity mismatch")
    data, known = build_ips_overlay(patch)
    trees = load_trees(data, known)
    if len(trees) != EXPECTED_NONEMPTY_TREES:
        raise PatchError(f"expected 221 populated trees, found {len(trees)}")
    if VECTOR_ENTRIES - len(trees) != EXPECTED_EMPTY_TREES:
        raise PatchError("unexpected empty-tree count")
    return data, known, trees


def integer(value: str) -> int:
    return int(value, 0)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ips",
        type=Path,
        default=root / "patch" / "fcpatch_070706.ips",
        help="verified local English reference IPS",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    stats_parser = subparsers.add_parser("stats", help="validate and summarize the tree block")
    stats_parser.add_argument("--json", action="store_true")
    decode_parser = subparsers.add_parser("decode", help="decode one candidate compressed offset")
    decode_parser.add_argument("--offset", type=integer, required=True, help="file offset, e.g. 0x203d2")
    decode_parser.add_argument("--max-symbols", type=int, default=4096)
    args = parser.parse_args()

    data, known, trees = verified_overlay(args.ips)
    if args.command == "stats":
        leaf_counts = [tree.leaf_count for tree in trees.values()]
        result = {
            "ips_sha256": EXPECTED_IPS_SHA256,
            "vector_file_offset": f"0x{VECTOR_OFFSET:x}",
            "vector_logical_address": "0x5c3f",
            "populated_trees": len(trees),
            "empty_trees": VECTOR_ENTRIES - len(trees),
            "minimum_leaves": min(leaf_counts),
            "maximum_leaves": max(leaf_counts),
            "candidate_initial_end_symbol": f"0x{CANDIDATE_END_SYMBOL:02x}",
        }
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            for key, value in result.items():
                print(f"{key}: {value}")
        return 0

    symbols, bits = decode_symbols(
        data,
        known,
        trees,
        args.offset,
        max_symbols=args.max_symbols,
    )
    print(render_basic(symbols))
    print(f"symbols={len(symbols)} bits={bits} bytes={(bits + 7) // 8}")
    print("High-byte word tokens are not expanded until the dictionary checkpoint is verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
