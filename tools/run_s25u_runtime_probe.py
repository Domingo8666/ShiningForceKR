#!/usr/bin/env python3
"""Run a ROM-local Gearsystem MCP read-breakpoint experiment on S25U."""

from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from typing import Any

try:
    from .patch_io import sha256_file
    from .v5_1_consumer import verify_target_identity
    from .v5_1_runtime_observation import (
        PUBLISH_RELATIVE_PATH as RUNTIME_OBSERVATION_PATH,
        build_runtime_observation,
        publish_runtime_observation,
        validate_runtime_observation,
        write_runtime_observation,
    )
    from .v5_1_runtime_hit_resolver import (
        _alignment_pointer,
        _find_access,
        _parse_trace_line,
        _read_addresses,
    )
    from .v5_1_trace_plan import logical_mapping_hypotheses
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_consumer import verify_target_identity
    from v5_1_runtime_observation import (
        PUBLISH_RELATIVE_PATH as RUNTIME_OBSERVATION_PATH,
        build_runtime_observation,
        publish_runtime_observation,
        validate_runtime_observation,
        write_runtime_observation,
    )
    from v5_1_runtime_hit_resolver import (
        _alignment_pointer,
        _find_access,
        _parse_trace_line,
        _read_addresses,
    )
    from v5_1_trace_plan import logical_mapping_hypotheses

DEFAULT_ROM = Path("build/Final_Conflict_Korean_v5.1.gg")
DEFAULT_TRACE_PLAN = Path("reports/v5_1_emucap_trace_plan.json")
LOCAL_REPORT = Path("reports/local/v5_1_gearsystem_probe.json")
LOCAL_FAILURE_REPORT = Path("reports/local/v5_1_runtime_failure.json")
GEARSYSTEM_COMMAND = (
    "export SDL_VIDEODRIVER=dummy SDL_AUDIODRIVER=dummy; "
    "export XDG_RUNTIME_DIR=/tmp/sfkr-runtime; "
    "mkdir -p \"$XDG_RUNTIME_DIR\"; "
    "cd /opt/sfkr-gearsystem && "
    "exec ./gearsystem --headless --mcp-stdio"
)
REQUIRED_TOOLS = {
    "controller_button",
    "debug_continue",
    "debug_get_status",
    "debug_pause",
    "debug_reset",
    "debug_step_frame",
    "debug_step_into",
    "get_call_stack",
    "get_media_info",
    "get_trace_log",
    "get_z80_status",
    "list_memory_areas",
    "load_media",
    "read_memory",
    "remove_breakpoint",
    "set_breakpoint_range",
    "set_trace_log",
}
INPUT_SCHEDULE: tuple[tuple[int, str | None], ...] = (
    (180, None),
    (240, "start"),
    *((180, "2"),) * 16,
)
MAX_REJECTED_BANK_HITS_PER_SLOT = 64
MAX_RUNTIME_CANDIDATE_GROUPS = 2
MIN_SINGLE_FRAME_TIMEOUT_SECONDS = 5.0
RUNTIME_FAILURE_STAGES = {
    "mcp-start",
    "mcp-initialize",
    "load-media",
    "media-identity",
    "trace-enable",
    "candidate-probe",
    "target-followup",
    "mcp-close",
    "runtime-probe",
    "runtime-hit-resolver",
    "renderer-probe",
    "decoder-stream-resolution",
    "route-capture",
    "decoder-register-trace",
    "renderer-output-trace",
    "renderer-output-mcp-initialize",
    "renderer-output-load-media",
    "renderer-output-route-selection",
    "renderer-output-route-watch",
    "renderer-output-route-hunt",
    "renderer-output-route-entry",
    "renderer-output-route-endpoint",
    "renderer-output-route-ready",
    "renderer-output-trace-enable",
    "renderer-output-trace-run",
    "renderer-output-trace-read",
    "renderer-output-artifact",
    "visible-unicode-mapping",
    "initial-font-page-trace",
    "initial-font-page-mcp-initialize",
    "initial-font-page-load-media",
    "initial-font-page-route-selection",
    "initial-font-page-output-watch",
    "test-patch",
    "test-patch-fixed-count-roundtrip",
    "test-patch-fixed-count-read-range",
    "test-patch-no-marker-candidate",
    "test-patch-marker-encoding",
    "test-patch-marker-roundtrip",
    "display-capture-preflight",
    "baseline-display-capture",
    "test-display-capture",
    "display-version-check",
    "display-pixel-comparison",
    "display-comparison-artifact",
    "display-capture-artifact",
    "display-capture-local-artifact",
    "display-capture-safe-schema",
    "display-capture-safe-publish",
    "display-comparison",
    "visible-entry-proof",
    "font-transfer-source",
    "confirmed-group-extract",
    "target-group-usage",
    "target-group-stream-map",
    "target-group-population",
    "target-group-population-decode",
    "target-group-expanded-glyphs",
    "target-group-non-hangul-glyphs",
    "target-group-expanded-corpus",
    "target-group-record-quality",
    "source-script-reference",
    "source-target-anchor",
    "source-target-section-projection",
    "section-projection-identity",
    "section-projection-anchor",
    "section-projection-target",
    "section-projection-source",
    "section-projection-tier",
    "section-projection-speaker",
    "section-projection-input",
    "section-projection-validation",
    "decoder-caller-resolution",
    "group-context-resolution",
    "group-runtime-context",
    "group-source-delta",
    "source-huffman-locator",
    "source-group-codec-probe",
    "group-text-candidate-resolution",
    "unmatched-glyph-fuzzy",
    "group-script-corpus",
    "source-record-pairing",
    "confirmed-group-unicode",
}
RUNTIME_FAILURE_KINDS = {
    "invalid-json",
    "subprocess-timeout",
    "process-io",
    "invalid-runtime-data",
    "mcp-timeout",
    "frame-step-timeout",
    "instruction-step-timeout",
    "mcp-error",
    "tool-error",
    "required-tools",
    "media-identity",
    "invalid-mcp-payload",
    "runtime-error",
    "unexpected-exception",
}


def _tool_payload(message: dict[str, object]) -> dict[str, Any]:
    result = message.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("MCP response has no result object")
    if result.get("isError"):
        content = result.get("content")
        raise RuntimeError(f"Gearsystem tool error: {content}")
    content = result.get("content")
    if not isinstance(content, list):
        raise RuntimeError("Gearsystem tool response has no content")
    text = next(
        (
            item.get("text")
            for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        ),
        None,
    )
    if text is not None:
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise RuntimeError("Gearsystem tool payload must be an object")
        return payload
    image = next(
        (
            item
            for item in content
            if (
                isinstance(item, dict)
                and item.get("type") == "image"
                and isinstance(item.get("data"), str)
                and isinstance(item.get("mimeType"), str)
            )
        ),
        None,
    )
    if image is not None:
        return {
            "data": image["data"],
            "mimeType": image["mimeType"],
        }
    raise RuntimeError("Gearsystem tool response has no JSON text or image")


class McpStdioClient:
    def __init__(self, command: list[str]) -> None:
        self._process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        if self._process.stdin is None or self._process.stdout is None:
            raise RuntimeError("failed to open Gearsystem MCP pipes")
        self._stdin = self._process.stdin
        self._stdout = self._process.stdout
        self._next_id = 1
        self._messages: queue.Queue[dict[str, object]] = queue.Queue()
        self.last_request_method: str | None = None
        self.last_tool_name: str | None = None
        self.stderr_tail: deque[str] = deque(maxlen=80)
        threading.Thread(
            target=self._drain_stdout,
            args=(self._stdout,),
            daemon=True,
        ).start()
        if self._process.stderr is not None:
            threading.Thread(
                target=self._drain_stderr,
                args=(self._process.stderr,),
                daemon=True,
            ).start()

    def _drain_stderr(self, stream: Any) -> None:
        for line in stream:
            self.stderr_tail.append(line.rstrip())

    def _drain_stdout(self, stream: Any) -> None:
        for line in stream:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                self._messages.put(message)

    def _request(self, method: str, params: dict[str, object]) -> dict[str, object]:
        self.last_request_method = method
        request_id = self._next_id
        self._next_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        self._stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self._stdin.flush()
        deadline = time.monotonic() + 30
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(
                    f"Gearsystem MCP timed out during {method}; stderr tail: "
                    + " | ".join(self.stderr_tail)
                )
            try:
                response = self._messages.get(timeout=remaining)
            except queue.Empty as error:
                raise RuntimeError(
                    f"Gearsystem MCP timed out during {method}; stderr tail: "
                    + " | ".join(self.stderr_tail)
                ) from error
            if response.get("id") != request_id:
                continue
            if "error" in response:
                raise RuntimeError(f"MCP error: {response['error']}")
            return response

    def initialize(self) -> set[str]:
        self._request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "SFKR-S25U-probe", "version": "1"},
            },
        )
        self._stdin.write(
            '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
        )
        self._stdin.flush()
        response = self._request("tools/list", {})
        result = response.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            raise RuntimeError("Gearsystem returned no MCP tool list")
        return {
            item["name"]
            for item in result["tools"]
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }

    def call(self, name: str, arguments: dict[str, object] | None = None) -> dict[str, Any]:
        self.last_tool_name = name
        return _tool_payload(
            self._request(
                "tools/call",
                {"name": name, "arguments": arguments or {}},
            )
        )

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._process.wait(timeout=5)


def _step_frames_and_wait(
    client: McpStdioClient,
    frames: int,
) -> dict[str, object]:
    """Advance exact frames with a recoverable completion barrier per frame."""

    if not 1 <= frames <= 1000:
        raise ValueError("frame step must be between 1 and 1000")
    status: dict[str, object] = {}
    for _ in range(frames):
        # Gearsystem 3.9.14 acknowledges a multi-frame request before the final
        # frame and cannot cancel its pending count through debug_pause. A
        # one-frame request reaches Debug_Command_None after a single main-loop
        # update, so every iteration has a bounded and recoverable barrier.
        client.call("debug_step_frame", {"frames": 1})
        deadline = time.monotonic() + _frame_step_timeout_seconds(1)
        while True:
            status = client.call("debug_get_status")
            if status.get("at_breakpoint") is True:
                return status
            if status.get("paused") is True:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "Gearsystem frame step did not finish within 1 frame"
                )
            time.sleep(0.01)
    return status


def _frame_step_timeout_seconds(frames: int) -> float:
    if not 1 <= frames <= 1000:
        raise ValueError("frame step must be between 1 and 1000")
    return max(MIN_SINGLE_FRAME_TIMEOUT_SECONDS, (frames / 50.0) + 2.0)


def _step_instruction_and_wait(client: McpStdioClient) -> dict[str, object]:
    """Execute exactly one Z80 instruction and wait for Gearsystem to stop."""

    client.call("debug_step_into")
    deadline = time.monotonic() + 5.0
    while True:
        status = client.call("debug_get_status")
        if status.get("paused") is True:
            return status
        if time.monotonic() >= deadline:
            raise RuntimeError("Gearsystem instruction step did not finish")
        time.sleep(0.02)


def _watch_ranges(plan: dict[str, object]) -> list[dict[str, int]]:
    if int(plan.get("schema_version", 0)) < 5:
        raise ValueError("trace plan schema 5 or newer is required")
    watch = plan.get("selected_watch")
    if not isinstance(watch, dict):
        raise ValueError("trace plan has no selected watch")
    mappings = watch.get("logical_mappings")
    if not isinstance(mappings, list) or not mappings:
        raise ValueError("trace plan has no logical mappings")
    output: list[dict[str, int]] = []
    for item in mappings:
        if not isinstance(item, dict):
            raise ValueError("logical mapping must be an object")
        mapping = {
            "slot": int(item["slot"]),
            "expected_bank": int(item["bank"]),
            "logical_start": int(item["logical_start"]),
            "logical_end": int(item["logical_end"]),
        }
        if mapping["slot"] not in (0, 1, 2):
            raise ValueError("logical mapping has an invalid slot")
        if not 0 <= mapping["logical_start"] <= mapping["logical_end"] <= 0xFFFF:
            raise ValueError("logical mapping range is invalid")
        output.append(mapping)
    if len({item["slot"] for item in output}) != len(output):
        raise ValueError("logical mapping slots must be unique")
    return output


def _range_key(mapping: dict[str, int]) -> tuple[int, int, int, int]:
    return (
        int(mapping["slot"]),
        int(mapping["expected_bank"]),
        int(mapping["logical_start"]),
        int(mapping["logical_end"]),
    )


def _prior_no_hit_ranges(
    root: Path,
    target_sha256: str,
) -> set[tuple[int, int, int, int]]:
    path = root / RUNTIME_OBSERVATION_PATH
    documents: list[str] = []
    try:
        documents.append(path.read_text(encoding="utf-8"))
    except OSError:
        pass
    relative = str(RUNTIME_OBSERVATION_PATH).replace("\\", "/")
    history = subprocess.run(
        ["git", "log", "-16", "--format=%H", "--", relative],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if history.returncode == 0:
        for commit in history.stdout.splitlines():
            shown = subprocess.run(
                ["git", "show", f"{commit}:{relative}"],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if shown.returncode == 0:
                documents.append(shown.stdout)
    output: set[tuple[int, int, int, int]] = set()
    for document in documents:
        try:
            observation = json.loads(document)
            if not isinstance(observation, dict):
                continue
            validate_runtime_observation(observation)
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(observation, dict):
            continue
        if (
            observation.get("target_sha256") != target_sha256
            or observation.get("read_hit_observed") is not False
        ):
            continue
        probe = observation.get("probe")
        if not isinstance(probe, dict):
            continue
        ranges = probe.get("breakpoint_ranges")
        if not isinstance(ranges, list):
            continue
        output.update(
            _range_key(item)
            for item in ranges
            if isinstance(item, dict)
        )
    return output


def _overlap_ratio(
    left: dict[str, object],
    right: dict[str, object],
) -> float:
    left_start = int(left["file_offset"])
    left_end = int(left["end_exclusive"])
    right_start = int(right["file_offset"])
    right_end = int(right["end_exclusive"])
    overlap = max(0, min(left_end, right_end) - max(left_start, right_start))
    shorter = min(left_end - left_start, right_end - right_start)
    return 0.0 if shorter <= 0 else overlap / shorter


def _candidate_cluster(
    selected: dict[str, object],
    ranked: list[dict[str, object]],
) -> list[dict[str, object]]:
    cluster: list[dict[str, object]] = []
    for item in ranked:
        if (
            item.get("family") != "triplet"
            or item.get("format") not in {"addr_le_bank", "bank_addr_le"}
            or int(item.get("entry_width", 0)) != 3
            or abs(int(item["file_offset"]) - int(selected["file_offset"])) >= 3
            or _overlap_ratio(selected, item) < 0.90
        ):
            continue
        cluster.append(
            {
                "file_offset": int(item["file_offset"]),
                "end_exclusive": int(item["end_exclusive"]),
                "format": str(item["format"]),
                "entries": int(item["entries"]),
            }
        )
    return cluster


def _runtime_candidate_groups(
    plan: dict[str, object],
    excluded_ranges: set[tuple[int, int, int, int]] | None = None,
) -> list[dict[str, object]]:
    if int(plan.get("schema_version", 0)) < 5:
        raise ValueError("trace plan schema 5 or newer is required")
    ranked_value = plan.get("ranked_consumer_hypotheses")
    if not isinstance(ranked_value, list):
        raise ValueError("trace plan has no ranked consumer hypotheses")
    ranked = [item for item in ranked_value if isinstance(item, dict)]
    excluded = excluded_ranges or set()
    groups: list[dict[str, object]] = []
    seen_extents: set[tuple[int, int]] = set()
    for rank, candidate in enumerate(ranked, 1):
        full_decode = candidate.get("full_decode_probe")
        if (
            candidate.get("family") != "triplet"
            or candidate.get("format") not in {"addr_le_bank", "bank_addr_le"}
            or int(candidate.get("entry_width", 0)) != 3
            or not isinstance(full_decode, dict)
            or int(full_decode.get("bounded_terminations", 0)) < 1
        ):
            continue
        cluster = _candidate_cluster(candidate, ranked)
        if not cluster:
            continue
        watch_start = min(int(item["file_offset"]) for item in cluster)
        watch_end = max(int(item["end_exclusive"]) for item in cluster)
        extent = (watch_start, watch_end)
        if extent in seen_extents:
            continue
        seen_extents.add(extent)
        mappings = [
            {
                "slot": int(item["slot"]),
                "expected_bank": int(item["bank"]),
                "logical_start": int(item["logical_start"]),
                "logical_end": int(item["logical_end"]),
            }
            for item in logical_mapping_hypotheses(
                watch_start, watch_end - watch_start
            )
        ]
        if mappings and all(_range_key(item) in excluded for item in mappings):
            continue
        groups.append(
            {
                "rank": rank,
                "watch": {
                    "file_start": watch_start,
                    "end_exclusive": watch_end,
                },
                "alignment_cluster": cluster,
                "mappings": mappings,
            }
        )
        if len(groups) >= MAX_RUNTIME_CANDIDATE_GROUPS:
            break
    return groups


def _parse_hex(value: object, label: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a hex string")
    return int(value, 16)


def _parse_mapper(data: object) -> tuple[int, int, int, int]:
    if not isinstance(data, str):
        raise ValueError("mapper data must be a hex byte string")
    values = [int(token, 16) for token in data.split()]
    if len(values) != 4 or any(not 0 <= value <= 255 for value in values):
        raise ValueError("mapper snapshot must contain four bytes")
    return values[0], values[1], values[2], values[3]


def _call_stack_depth(payload: dict[str, object]) -> int:
    for key in ("frames", "call_stack", "stack"):
        value = payload.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def _frames_per_slot() -> int:
    return sum(frames for frames, _ in INPUT_SCHEDULE)


def _capture_state(
    client: McpStdioClient,
) -> tuple[dict[str, object], dict[str, object]]:
    status = client.call("debug_get_status")
    z80 = client.call("get_z80_status")
    areas = client.call("list_memory_areas")
    area_list = areas.get("areas")
    if not isinstance(area_list, list):
        raise RuntimeError("Gearsystem returned no memory areas")
    ram = next(
        (
            item
            for item in area_list
            if isinstance(item, dict)
            and item.get("name") == "RAM"
            and isinstance(item.get("id"), int)
            and isinstance(item.get("size"), int)
            and item["size"] >= 0x2000
        ),
        None,
    )
    if ram is None:
        raise RuntimeError("Gearsystem RAM area was not found")
    mapper_offset = int(ram["size"]) - 4
    mapper_payload = client.call(
        "read_memory",
        {
            "area": int(ram["id"]),
            "offset": f"{mapper_offset:04X}",
            "size": 4,
        },
    )
    mapper_control, slot0, slot1, slot2 = _parse_mapper(
        mapper_payload.get("data")
    )
    trace = client.call("get_trace_log", {"count": 256})
    call_stack = client.call("get_call_stack")
    registers = {
        key.lower(): _parse_hex(z80.get(key), key)
        for key in ("AF", "BC", "DE", "HL", "IX", "IY", "SP")
    }
    safe_state: dict[str, object] = {
        "pc_after": _parse_hex(status.get("pc"), "pc"),
        "physical_pc_after": _parse_hex(z80.get("physical_PC"), "physical_PC"),
        "executing_bank": _parse_hex(z80.get("bank"), "bank"),
        "mapper_control": mapper_control,
        "slot0_bank": slot0,
        "slot1_bank": slot1,
        "slot2_bank": slot2,
        "registers": registers,
        "trace_entries": int(trace.get("count", len(trace.get("lines", [])))),
        "call_stack_depth": _call_stack_depth(call_stack),
    }
    local_evidence = {
        "status": status,
        "z80": z80,
        "mapper": mapper_payload,
        "trace": trace,
        "call_stack": call_stack,
    }
    return safe_state, local_evidence


def _capture_hit(
    client: McpStdioClient,
    mapping: dict[str, int],
) -> tuple[dict[str, object], dict[str, object]]:
    safe_state, local_evidence = _capture_state(client)
    return {**mapping, **safe_state}, local_evidence


def _mapping_bank_matches(
    hit: dict[str, object],
    mapping: dict[str, int],
) -> bool:
    slot = int(mapping["slot"])
    return int(hit[f"slot{slot}_bank"]) == int(mapping["expected_bank"])


def _instruction_fetch_like(
    hit: dict[str, object],
    mapping: dict[str, int],
) -> bool:
    """Reject ROM read breakpoints raised by execution inside the watched bytes."""

    physical_start = (
        int(mapping["expected_bank"]) * 0x4000
        + (int(mapping["logical_start"]) & 0x3FFF)
    )
    physical_end = (
        int(mapping["expected_bank"]) * 0x4000
        + (int(mapping["logical_end"]) & 0x3FFF)
    )
    physical_pc_after = int(hit["physical_pc_after"])
    # Gearsystem can report the PC after fetching one or more opcode bytes.
    return physical_start <= physical_pc_after <= physical_end + 4


def _rejected_instruction_fetch_hit(
    hit: dict[str, object],
    mapping: dict[str, int],
) -> dict[str, object]:
    slot = int(mapping["slot"])
    return {
        "slot": slot,
        "expected_bank": int(mapping["expected_bank"]),
        "mapped_bank": int(hit[f"slot{slot}_bank"]),
        "pc_after": int(hit["pc_after"]),
        "physical_pc_after": int(hit["physical_pc_after"]),
        "rejection_kind": "instruction-fetch-like",
    }


def _rejected_bank_hit(
    hit: dict[str, object],
    mapping: dict[str, int],
) -> dict[str, int]:
    slot = int(mapping["slot"])
    return {
        "slot": slot,
        "expected_bank": int(mapping["expected_bank"]),
        "mapped_bank": int(hit[f"slot{slot}_bank"]),
        "pc_after": int(hit["pc_after"]),
        "physical_pc_after": int(hit["physical_pc_after"]),
    }


def _target_candidates(
    rom: bytes,
    plan: dict[str, object],
    physical_table_byte: int,
) -> list[dict[str, object]]:
    cluster = plan.get("selected_alignment_cluster")
    if not isinstance(cluster, list):
        raise ValueError("trace plan has no alignment cluster")
    output: list[dict[str, object]] = []
    for item in cluster:
        if not isinstance(item, dict):
            continue
        pointer = _alignment_pointer(rom, item, physical_table_byte)
        if (
            pointer is not None
            and pointer["target_file_offset"] is not None
            and pointer["target_slot"] in {1, 2}
        ):
            output.append(pointer)
    return output


def _last_candidate_access(
    evidence: dict[str, object],
    candidates: list[dict[str, object]],
) -> tuple[dict[str, int], int] | None:
    trace = evidence.get("trace")
    z80 = evidence.get("z80")
    if not isinstance(trace, dict) or not isinstance(z80, dict):
        return None
    lines = trace.get("lines")
    if not isinstance(lines, list):
        return None
    addresses = {int(item["pointer_address"]) for item in candidates}
    for line in reversed(lines):
        if not isinstance(line, str):
            continue
        parsed = _parse_trace_line(line)
        if parsed is None:
            continue
        registers = parsed["registers"]
        assert isinstance(registers, dict)
        registers = {str(key): int(value) for key, value in registers.items()}
        for name in ("IX", "IY"):
            value = z80.get(name)
            if isinstance(value, str):
                registers[name.lower()] = int(value, 16)
        for address in _read_addresses(parsed["opcodes"], registers):
            if address in addresses:
                return {
                    "bank": int(parsed["bank"]),
                    "pc": int(parsed["pc"]),
                }, address
    return None


def _matching_target_candidate(
    candidates: list[dict[str, object]],
    logical_access: int,
    state: dict[str, object],
) -> dict[str, object] | None:
    matches: list[dict[str, object]] = []
    for candidate in candidates:
        slot = int(candidate["target_slot"])
        if (
            int(candidate["pointer_address"]) == logical_access
            and int(candidate["pointer_bank"]) == int(state[f"slot{slot}_bank"])
        ):
            matches.append(candidate)
    return matches[0] if len(matches) == 1 else None


def _follow_target_read(
    client: McpStdioClient,
    candidates: list[dict[str, object]],
    timeout_seconds: float = 10.0,
) -> dict[str, object]:
    result: dict[str, object] = {
        "status": "target-read-not-attempted",
        "candidates": candidates,
        "matching_candidate": None,
        "logical_access": None,
        "trace_record": None,
        "hit": None,
        "evidence": None,
        "events_seen": 0,
    }
    if not candidates:
        result["status"] = "target-read-no-valid-candidates"
        return result

    addresses = sorted({int(item["pointer_address"]) for item in candidates})
    armed: list[str] = []
    try:
        for address in addresses:
            encoded = f"{address:04X}"
            client.call(
                "set_breakpoint_range",
                {
                    "start_address": encoded,
                    "end_address": encoded,
                    "memory_area": "rom_ram",
                    "execute": False,
                    "read": True,
                    "write": False,
                },
            )
            armed.append(encoded)

        deadline = time.monotonic() + timeout_seconds
        client.call("debug_continue")
        while time.monotonic() < deadline:
            status = client.call("debug_get_status")
            if status.get("at_breakpoint") is not True:
                time.sleep(0.05)
                continue
            state, evidence = _capture_state(client)
            result["events_seen"] = int(result["events_seen"]) + 1
            access = _last_candidate_access(evidence, candidates)
            if access is not None:
                trace_record, logical_access = access
                matching = _matching_target_candidate(
                    candidates, logical_access, state
                )
                result.update(
                    {
                        "logical_access": logical_access,
                        "trace_record": trace_record,
                        "hit": state,
                        "evidence": evidence,
                        "matching_candidate": matching,
                    }
                )
                if matching is not None:
                    result["status"] = "target-read-confirmed"
                    return result
            if int(result["events_seen"]) >= 32:
                result["status"] = "target-read-unconfirmed"
                return result
            client.call("debug_continue")

        client.call("debug_pause")
        result["status"] = "target-read-timeout"
        return result
    finally:
        for encoded in armed:
            try:
                client.call(
                    "remove_breakpoint",
                    {
                        "address": encoded,
                        "end_address": encoded,
                        "memory_area": "rom_ram",
                    },
                )
            except RuntimeError:
                pass


def _probe_slot(
    client: McpStdioClient,
    mapping: dict[str, int],
    *,
    max_rejected_bank_hits: int = MAX_REJECTED_BANK_HITS_PER_SLOT,
) -> tuple[
    dict[str, object] | None,
    dict[str, object] | None,
    list[dict[str, object]],
]:
    if max_rejected_bank_hits < 1:
        raise ValueError("max_rejected_bank_hits must be positive")
    rejected_bank_hits: list[dict[str, object]] = []
    client.call("debug_reset")
    client.call("debug_pause")
    start = f"{mapping['logical_start']:04X}"
    end = f"{mapping['logical_end']:04X}"
    client.call(
        "set_breakpoint_range",
        {
            "start_address": start,
            "end_address": end,
            "memory_area": "rom_ram",
            "execute": False,
            "read": True,
            "write": False,
        },
    )
    try:
        for frames, button in INPUT_SCHEDULE:
            if button is not None:
                client.call(
                    "controller_button",
                    {
                        "player": 1,
                        "button": button,
                        "action": "press_and_release",
                    },
                )
            while True:
                status = _step_frames_and_wait(client, frames)
                if status.get("at_breakpoint") is not True:
                    break
                hit, evidence = _capture_hit(client, mapping)
                if _mapping_bank_matches(hit, mapping):
                    if _instruction_fetch_like(hit, mapping):
                        rejected_bank_hits.append(
                            _rejected_instruction_fetch_hit(hit, mapping)
                        )
                        if len(rejected_bank_hits) >= max_rejected_bank_hits:
                            return None, None, rejected_bank_hits
                        client.call(
                            "remove_breakpoint",
                            {
                                "address": start,
                                "end_address": end,
                                "memory_area": "rom_ram",
                            },
                        )
                        _step_instruction_and_wait(client)
                        client.call(
                            "set_breakpoint_range",
                            {
                                "start_address": start,
                                "end_address": end,
                                "memory_area": "rom_ram",
                                "execute": False,
                                "read": True,
                                "write": False,
                            },
                        )
                        continue
                    return hit, evidence, rejected_bank_hits
                rejected_bank_hits.append(_rejected_bank_hit(hit, mapping))
                if len(rejected_bank_hits) >= max_rejected_bank_hits:
                    return None, None, rejected_bank_hits
    finally:
        try:
            client.call(
                "remove_breakpoint",
                {
                    "address": start,
                    "end_address": end,
                    "memory_area": "rom_ram",
                },
            )
        except RuntimeError:
            pass
    return None, None, rejected_bank_hits


def _default_command() -> list[str]:
    return [
        "proot-distro",
        "login",
        "--bind",
        "/storage/emulated/0:/storage/emulated/0",
        "ubuntu",
        "--",
        "bash",
        "-lc",
        GEARSYSTEM_COMMAND,
    ]


def _runtime_failure_kind(error: Exception) -> str:
    if isinstance(error, json.JSONDecodeError):
        return "invalid-json"
    if isinstance(error, subprocess.TimeoutExpired):
        return "subprocess-timeout"
    if isinstance(error, OSError):
        return "process-io"
    if isinstance(error, ValueError):
        return "invalid-runtime-data"
    message = str(error)
    if message.startswith("Gearsystem frame step did not finish"):
        return "frame-step-timeout"
    if message.startswith("Gearsystem instruction step did not finish"):
        return "instruction-step-timeout"
    if "timed out" in message or "did not finish" in message:
        return "mcp-timeout"
    if message.startswith("MCP error:"):
        return "mcp-error"
    if message.startswith("Gearsystem tool error:"):
        return "tool-error"
    if "MCP tools missing" in message:
        return "required-tools"
    if "did not load the expected Game Gear ROM" in message:
        return "media-identity"
    if (
        "MCP response" in message
        or "tool response" in message
        or "tool payload" in message
    ):
        return "invalid-mcp-payload"
    if isinstance(error, RuntimeError):
        return "runtime-error"
    return "unexpected-exception"


def _runtime_failure_receipt(
    stage: str,
    error: Exception,
    client: McpStdioClient | None,
) -> dict[str, object]:
    if stage not in RUNTIME_FAILURE_STAGES:
        stage = "candidate-probe"
    method = client.last_tool_name if client is not None else None
    if method is None and client is not None:
        method = client.last_request_method
    failure_kind = _runtime_failure_kind(error)
    if failure_kind in {"frame-step-timeout", "instruction-step-timeout"}:
        method = "debug_get_status"
    if method is not None and (
        not method.replace("_", "").isalnum() or len(method) > 40
    ):
        method = None
    receipt: dict[str, object] = {
        "schema_version": 1,
        "failure_stage": stage,
        "failure_kind": failure_kind,
        "mcp_method": method,
    }
    validate_runtime_failure_receipt(receipt)
    return receipt


def validate_runtime_failure_receipt(receipt: dict[str, object]) -> None:
    if set(receipt) != {
        "schema_version",
        "failure_stage",
        "failure_kind",
        "mcp_method",
    }:
        raise ValueError("runtime failure receipt fields do not match")
    if receipt["schema_version"] != 1:
        raise ValueError("unexpected runtime failure receipt schema")
    if receipt["failure_stage"] not in RUNTIME_FAILURE_STAGES:
        raise ValueError("unexpected runtime failure stage")
    if receipt["failure_kind"] not in RUNTIME_FAILURE_KINDS:
        raise ValueError("unexpected runtime failure kind")
    method = receipt["mcp_method"]
    if method is not None and (
        not isinstance(method, str)
        or not method.replace("_", "").isalnum()
        or len(method) > 40
    ):
        raise ValueError("runtime failure MCP method is not a safe token")


def _write_runtime_failure_receipt(
    root: Path,
    receipt: dict[str, object],
) -> Path:
    validate_runtime_failure_receipt(receipt)
    path = root / LOCAL_FAILURE_REPORT
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rom", type=Path, default=DEFAULT_ROM)
    parser.add_argument("--trace-plan", type=Path, default=DEFAULT_TRACE_PLAN)
    parser.add_argument("--publish-safe-observation", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    failure_path = root / LOCAL_FAILURE_REPORT
    failure_path.unlink(missing_ok=True)
    rom_path = (root / args.rom).resolve() if not args.rom.is_absolute() else args.rom
    plan_path = (
        (root / args.trace_plan).resolve()
        if not args.trace_plan.is_absolute()
        else args.trace_plan
    )
    rom = rom_path.read_bytes()
    verify_target_identity(rom)
    target_sha256 = sha256_file(rom_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(plan, dict):
        raise ValueError("trace plan must be a JSON object")
    if plan.get("source_analysis_sha256") != target_sha256:
        raise ValueError("trace plan and local v5.1 ROM identities do not match")
    excluded_ranges = _prior_no_hit_ranges(root, target_sha256)
    candidate_groups = _runtime_candidate_groups(plan, excluded_ranges)
    planned_ranges = [
        mapping
        for group in candidate_groups
        for mapping in group["mappings"]
        if isinstance(mapping, dict)
    ]

    local_result: dict[str, object] = {
        "target_sha256": target_sha256,
        "trace_plan": str(plan_path),
        "rom": str(rom_path),
        "candidate_groups": candidate_groups,
        "planned_ranges": planned_ranges,
        "attempts": [],
    }
    if not candidate_groups:
        exhausted_ranges = [
            {
                "slot": slot,
                "expected_bank": bank,
                "logical_start": logical_start,
                "logical_end": logical_end,
            }
            for slot, bank, logical_start, logical_end in sorted(excluded_ranges)
        ]
        local_path = root / LOCAL_REPORT
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_result["candidate_search_exhausted"] = True
        local_path.write_text(
            json.dumps(local_result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        observation = build_runtime_observation(
            target_sha256=target_sha256,
            emulator_version="not-run",
            frames_per_slot=_frames_per_slot(),
            slots_attempted=sorted(
                {int(item["slot"]) for item in exhausted_ranges}
            ),
            breakpoint_ranges=exhausted_ranges,
            hit=None,
        )
        safe_path = write_runtime_observation(root, observation)
        print("SFKR ranked table candidates exhausted; renderer probe is next.")
        print(f"Local evidence: {local_path}")
        print(f"Safe observation: {safe_path}")
        return 0

    client: McpStdioClient | None = None
    slots_attempted: list[int] = []
    ranges_attempted: list[dict[str, int]] = []
    safe_hit: dict[str, object] | None = None
    emulator_version = "unknown"
    runtime_stage = "mcp-start"
    runtime_error: Exception | None = None
    try:
        client = McpStdioClient(_default_command())
        runtime_stage = "mcp-initialize"
        tools = client.initialize()
        missing = sorted(REQUIRED_TOOLS - tools)
        if missing:
            raise RuntimeError(f"Gearsystem MCP tools missing: {missing}")
        runtime_stage = "load-media"
        client.call("load_media", {"file_path": str(rom_path)})
        media = client.call("get_media_info")
        local_result["media"] = media
        runtime_stage = "media-identity"
        if (
            media.get("ready") is not True
            or media.get("is_game_gear") is not True
            or int(media.get("rom_size", 0)) != len(rom)
        ):
            raise RuntimeError("Gearsystem did not load the expected Game Gear ROM")
        emulator_version = str(media.get("emulator_version", "unknown"))
        runtime_stage = "trace-enable"
        # A full CPU trace formats every Z80 instruction. That makes a long
        # breakpoint route prohibitively slow in the S25U proot environment.
        # First locate a mapper-correct, non-executing range read without CPU
        # trace; a later bounded replay can trace only the confirmed window.
        client.call(
            "set_trace_log",
            {
                "enabled": False,
            },
        )
        for group in candidate_groups:
            watch = group["watch"]
            alignment_cluster = group["alignment_cluster"]
            assert isinstance(watch, dict)
            assert isinstance(alignment_cluster, list)
            mappings = group["mappings"]
            assert isinstance(mappings, list)
            for mapping in mappings:
                assert isinstance(mapping, dict)
                ranges_attempted.append(mapping)
                slot = int(mapping["slot"])
                if slot not in slots_attempted:
                    slots_attempted.append(slot)
                runtime_stage = "candidate-probe"
                hit, evidence, rejected_bank_hits = _probe_slot(client, mapping)
                attempt: dict[str, object] = {
                    "candidate_rank": int(group["rank"]),
                    "watch": watch,
                    "alignment_cluster": alignment_cluster,
                    "mapping": mapping,
                    "hit": hit,
                    "evidence": evidence,
                    "rejected_bank_hits": rejected_bank_hits,
                    "target_followup": None,
                }
                local_result["attempts"].append(attempt)
                if hit is not None:
                    found = _find_access(attempt)
                    if found is None:
                        attempt["target_followup"] = {
                            "status": "table-read-address-unresolved",
                            "candidates": [],
                            "matching_candidate": None,
                            "logical_access": None,
                            "trace_record": None,
                            "hit": None,
                            "evidence": None,
                            "events_seen": 0,
                        }
                        # The range breakpoint plus mapper match and execution
                        # exclusion are valid coarse read evidence. Preserve
                        # that hit and stop this expensive route; exact access
                        # recovery belongs to a short traced replay.
                        safe_hit = hit
                        break
                    else:
                        _, _, logical_access = found
                        physical_table_byte = (
                            int(watch["file_start"])
                            + logical_access
                            - int(hit["logical_start"])
                        )
                        candidates = _target_candidates(
                            rom,
                            {"selected_alignment_cluster": alignment_cluster},
                            physical_table_byte,
                        )
                        runtime_stage = "target-followup"
                        attempt["target_followup"] = _follow_target_read(
                            client, candidates
                        )
                    safe_hit = hit
                    break
            if safe_hit is not None:
                break
    except Exception as error:
        runtime_error = error
    finally:
        if client is not None:
            local_result["stderr_tail"] = list(client.stderr_tail)
            try:
                client.close()
            except Exception as close_error:
                if runtime_error is None:
                    runtime_stage = "mcp-close"
                    runtime_error = close_error

    if runtime_error is not None:
        receipt = _runtime_failure_receipt(runtime_stage, runtime_error, client)
        local_result["failure"] = receipt
        local_result["failure_detail"] = {
            "exception_type": type(runtime_error).__name__,
            "message": str(runtime_error),
        }
        local_path = root / LOCAL_REPORT
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(
            json.dumps(local_result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        receipt_path = _write_runtime_failure_receipt(root, receipt)
        print(
            "SFKR runtime probe failed: "
            f"{receipt['failure_stage']}/{receipt['failure_kind']}",
            file=sys.stderr,
        )
        print(f"Local failure receipt: {receipt_path}", file=sys.stderr)
        return 1

    local_path = root / LOCAL_REPORT
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local_result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    observation = build_runtime_observation(
        target_sha256=target_sha256,
        emulator_version=emulator_version,
        frames_per_slot=_frames_per_slot(),
        slots_attempted=slots_attempted,
        breakpoint_ranges=ranges_attempted,
        hit=safe_hit,
    )
    safe_path = write_runtime_observation(root, observation)
    print(
        "SFKR runtime observation: "
        + (
            f"read hit at PC 0x{safe_hit['pc_after']:04X}, slot {safe_hit['slot']}"
            if safe_hit is not None
            else "no read hit in the scripted intro window"
        )
    )
    print(f"Local evidence: {local_path}")
    print(f"Safe observation: {safe_path}")
    if args.publish_safe_observation:
        result = publish_runtime_observation(root, safe_path)
        print(f"Published runtime observation: {result['path']} @ {result['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
