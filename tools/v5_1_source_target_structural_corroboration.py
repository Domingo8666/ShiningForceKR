#!/usr/bin/env python3
"""Corroborate an anchored source/target projection with local structure.

The source speaker labels and target control symbols are copyrighted or
reverse-engineering payload, so every row and signature stays in ignored local
reports.  The publishable receipt contains fixed-schema counts only.  This
evidence can strengthen or weaken a single-anchor projection, but it never
approves translations or completes source pairing by itself.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .v5_1_renderer_output_trace import _load_json_object
    from .v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
        PUBLISH_RELATIVE_PATH as PROJECTION_PATH,
        validate_source_target_section_projection,
    )
except ImportError:  # pragma: no cover - direct script execution
    from patch_io import sha256_file
    from v5_1_renderer_output_trace import _load_json_object
    from v5_1_source_target_section_projection import (
        LOCAL_REPORT_PATH as LOCAL_PROJECTION_PATH,
        PUBLISH_RELATIVE_PATH as PROJECTION_PATH,
        validate_source_target_section_projection,
    )


ARTIFACT_KIND = (
    "sanitized-v5-1-source-target-structural-corroboration"
)
SCHEMA_VERSION = 1
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/"
    "v5_1_latest_source_target_structural_corroboration.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_source_target_structural_corroboration.json"
)

COUNT_KEYS = {
    "pair_count",
    "adjacent_pair_boundary_count",
    "speaker_labeled_pair_count",
    "narration_pair_count",
    "pair_with_target_control_count",
    "target_control_occurrence_count",
    "distinct_target_control_signature_count",
    "source_speaker_transition_count",
    "target_control_signature_transition_count",
    "coincident_transition_count",
    "transition_agreement_count",
    "speaker_transition_with_target_control_count",
    "speaker_transition_without_target_control_count",
    "speaker_stay_with_target_control_count",
    "speaker_stay_without_target_control_count",
    "repeat_supported_signature_count",
    "speaker_pure_repeat_supported_signature_count",
    "speaker_pure_repeat_supported_pair_count",
    "speaker_pure_repeat_supported_speaker_count",
}

SAFE_FIELDS = {
    "artifact_kind",
    "schema_version",
    "status",
    "target_sha256",
    "source_section_projection_sha256",
    "local_analysis_sha256",
    "captured_utc",
    "corroboration",
    "candidate_pairing_only",
    "human_review_required",
    "hancharacter_contract_mode",
    "local_payload_policy",
    "source_pairing_complete",
    "speaker_assignment_complete",
    "translation_build_eligible",
    "next_checkpoint",
}


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _signature_key(symbols: tuple[int, ...]) -> str:
    encoded = json.dumps(
        symbols,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def analyze_structural_corroboration(
    pairs: list[dict[str, object]],
) -> tuple[dict[str, int], dict[str, object]]:
    if not pairs:
        raise ValueError("structural corroboration pairs are missing")

    rows: list[dict[str, object]] = []
    signature_speakers: dict[str, Counter[str]] = defaultdict(Counter)
    signature_positions: dict[str, list[int]] = defaultdict(list)
    signature_symbols: dict[str, tuple[int, ...]] = {}
    control_occurrences = 0
    speaker_labeled = 0
    narration = 0

    for expected_index, pair in enumerate(pairs):
        if not isinstance(pair, dict):
            raise ValueError("structural corroboration pair is invalid")
        pair_index = pair.get("pair_index")
        speaker = pair.get("speaker")
        target_record = pair.get("target_record")
        if pair_index != expected_index:
            raise ValueError("structural corroboration pair order is invalid")
        if speaker is None:
            narration += 1
            speaker_key = "__NARRATION__"
        elif isinstance(speaker, str) and speaker:
            speaker_labeled += 1
            speaker_key = speaker
        else:
            raise ValueError("structural corroboration speaker is invalid")
        if not isinstance(target_record, dict):
            raise ValueError("structural corroboration target record is invalid")
        tokens = target_record.get("tokens")
        if not isinstance(tokens, list):
            raise ValueError("structural corroboration target tokens are missing")

        controls: list[int] = []
        for token in tokens:
            if not isinstance(token, dict):
                raise ValueError("structural corroboration target token is invalid")
            kind = token.get("kind")
            if kind == "control":
                symbol = token.get("symbol")
                if (
                    not isinstance(symbol, int)
                    or isinstance(symbol, bool)
                    or not 0 <= symbol <= 0xFF
                ):
                    raise ValueError(
                        "structural corroboration control symbol is invalid"
                    )
                controls.append(symbol)
            elif kind not in {"glyph", "page-select", "terminator"}:
                raise ValueError(
                    "structural corroboration target token kind is invalid"
                )

        symbols = tuple(controls)
        signature = _signature_key(symbols)
        signature_symbols[signature] = symbols
        control_occurrences += len(symbols)
        signature_positions[signature].append(expected_index)
        if symbols and speaker is not None:
            signature_speakers[signature][speaker_key] += 1
        rows.append(
            {
                "pair_index": expected_index,
                "speaker": speaker,
                "control_symbols": list(symbols),
                "control_signature": signature,
                "has_target_control": bool(symbols),
            }
        )

    source_transitions = 0
    target_transitions = 0
    coincident_transitions = 0
    transition_agreements = 0
    speaker_transition_with_control = 0
    speaker_transition_without_control = 0
    speaker_stay_with_control = 0
    speaker_stay_without_control = 0

    for index in range(1, len(rows)):
        previous = rows[index - 1]
        current = rows[index]
        speaker_changed = current["speaker"] != previous["speaker"]
        signature_changed = (
            current["control_signature"] != previous["control_signature"]
        )
        has_control = bool(current["has_target_control"])
        source_transitions += int(speaker_changed)
        target_transitions += int(signature_changed)
        coincident_transitions += int(speaker_changed and signature_changed)
        transition_agreements += int(speaker_changed == signature_changed)
        if speaker_changed and has_control:
            speaker_transition_with_control += 1
        elif speaker_changed:
            speaker_transition_without_control += 1
        elif has_control:
            speaker_stay_with_control += 1
        else:
            speaker_stay_without_control += 1
        current["speaker_changed"] = speaker_changed
        current["control_signature_changed"] = signature_changed

    rows[0]["speaker_changed"] = None
    rows[0]["control_signature_changed"] = None

    repeat_supported: list[str] = []
    pure_supported: list[str] = []
    pure_speakers: set[str] = set()
    pure_pair_count = 0
    for signature, positions in signature_positions.items():
        if (
            signature_symbols[signature]
            and len(positions) >= 2
            and positions[-1] - positions[0] >= 2
        ):
            repeat_supported.append(signature)
            speakers = signature_speakers.get(signature, Counter())
            if len(speakers) == 1 and sum(speakers.values()) >= 2:
                pure_supported.append(signature)
                pure_speakers.update(speakers)
                pure_pair_count += sum(speakers.values())

    counts = {
        "pair_count": len(rows),
        "adjacent_pair_boundary_count": max(0, len(rows) - 1),
        "speaker_labeled_pair_count": speaker_labeled,
        "narration_pair_count": narration,
        "pair_with_target_control_count": sum(
            int(bool(row["has_target_control"])) for row in rows
        ),
        "target_control_occurrence_count": control_occurrences,
        "distinct_target_control_signature_count": len(signature_positions),
        "source_speaker_transition_count": source_transitions,
        "target_control_signature_transition_count": target_transitions,
        "coincident_transition_count": coincident_transitions,
        "transition_agreement_count": transition_agreements,
        "speaker_transition_with_target_control_count":
            speaker_transition_with_control,
        "speaker_transition_without_target_control_count":
            speaker_transition_without_control,
        "speaker_stay_with_target_control_count": speaker_stay_with_control,
        "speaker_stay_without_target_control_count": speaker_stay_without_control,
        "repeat_supported_signature_count": len(repeat_supported),
        "speaker_pure_repeat_supported_signature_count": len(pure_supported),
        "speaker_pure_repeat_supported_pair_count": pure_pair_count,
        "speaker_pure_repeat_supported_speaker_count": len(pure_speakers),
    }
    boundary_count = counts["adjacent_pair_boundary_count"]
    strong = (
        boundary_count >= 5
        and source_transitions >= 2
        and target_transitions >= 2
        and coincident_transitions * 2 >= source_transitions
        and transition_agreements * 10 >= boundary_count * 7
        and len(pure_supported) >= 1
    )
    return counts, {
        "rows": rows,
        "repeat_supported_signatures": repeat_supported,
        "speaker_pure_repeat_supported_signatures": pure_supported,
        "structural_corroboration_found": strong,
        "candidate_evidence_only": True,
        "publication_policy": (
            "never-publish-speakers-control-symbols-signatures-rows-or-text"
        ),
    }


def build_source_target_structural_corroboration(
    *,
    target_sha256: str,
    source_section_projection_sha256: str,
    local_analysis_sha256: str,
    corroboration: dict[str, int],
    structural_corroboration_found: bool,
    captured_utc: str,
) -> dict[str, object]:
    status = (
        "structural-corroboration-found"
        if structural_corroboration_found
        else "structural-corroboration-insufficient"
    )
    value: dict[str, object] = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "target_sha256": target_sha256,
        "source_section_projection_sha256":
            source_section_projection_sha256,
        "local_analysis_sha256": local_analysis_sha256,
        "captured_utc": captured_utc,
        "corroboration": corroboration,
        "candidate_pairing_only": True,
        "human_review_required": True,
        "hancharacter_contract_mode": "translator_declared",
        "local_payload_policy": (
            "speakers-control-symbols-signatures-rows-and-text-local-only"
        ),
        "source_pairing_complete": False,
        "speaker_assignment_complete": False,
        "translation_build_eligible": False,
        "next_checkpoint": "capture-bounded-runtime-sequence",
    }
    validate_source_target_structural_corroboration(value)
    return value


def validate_source_target_structural_corroboration(
    value: dict[str, object],
) -> None:
    if set(value) != SAFE_FIELDS:
        raise ValueError(
            "structural corroboration fields do not match"
        )
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"]
        not in {
            "structural-corroboration-found",
            "structural-corroboration-insufficient",
        }
        or not _is_sha256(value["target_sha256"])
        or not _is_sha256(value["source_section_projection_sha256"])
        or not _is_sha256(value["local_analysis_sha256"])
    ):
        raise ValueError("structural corroboration identity is invalid")

    try:
        timestamp = datetime.fromisoformat(
            str(value["captured_utc"]).replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            "structural corroboration timestamp is invalid"
        ) from error
    if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
        raise ValueError("structural corroboration timestamp needs UTC")

    counts = value["corroboration"]
    if not isinstance(counts, dict) or set(counts) != COUNT_KEYS:
        raise ValueError("structural corroboration counts do not match")
    pair_count = counts.get("pair_count")
    if not _bounded_int(pair_count, 1, 100000):
        raise ValueError("structural corroboration pair count is invalid")
    assert isinstance(pair_count, int)
    for key, count in counts.items():
        if not _bounded_int(count, 0, max(1, pair_count * 256)):
            raise ValueError(
                f"structural corroboration {key} is invalid"
            )

    boundary_count = int(counts["adjacent_pair_boundary_count"])
    if (
        boundary_count != pair_count - 1
        or counts["speaker_labeled_pair_count"]
        + counts["narration_pair_count"]
        != pair_count
        or counts["pair_with_target_control_count"] > pair_count
        or counts["source_speaker_transition_count"] > boundary_count
        or counts["target_control_signature_transition_count"]
        > boundary_count
        or counts["coincident_transition_count"]
        > min(
            counts["source_speaker_transition_count"],
            counts["target_control_signature_transition_count"],
        )
        or counts["transition_agreement_count"] > boundary_count
        or counts["speaker_transition_with_target_control_count"]
        + counts["speaker_transition_without_target_control_count"]
        != counts["source_speaker_transition_count"]
        or counts["speaker_stay_with_target_control_count"]
        + counts["speaker_stay_without_target_control_count"]
        != boundary_count - counts["source_speaker_transition_count"]
        or counts["speaker_pure_repeat_supported_signature_count"]
        > counts["repeat_supported_signature_count"]
        or counts["speaker_pure_repeat_supported_pair_count"] > pair_count
        or counts["speaker_pure_repeat_supported_speaker_count"] > pair_count
    ):
        raise ValueError(
            "structural corroboration aggregates are inconsistent"
        )

    if (
        value["candidate_pairing_only"] is not True
        or value["human_review_required"] is not True
        or value["hancharacter_contract_mode"] != "translator_declared"
        or value["local_payload_policy"]
        != "speakers-control-symbols-signatures-rows-and-text-local-only"
        or value["source_pairing_complete"] is not False
        or value["speaker_assignment_complete"] is not False
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"] != "capture-bounded-runtime-sequence"
    ):
        raise ValueError(
            "structural corroboration policy is invalid"
        )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    args = parser.parse_args()
    projection_path = root / PROJECTION_PATH
    local_projection_path = root / LOCAL_PROJECTION_PATH
    if not projection_path.is_file() or not local_projection_path.is_file():
        if args.if_ready:
            print("Source-target structural corroboration is not ready")
            return 0
        raise SystemExit(
            "source-target structural corroboration input is missing"
        )

    projection = _load_json_object(projection_path)
    local_projection = _load_json_object(local_projection_path)
    validate_source_target_section_projection(projection)
    if (
        local_projection.get("target_sha256")
        != projection["target_sha256"]
        or sha256_file(local_projection_path)
        != projection["local_projection_sha256"]
    ):
        raise ValueError(
            "structural corroboration projection identity disagrees"
        )
    local_payload = local_projection.get("projection")
    if not isinstance(local_payload, dict):
        raise ValueError(
            "structural corroboration local projection is missing"
        )
    pairs = local_payload.get("pairs")
    if not isinstance(pairs, list):
        raise ValueError("structural corroboration pairs are missing")

    counts, local_analysis = analyze_structural_corroboration(pairs)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local = {
        "artifact_kind":
            "local-v5-1-source-target-structural-corroboration",
        "schema_version": SCHEMA_VERSION,
        "target_sha256": projection["target_sha256"],
        "source_section_projection_sha256":
            sha256_file(projection_path),
        "captured_utc": captured_utc,
        "corroboration": counts,
        "analysis": local_analysis,
        "publication_policy": (
            "never-publish-speakers-control-symbols-signatures-rows-or-text"
        ),
    }
    local_path = root / LOCAL_REPORT_PATH
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    safe = build_source_target_structural_corroboration(
        target_sha256=str(projection["target_sha256"]),
        source_section_projection_sha256=sha256_file(projection_path),
        local_analysis_sha256=sha256_file(local_path),
        corroboration=counts,
        structural_corroboration_found=bool(
            local_analysis["structural_corroboration_found"]
        ),
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR source-target structural corroboration: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
