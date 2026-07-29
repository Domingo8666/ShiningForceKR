#!/usr/bin/env python3
"""Run the safe S25U preparation and candidate-analysis pipeline in one command."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from .analyze_v5_1 import (
        EXPECTED_PATCH_SHA256,
        EXPECTED_PATCH_SIZE,
        EXPECTED_SOURCE_SHA256,
        EXPECTED_SOURCE_SIZE,
        make_report,
    )
    from .patch_io import apply_bps, sha256_bytes
    from .sfgfc_huffman import verified_overlay
    from .v5_1_consumer import (
        analyze_rom as analyze_consumer,
        to_korean_summary,
        to_markdown as consumer_to_markdown,
    )
    from .v5_1_engine import analyze_patch, to_markdown
    from .v5_1_trace_plan import (
        build_trace_plan,
        to_korean_summary as trace_to_korean_summary,
        to_markdown as trace_to_markdown,
    )
except ImportError:  # direct script execution
    from analyze_v5_1 import (
        EXPECTED_PATCH_SHA256,
        EXPECTED_PATCH_SIZE,
        EXPECTED_SOURCE_SHA256,
        EXPECTED_SOURCE_SIZE,
        make_report,
    )
    from patch_io import apply_bps, sha256_bytes
    from sfgfc_huffman import verified_overlay
    from v5_1_consumer import (
        analyze_rom as analyze_consumer,
        to_korean_summary,
        to_markdown as consumer_to_markdown,
    )
    from v5_1_engine import analyze_patch, to_markdown
    from v5_1_trace_plan import (
        build_trace_plan,
        to_korean_summary as trace_to_korean_summary,
        to_markdown as trace_to_markdown,
    )


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rom", type=Path, required=True, help="clean Japanese ROM on S25U")
    parser.add_argument(
        "--patch",
        type=Path,
        default=root / "patch" / "Final_Conflict_Japan_to_Korean_v5.1.bps",
    )
    parser.add_argument(
        "--english-ips",
        type=Path,
        default=root / "patch" / "fcpatch_070706.ips",
        help="optional verified English reference IPS",
    )
    parser.add_argument(
        "--output-rom",
        type=Path,
        default=root / "build" / "Final_Conflict_Korean_v5.1.gg",
    )
    parser.add_argument(
        "--verification-report",
        type=Path,
        default=root / "reports" / "v5_1_mobile_verification.md",
    )
    parser.add_argument(
        "--engine-report",
        type=Path,
        default=root / "reports" / "v5_1_engine_report.md",
    )
    parser.add_argument(
        "--consumer-report",
        type=Path,
        default=root / "reports" / "v5_1_script_lookup_candidates.md",
    )
    parser.add_argument(
        "--trace-plan-report",
        type=Path,
        default=root / "reports" / "v5_1_emucap_trace_plan.md",
    )
    parser.add_argument(
        "--trace-plan-json",
        type=Path,
        default=root / "reports" / "v5_1_emucap_trace_plan.json",
    )
    parser.add_argument(
        "--summary-report",
        type=Path,
        default=root / "reports" / "NEXT_STEP.txt",
    )
    parser.add_argument(
        "--status-json",
        type=Path,
        default=root / "reports" / "pipeline_status.json",
    )
    parser.add_argument(
        "--no-rom-output",
        action="store_true",
        help="validate in memory without writing the patched ROM",
    )
    args = parser.parse_args()

    source_path = args.rom.resolve()
    output_path = args.output_rom.resolve()
    if not args.no_rom_output and source_path == output_path:
        raise SystemExit("refusing to overwrite the clean source ROM")

    source = args.rom.read_bytes()
    patch = args.patch.read_bytes()
    if len(source) != EXPECTED_SOURCE_SIZE or sha256_bytes(source) != EXPECTED_SOURCE_SHA256:
        raise SystemExit("clean ROM identity mismatch; refusing to continue")
    if len(patch) != EXPECTED_PATCH_SIZE or sha256_bytes(patch) != EXPECTED_PATCH_SHA256:
        raise SystemExit("v5.1 BPS identity mismatch; refusing to continue")

    engine = analyze_patch(patch)
    target = apply_bps(source, patch)
    target_sha256 = sha256_bytes(target)
    consumer = analyze_consumer(target)
    trace_plan = build_trace_plan(target, consumer)

    if not args.no_rom_output:
        args.output_rom.parent.mkdir(parents=True, exist_ok=True)
        args.output_rom.write_bytes(target)

    _write_text(args.verification_report, make_report(source, target, patch, args.rom))
    _write_text(args.engine_report, to_markdown(engine))
    _write_text(args.consumer_report, consumer_to_markdown(consumer))
    _write_text(args.trace_plan_report, trace_to_markdown(trace_plan))
    _write_text(
        args.trace_plan_json,
        json.dumps(trace_plan, ensure_ascii=False, indent=2) + "\n",
    )
    _write_text(
        args.summary_report,
        to_korean_summary(consumer) + "\n" + trace_to_korean_summary(trace_plan),
    )

    english: dict[str, object]
    if args.english_ips.exists():
        _, _, trees = verified_overlay(args.english_ips)
        english = {
            "status": "pass",
            "path": args.english_ips.name,
            "populated_trees": len(trees),
            "empty_trees": 256 - len(trees),
        }
    else:
        english = {
            "status": "skipped",
            "reason": "verified English IPS not present; run tools/fetch_fc_english_patch.py",
        }

    pointer_tables = consumer["pointer_table_candidates"]
    assert isinstance(pointer_tables, dict)
    status = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": {
            "name": args.rom.name,
            "size": len(source),
            "sha256": sha256_bytes(source),
        },
        "target": {
            "written": not args.no_rom_output,
            "name": None if args.no_rom_output else args.output_rom.name,
            "size": len(target),
            "sha256": target_sha256,
            "crc32": engine["patch"]["target_crc32"],
        },
        "checks": {
            "clean_source_identity": "pass",
            "bps_identity_and_crc": "pass",
            "korean_huffman_vector": "pass",
            "korean_font_runtime": "pass",
            "english_reference": english,
            "script_lookup_candidate_scan": "pass",
            "script_consumer_cross_reference_plan": "pass",
            "script_lookup_runtime_consumer": "investigating",
            "token_semantics": "investigating",
            "emulator_cold_boot": "not_run",
        },
        "script_lookup_candidates": {
            "triplet_runs_found": pointer_tables["triplet_runs_found"],
            "pair_runs_found": pointer_tables["pair_runs_found"],
            "report": args.consumer_report.name,
        },
        "runtime_trace_plan": {
            "status": trace_plan["status"],
            "schema_version": trace_plan["schema_version"],
            "selected_file_offset": (
                None
                if trace_plan["selected_hypothesis"] is None
                else trace_plan["selected_hypothesis"]["file_offset"]
            ),
            "selected_mapper_coupled_pointer_loads": (
                0
                if trace_plan["selected_hypothesis"] is None
                else trace_plan["selected_hypothesis"][
                    "mapper_coupled_pointer_load_count"
                ]
            ),
            "report": args.trace_plan_report.name,
            "json": args.trace_plan_json.name,
        },
        "translation_build_eligible": False,
        "next_checkpoint": (
            "trace the highest-ranked lookup candidate with mapper state in the emulator"
        ),
    }
    _write_text(args.status_json, json.dumps(status, ensure_ascii=False, indent=2) + "\n")

    print("S25U pipeline and script-candidate scan passed.")
    if args.no_rom_output:
        print("Patched ROM was validated in memory and not written.")
    else:
        print(f"Built local ROM: {args.output_rom}")
    print(f"Readable summary: {args.summary_report}")
    print(f"Script candidate report: {args.consumer_report}")
    print(f"emucap trace plan: {args.trace_plan_report}")
    print(f"Pipeline status: {args.status_json}")
    print("Open in My Files: Internal storage > ShiningForceKR > reports > NEXT_STEP.txt")
    print("Runtime consumer proof remains pending; no translation was marked build-eligible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
