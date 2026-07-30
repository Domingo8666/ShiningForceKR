#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

source_rom=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-rom)
      if [ "$#" -lt 2 ]; then
        echo "--source-rom requires a path" >&2
        exit 2
      fi
      source_rom="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

stage_status=0
diagnostic_trigger=manual
failure_report="$root/reports/local/v5_1_runtime_failure.json"
test_patch_failure_token="$root/reports/local/v5_1_test_patch_failure_token.txt"
next_step_file="$root/reports/NEXT_STEP.txt"
rm -f "$failure_report" "$test_patch_failure_token"

write_next_step() {
  next_step_temp="$next_step_file.tmp"
  mkdir -p "$(dirname "$next_step_file")"
  printf '%s\n' "$1" >"$next_step_temp"
  mv "$next_step_temp" "$next_step_file"
}

decoder_selection_ready() {
  selection_ready="$(
    python -c 'import json; from pathlib import Path; from tools.patch_io import sha256_file; from tools.v5_1_decoder_stream_resolution import validate_decoder_stream_resolution; path=Path("analysis/device/v5_1_latest_decoder_stream_resolution.json"); target=Path("build/Final_Conflict_Korean_v5.1.gg"); value=json.loads(path.read_text(encoding="utf-8")); validate_decoder_stream_resolution(value); print("yes" if target.is_file() and value.get("target_sha256") == sha256_file(target) and value.get("consumer_evidence_confirmed") is True and isinstance(value.get("selected_stream_index"), int) else "no")' 2>/dev/null || true
  )"
  [ "$selection_ready" = "yes" ]
}

group_selection_ready() {
  group_ready="$(
    python -c 'import json; from pathlib import Path; from tools.patch_io import sha256_file; from tools.v5_1_test_display_capture import validate_display_capture; path=Path("analysis/evidence/v5_1_confirmed_group_capture.json"); target=Path("build/Final_Conflict_Korean_v5.1.gg"); value=json.loads(path.read_text(encoding="utf-8")); validate_display_capture(value); group=value.get("group_entry"); print("yes" if target.is_file() and value.get("baseline_target_sha256") == sha256_file(target) and isinstance(group, dict) and group.get("status") == "resolved" and group.get("prefix_roundtrip_exact") is True else "no")' 2>/dev/null || true
  )"
  [ "$group_ready" = "yes" ]
}

decoder_register_trace_needed() {
  trace_needed="$(
    python -c 'from pathlib import Path; from tools.v5_1_decoder_register_trace import decoder_register_trace_needed; print("yes" if decoder_register_trace_needed(Path(".")) else "no")' 2>/dev/null || true
  )"
  [ "$trace_needed" = "yes" ]
}

display_comparison_ready() {
  comparison_ready="$(
    python -c 'import json; from pathlib import Path; from tools.v5_1_test_display_comparison import validate_display_comparison; comparison_path=Path("analysis/device/v5_1_latest_display_comparison.json"); build_path=Path("reports/local/v5_1_test_patch_build.json"); comparison=json.loads(comparison_path.read_text(encoding="utf-8")); build=json.loads(build_path.read_text(encoding="utf-8")); validate_display_comparison(comparison); print("yes" if comparison.get("baseline_target_sha256") == build.get("baseline_target_sha256") and comparison.get("test_target_sha256") == build.get("test_target_sha256") else "no")' 2>/dev/null || true
  )"
  [ "$comparison_ready" = "yes" ]
}

run_display_capture() {
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 15s 180s \
      python tools/v5_1_test_display_capture.py --if-ready
  else
    python tools/v5_1_test_display_capture.py --if-ready
  fi
}

visible_font_catalog_ready() {
  python -c 'import json; from pathlib import Path; path=Path("analysis/local/v5_1_font_catalog.json"); value=json.loads(path.read_text(encoding="utf-8")); print("yes" if value.get("artifact_kind") == "local-v5-1-galmuri7-font-catalog" and value.get("status") == "verified-static-local-analysis" and isinstance(value.get("entries"), list) and bool(value["entries"]) else "no")' 2>/dev/null || true
}

prepare_visible_font_catalog() {
  if [ "$(visible_font_catalog_ready)" = "yes" ]; then
    return 0
  fi
  python tools/fetch_galmuri7_bdf.py --force &&
    python tools/v5_1_font_catalog.py &&
    [ "$(visible_font_catalog_ready)" = "yes" ]
}

record_stage_failure() {
  python tools/v5_1_runtime_stage_failure.py \
    --stage "$1" \
    --if-missing >/dev/null 2>&1 || true
}

write_next_step \
  "새 후보를 자동 검사하고 있습니다. 지금 사용자가 할 일은 없습니다."

bash tools/setup_s25u_gearsystem.sh
setup_status=$?
if [ "$setup_status" -ne 0 ]; then
  stage_status="$setup_status"
  diagnostic_trigger=setup
else
  if decoder_selection_ready || group_selection_ready; then
    echo "SFKR runtime stage: using the confirmed decoder stream."
  else
    python tools/run_s25u_runtime_probe.py
    probe_status=$?
    if [ "$probe_status" -ne 0 ]; then
      stage_status="$probe_status"
      diagnostic_trigger=probe
      record_stage_failure runtime-probe
    else
      python tools/v5_1_runtime_hit_resolver.py
      resolver_status=$?
      if [ "$resolver_status" -ne 0 ]; then
        stage_status="$resolver_status"
        diagnostic_trigger=probe
        record_stage_failure runtime-hit-resolver
      else
        python tools/run_s25u_renderer_probe.py --if-needed
        renderer_probe_status=$?
        if [ "$renderer_probe_status" -ne 0 ]; then
          stage_status="$renderer_probe_status"
          diagnostic_trigger=probe
          record_stage_failure renderer-probe
        else
          python tools/v5_1_decoder_stream_resolution.py
          stream_resolver_status=$?
          if [ "$stream_resolver_status" -ne 0 ]; then
            stage_status="$stream_resolver_status"
            diagnostic_trigger=probe
            record_stage_failure decoder-stream-resolution
          else
            python tools/run_s25u_route_capture.py --if-needed
            route_capture_status=$?
            if [ "$route_capture_status" -ne 0 ]; then
              stage_status="$route_capture_status"
              diagnostic_trigger=probe
              record_stage_failure route-capture
            fi
          fi
        fi
      fi
    fi
  fi

  if [ "$stage_status" -eq 0 ] && decoder_register_trace_needed; then
    python tools/v5_1_decoder_register_trace.py
    register_trace_status=$?
    if [ "$register_trace_status" -ne 0 ]; then
      stage_status="$register_trace_status"
      diagnostic_trigger=probe
      record_stage_failure decoder-register-trace
    fi
  fi

  if [ "$stage_status" -eq 0 ] && [ -n "$source_rom" ]; then
    comparison_attempt=1
    comparison_attempt_limit=8
    while [ "$comparison_attempt" -le "$comparison_attempt_limit" ]; do
      if ! decoder_selection_ready && ! group_selection_ready; then
        break
      fi

      rm -f \
        build/Final_Conflict_Korean_test_phrase.gg \
        build/Final_Conflict_Korean_test_phrase_overlay.ips \
        reports/local/v5_1_test_patch_build.json
      python tools/v5_1_test_patch.py \
        --source-rom "$source_rom" \
        --if-ready
      test_build_status=$?
      if [ "$test_build_status" -ne 0 ]; then
        stage_status="$test_build_status"
        diagnostic_trigger=probe
        test_patch_failure_stage="test-patch"
        if [ -f "$test_patch_failure_token" ]; then
          candidate_failure_stage="$(
            tr -d '\r\n' <"$test_patch_failure_token"
          )"
          case "$candidate_failure_stage" in
            test-patch-fixed-count-roundtrip|\
            test-patch-fixed-count-read-range|\
            test-patch-no-marker-candidate|\
            test-patch-marker-encoding|\
            test-patch-marker-roundtrip)
              test_patch_failure_stage="$candidate_failure_stage"
              ;;
          esac
        fi
        record_stage_failure "$test_patch_failure_stage"
        break
      fi
      if [ ! -f build/Final_Conflict_Korean_test_phrase.gg ] || \
        [ ! -f reports/local/v5_1_test_patch_build.json ]; then
        stage_status=1
        diagnostic_trigger=probe
        record_stage_failure test-patch
        break
      fi

      run_display_capture
      display_capture_status=$?
      if [ "$display_capture_status" -ne 0 ]; then
        stage_status="$display_capture_status"
        diagnostic_trigger=probe
        record_stage_failure test-display-capture
        break
      fi

      if ! display_comparison_ready; then
        python tools/v5_1_runtime_bundle.py --publish
        progress_publish_status=$?
        if [ "$progress_publish_status" -ne 0 ]; then
          stage_status="$progress_publish_status"
          diagnostic_trigger=probe
          record_stage_failure display-capture-safe-publish
          break
        fi
        run_display_capture
        display_capture_status=$?
        if [ "$display_capture_status" -ne 0 ]; then
          stage_status="$display_capture_status"
          diagnostic_trigger=probe
          record_stage_failure test-display-capture
          break
        fi
      fi

      comparison_result="$(
        python tools/v5_1_test_display_comparison.py --result-only
      )"
      comparison_status=$?
      if [ "$comparison_status" -ne 0 ]; then
        stage_status="$comparison_status"
        diagnostic_trigger=probe
        record_stage_failure display-comparison
        break
      fi
      if [ "$comparison_result" != "no-visible-pixel-change" ] && \
        [ "$comparison_result" != "technical-marker-absent-auto-rejected" ]; then
        break
      fi
      fixed_block_probe="$(
        python -c 'import json; from pathlib import Path; path=Path("reports/local/v5_1_test_patch_build.json"); value=json.loads(path.read_text(encoding="utf-8")); entry=value.get("runtime_entry"); print("yes" if isinstance(entry, dict) and (entry.get("kind") == "runtime-decoder-block" or entry.get("kind") == "runtime-length-prefixed-entry") else "no")' 2>/dev/null || true
      )"
      if [ "$fixed_block_probe" = "yes" ]; then
        break
      fi

      python tools/v5_1_decoder_stream_resolution.py
      stream_resolver_status=$?
      if [ "$stream_resolver_status" -ne 0 ]; then
        stage_status="$stream_resolver_status"
        diagnostic_trigger=probe
        record_stage_failure decoder-stream-resolution
        break
      fi
      comparison_attempt=$((comparison_attempt + 1))
    done
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_visible_entry_proof.py --if-ready
    visible_entry_status=$?
    if [ "$visible_entry_status" -ne 0 ]; then
      stage_status="$visible_entry_status"
      diagnostic_trigger=probe
      record_stage_failure visible-entry-proof
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_poc_expansion_proof.py --if-ready
    expansion_proof_status=$?
    if [ "$expansion_proof_status" -ne 0 ]; then
      stage_status="$expansion_proof_status"
      diagnostic_trigger=probe
      record_stage_failure display-comparison-artifact
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_visible_script_record.py --if-ready
    visible_script_status=$?
    if [ "$visible_script_status" -ne 0 ]; then
      stage_status="$visible_script_status"
      diagnostic_trigger=probe
      record_stage_failure display-comparison-artifact
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_renderer_output_trace.py --if-ready
    renderer_output_trace_status=$?
    if [ "$renderer_output_trace_status" -ne 0 ]; then
      stage_status="$renderer_output_trace_status"
      diagnostic_trigger=probe
      record_stage_failure renderer-output-trace
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    if python -c 'import json; from pathlib import Path; from tools.v5_1_renderer_output_trace import validate_renderer_output_trace; path=Path("analysis/device/v5_1_latest_renderer_output_trace.json"); value=json.loads(path.read_text(encoding="utf-8")); validate_renderer_output_trace(value); print("yes" if value.get("consumer_chain_confirmed") is True else "no")' 2>/dev/null |
      grep -qx yes; then
      prepare_visible_font_catalog
      font_catalog_status=$?
      if [ "$font_catalog_status" -ne 0 ]; then
        stage_status="$font_catalog_status"
        diagnostic_trigger=probe
        record_stage_failure visible-unicode-mapping
      fi
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_visible_unicode_mapping.py --if-ready
    visible_unicode_status=$?
    if [ "$visible_unicode_status" -ne 0 ]; then
      stage_status="$visible_unicode_status"
      diagnostic_trigger=probe
      record_stage_failure visible-unicode-mapping
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_initial_font_page_trace.py --if-ready
    initial_font_page_status=$?
    if [ "$initial_font_page_status" -ne 0 ]; then
      stage_status="$initial_font_page_status"
      diagnostic_trigger=probe
      record_stage_failure initial-font-page-trace
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_font_transfer_source.py --if-ready
    font_transfer_source_status=$?
    if [ "$font_transfer_source_status" -ne 0 ]; then
      stage_status="$font_transfer_source_status"
      diagnostic_trigger=probe
      record_stage_failure font-transfer-source
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_confirmed_group_extract.py --if-ready
    confirmed_group_extract_status=$?
    if [ "$confirmed_group_extract_status" -ne 0 ]; then
      stage_status="$confirmed_group_extract_status"
      diagnostic_trigger=probe
      record_stage_failure confirmed-group-extract
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_target_group_usage.py --if-ready
    target_group_usage_status=$?
    if [ "$target_group_usage_status" -ne 0 ]; then
      stage_status="$target_group_usage_status"
      diagnostic_trigger=probe
      record_stage_failure target-group-usage
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_target_group_stream_map.py --if-ready
    target_group_stream_map_status=$?
    if [ "$target_group_stream_map_status" -ne 0 ]; then
      stage_status="$target_group_stream_map_status"
      diagnostic_trigger=probe
      record_stage_failure target-group-stream-map
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_target_group_population.py --if-ready
    target_group_population_status=$?
    if [ "$target_group_population_status" -ne 0 ]; then
      stage_status="$target_group_population_status"
      diagnostic_trigger=probe
      record_stage_failure target-group-population
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_target_group_population_decode.py --if-ready
    target_group_population_decode_status=$?
    if [ "$target_group_population_decode_status" -ne 0 ]; then
      stage_status="$target_group_population_decode_status"
      diagnostic_trigger=probe
      record_stage_failure target-group-population-decode
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_target_group_expanded_glyphs.py --if-ready
    target_group_expanded_glyphs_status=$?
    if [ "$target_group_expanded_glyphs_status" -ne 0 ]; then
      stage_status="$target_group_expanded_glyphs_status"
      diagnostic_trigger=probe
      record_stage_failure target-group-expanded-glyphs
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_target_group_expanded_corpus.py --if-ready
    target_group_expanded_corpus_status=$?
    if [ "$target_group_expanded_corpus_status" -ne 0 ]; then
      stage_status="$target_group_expanded_corpus_status"
      diagnostic_trigger=probe
      record_stage_failure target-group-expanded-corpus
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_decoder_caller_resolution.py --if-ready
    decoder_caller_resolution_status=$?
    if [ "$decoder_caller_resolution_status" -ne 0 ]; then
      stage_status="$decoder_caller_resolution_status"
      diagnostic_trigger=probe
      record_stage_failure decoder-caller-resolution
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_group_context_resolution.py --if-ready
    group_context_resolution_status=$?
    if [ "$group_context_resolution_status" -ne 0 ]; then
      stage_status="$group_context_resolution_status"
      diagnostic_trigger=probe
      record_stage_failure group-context-resolution
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_group_runtime_context.py --if-ready
    group_runtime_context_status=$?
    if [ "$group_runtime_context_status" -ne 0 ]; then
      stage_status="$group_runtime_context_status"
      diagnostic_trigger=probe
      record_stage_failure group-runtime-context
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    if [ -n "$source_rom" ]; then
      python tools/v5_1_group_source_delta.py \
        --source-rom "$source_rom" \
        --if-ready
      group_source_delta_status=$?
      if [ "$group_source_delta_status" -ne 0 ]; then
        stage_status="$group_source_delta_status"
        diagnostic_trigger=probe
        record_stage_failure group-source-delta
      fi
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    if [ -n "$source_rom" ]; then
      python tools/v5_1_source_huffman_locator.py \
        --source-rom "$source_rom" \
        --if-ready
      source_huffman_locator_status=$?
      if [ "$source_huffman_locator_status" -ne 0 ]; then
        stage_status="$source_huffman_locator_status"
        diagnostic_trigger=probe
        record_stage_failure source-huffman-locator
      fi
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    if [ -n "$source_rom" ]; then
      python tools/v5_1_source_group_codec_probe.py \
        --source-rom "$source_rom" \
        --if-ready
      source_group_codec_probe_status=$?
      if [ "$source_group_codec_probe_status" -ne 0 ]; then
        stage_status="$source_group_codec_probe_status"
        diagnostic_trigger=probe
        record_stage_failure source-group-codec-probe
      fi
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_group_text_candidate_resolution.py --if-ready
    group_text_candidate_status=$?
    if [ "$group_text_candidate_status" -ne 0 ]; then
      stage_status="$group_text_candidate_status"
      diagnostic_trigger=probe
      record_stage_failure group-text-candidate-resolution
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_unmatched_glyph_fuzzy.py --if-ready
    unmatched_glyph_fuzzy_status=$?
    if [ "$unmatched_glyph_fuzzy_status" -ne 0 ]; then
      stage_status="$unmatched_glyph_fuzzy_status"
      diagnostic_trigger=probe
      record_stage_failure unmatched-glyph-fuzzy
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_group_script_corpus.py --if-ready
    group_script_corpus_status=$?
    if [ "$group_script_corpus_status" -ne 0 ]; then
      stage_status="$group_script_corpus_status"
      diagnostic_trigger=probe
      record_stage_failure group-script-corpus
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    if [ -n "$source_rom" ]; then
      python tools/v5_1_source_record_pairing.py \
        --source-rom "$source_rom" \
        --if-ready
      source_record_pairing_status=$?
      if [ "$source_record_pairing_status" -ne 0 ]; then
        stage_status="$source_record_pairing_status"
        diagnostic_trigger=probe
        record_stage_failure source-record-pairing
      fi
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_confirmed_group_unicode.py --if-ready
    confirmed_group_unicode_status=$?
    if [ "$confirmed_group_unicode_status" -ne 0 ]; then
      stage_status="$confirmed_group_unicode_status"
      diagnostic_trigger=probe
      record_stage_failure confirmed-group-unicode
    fi
  fi
fi

python tools/v5_1_runtime_diagnostic.py \
  --trigger "$diagnostic_trigger" \
  --exit-code "$stage_status"
diagnostic_status=$?
if [ "$diagnostic_status" -ne 0 ] && [ "$stage_status" -eq 0 ]; then
  stage_status="$diagnostic_status"
fi
if [ "$stage_status" -ne 0 ]; then
  write_next_step \
    "자동 검사 실패 지점을 안전하게 기록했습니다. 자동실행기를 끄지 말고 다음 수정이 올 때까지 기다려주세요."
fi

python tools/v5_1_runtime_bundle.py --publish
publish_status=$?
if [ "$publish_status" -ne 0 ]; then
  exit "$publish_status"
fi
exit "$stage_status"
