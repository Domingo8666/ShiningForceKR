#!/data/data/com.termux/files/usr/bin/bash
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The running autopilot can fetch this script before its manager is restarted.
# Acquire the Termux wake lock here as well so a screen-off runtime stage keeps
# progressing.  The manager records ownership and releases it on a safe stop.
state_dir="${SFKR_AUTOPILOT_STATE_DIR:-$HOME/.local/state/shiningforcekr}"
wake_lock_file="$state_dir/wake_lock_owned"
if command -v termux-wake-lock >/dev/null 2>&1 &&
  termux-wake-lock >/dev/null 2>&1; then
  mkdir -p "$state_dir"
  touch "$wake_lock_file"
fi

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

display_reviewed_build_ready() {
  review_ready="$(
    python -c 'import json; from pathlib import Path; from tools.patch_io import sha256_file; from tools.v5_1_test_display_review import validate_display_review; review_path=Path("analysis/device/v5_1_latest_display_review.json"); build_path=Path("reports/local/v5_1_test_patch_build.json"); baseline_path=Path("build/Final_Conflict_Korean_v5.1.gg"); test_path=Path("build/Final_Conflict_Korean_test_phrase.gg"); review=json.loads(review_path.read_text(encoding="utf-8")); build=json.loads(build_path.read_text(encoding="utf-8")); validate_display_review(review); valid_build=build.get("artifact_kind") == "s25u-local-korean-test-patch-build" and build.get("status") == "technical-poc-built-needs-runtime-display-proof"; identities=review.get("baseline_target_sha256") == build.get("baseline_target_sha256") and review.get("test_target_sha256") == build.get("test_target_sha256"); files=baseline_path.is_file() and test_path.is_file() and sha256_file(baseline_path) == build.get("baseline_target_sha256") and sha256_file(test_path) == build.get("test_target_sha256"); print("yes" if valid_build and identities and files and review.get("result") == "phrase-visible-pass" else "no")' 2>/dev/null || true
  )"
  [ "$review_ready" = "yes" ]
}

run_display_capture() {
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 15s 180s \
      python tools/v5_1_test_display_capture.py --if-ready
  else
    python tools/v5_1_test_display_capture.py --if-ready
  fi
}

run_source_target_runtime_sequence() {
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 15s 240s \
      python tools/v5_1_source_target_runtime_sequence.py --if-ready
  else
    python tools/v5_1_source_target_runtime_sequence.py --if-ready
  fi
}

run_active_register_rom_source() {
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 15s 150s \
      python tools/v5_1_active_register_rom_source.py --if-ready
  else
    python tools/v5_1_active_register_rom_source.py --if-ready
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
  critical_path_focus="$(
    python tools/v5_1_critical_path.py \
      --if-ready \
      --print-next-stage 2>/dev/null || printf 'continue\n'
  )"
  # A signed repository commit can request one already-whitelisted stage.  This
  # keeps device-only evidence private while allowing a stale derived receipt
  # to be rebuilt deterministically without an interactive Termux command.
  stage_request="$(git log -1 --pretty=%s 2>/dev/null || true)"
  case "$stage_request" in
    "Run stage: first-context-translated-glyph-route")
      critical_path_focus="first-context-translated-glyph-route"
      ;;
    "Run stage: first-context-direct-renderer-capture")
      critical_path_focus="first-context-direct-renderer-capture"
      ;;
  esac
  if [ "$critical_path_focus" = "active-register-rom-source" ]; then
    echo "SFKR critical path: mapping the one unresolved ROM source boundary."
    write_next_step \
      "확정된 과거 단계는 건너뛰고 현재 ROM 원천 한 단계만 자동 검사하고 있습니다."
    run_active_register_rom_source
    active_register_rom_source_status=$?
    if [ "$active_register_rom_source_status" -ne 0 ]; then
      stage_status="$active_register_rom_source_status"
      diagnostic_trigger=probe
      record_stage_failure active-register-rom-source
    fi
  elif [ "$critical_path_focus" = "active-rom-source-role" ]; then
    echo "SFKR critical path: classifying the confirmed ROM source role."
    write_next_step \
      "확정된 ROM 바이트가 대사·코드·렌더 데이터 중 무엇인지 자동 분류하고 있습니다."
    python tools/v5_1_active_rom_source_role.py --if-ready
    active_rom_source_role_status=$?
    if [ "$active_rom_source_role_status" -ne 0 ]; then
      stage_status="$active_rom_source_role_status"
      diagnostic_trigger=probe
      record_stage_failure active-rom-source-role
    fi
  elif [ "$critical_path_focus" = "active-rom-read-block" ]; then
    echo "SFKR critical path: bounding the active ROM read pattern."
    write_next_step \
      "산발적으로 읽힌 ROM 주소의 간격과 반복을 묶어 조회표인지 연속 데이터인지 판정하고 있습니다."
    python tools/v5_1_active_rom_read_block.py --if-ready
    active_rom_read_block_status=$?
    if [ "$active_rom_read_block_status" -ne 0 ]; then
      stage_status="$active_rom_read_block_status"
      diagnostic_trigger=probe
      record_stage_failure active-rom-read-block
    fi
  elif [ "$critical_path_focus" = "active-rom-lookup-index-producer" ]; then
    echo "SFKR critical path: tracing the ROM lookup address producer."
    write_next_step \
      "기존 실행 기록에서 조회 주소를 만든 직전 Z80 명령을 역추적하고 있습니다."
    python tools/v5_1_active_rom_lookup_index_producer.py --if-ready
    active_rom_lookup_index_status=$?
    if [ "$active_rom_lookup_index_status" -ne 0 ]; then
      stage_status="$active_rom_lookup_index_status"
      diagnostic_trigger=probe
      record_stage_failure active-rom-lookup-index-producer
    fi
  elif [ "$critical_path_focus" = "active-rom-path-scope" ]; then
    echo "SFKR critical path: classifying whether the ROM path can explain translated glyphs."
    write_next_step \
      "현재 ROM 읽기 경로가 번역 글자 경로인지 반복 비문자 타일 경로인지 판정하고 있습니다."
    python tools/v5_1_active_rom_path_scope.py --if-ready
    active_rom_path_scope_status=$?
    if [ "$active_rom_path_scope_status" -ne 0 ]; then
      stage_status="$active_rom_path_scope_status"
      diagnostic_trigger=probe
      record_stage_failure active-rom-path-scope
    fi
  elif [ "$critical_path_focus" = "first-context-translated-vram-diff" ]; then
    echo "SFKR critical path: comparing baseline and translated dialogue VRAM."
    write_next_step \
      "기준 ROM과 번역 ROM을 같은 대사 지점에서 각각 콜드부팅해 실제 한글 글꼴 VRAM 유입을 비교하고 있습니다."
    python tools/v5_1_first_context_translated_vram_diff.py
    translated_vram_diff_status=$?
    if [ "$translated_vram_diff_status" -ne 0 ]; then
      stage_status="$translated_vram_diff_status"
      diagnostic_trigger=probe
      translated_vram_failure_stage="first-context-translated-vram-diff"
      translated_vram_failure_token="reports/local/v5_1_first_context_translated_vram_failure_stage.txt"
      if [ -f "$translated_vram_failure_token" ]; then
        candidate_failure_stage="$(
          tr -d '\r\n' <"$translated_vram_failure_token"
        )"
        case "$candidate_failure_stage" in
          first-context-translated-vram-identity|\
          first-context-translated-vram-baseline-initialize|\
          first-context-translated-vram-baseline-media|\
          first-context-translated-vram-baseline-anchor|\
          first-context-translated-vram-baseline-context|\
          first-context-translated-vram-baseline-vram|\
          first-context-translated-vram-baseline-screenshot|\
          first-context-translated-vram-test-initialize|\
          first-context-translated-vram-test-media|\
          first-context-translated-vram-test-anchor|\
          first-context-translated-vram-test-context|\
          first-context-translated-vram-test-vram|\
          first-context-translated-vram-test-screenshot|\
          first-context-translated-vram-analysis|\
          first-context-translated-vram-artifact)
            translated_vram_failure_stage="$candidate_failure_stage"
            ;;
        esac
      fi
      record_stage_failure "$translated_vram_failure_stage"
    fi
  elif [ "$critical_path_focus" = "first-context-translated-glyph-route" ]; then
    echo "SFKR critical path: joining confirmed VRAM tiles to font slots."
    write_next_step \
      "기존에 확인된 한글 VRAM 타일을 재사용해 실제 글꼴 페이지와 슬롯 연결을 판정하고 있습니다."
    python tools/v5_1_first_context_translated_glyph_route.py
    translated_glyph_route_status=$?
    if [ "$translated_glyph_route_status" -ne 0 ]; then
      stage_status="$translated_glyph_route_status"
      diagnostic_trigger=probe
      record_stage_failure first-context-translated-glyph-route
    fi
  elif [ "$critical_path_focus" = "first-context-direct-renderer-capture" ]; then
    echo "SFKR critical path: rebuilding the first dialogue on the observed font page."
    write_next_step \
      "관측된 실제 글꼴 페이지를 직접 사용해 첫 대사 한 줄을 다시 만들고, 콜드부팅 화면을 자동 캡처하고 있습니다."
    direct_renderer_capture_output="$(
      python tools/v5_1_first_context_translation_encoding.py \
        --direct-renderer-observed-page &&
      python tools/v5_1_first_context_record_reinsertion.py &&
      python tools/v5_1_first_context_translation_test_build.py &&
      python tools/v5_1_first_context_direct_renderer_capture.py
    )"
    direct_renderer_capture_status=$?
    printf '%s\n' "$direct_renderer_capture_output"
    if [ "$direct_renderer_capture_status" -ne 0 ]; then
      stage_status="$direct_renderer_capture_status"
      diagnostic_trigger=probe
      record_stage_failure first-context-direct-renderer-capture
    fi
  elif [ "$critical_path_focus" = "active-rom-cursor-reset" ]; then
    echo "SFKR critical path: resolving the ROM cursor reset and stride."
    write_next_step \
      "BC 순차 커서의 초기화 명령과 증가 간격을 기존 실행 기록에서 판정하고 있습니다."
    python tools/v5_1_active_rom_cursor_reset.py --if-ready
    active_rom_cursor_reset_status=$?
    if [ "$active_rom_cursor_reset_status" -ne 0 ]; then
      stage_status="$active_rom_cursor_reset_status"
      diagnostic_trigger=probe
      record_stage_failure active-rom-cursor-reset
    fi
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

      if display_reviewed_build_ready; then
        echo "SFKR display stage: reusing human review for identical ROM hashes."
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
    python tools/v5_1_target_group_non_hangul_glyphs.py --if-ready
    target_group_non_hangul_glyphs_status=$?
    if [ "$target_group_non_hangul_glyphs_status" -ne 0 ]; then
      stage_status="$target_group_non_hangul_glyphs_status"
      diagnostic_trigger=probe
      record_stage_failure target-group-non-hangul-glyphs
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
    python tools/v5_1_target_group_record_quality.py --if-ready
    target_group_record_quality_status=$?
    if [ "$target_group_record_quality_status" -ne 0 ]; then
      stage_status="$target_group_record_quality_status"
      diagnostic_trigger=probe
      record_stage_failure target-group-record-quality
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_source_script_reference.py --if-ready
    source_script_reference_status=$?
    if [ "$source_script_reference_status" -ne 0 ]; then
      stage_status="$source_script_reference_status"
      diagnostic_trigger=probe
      record_stage_failure source-script-reference
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_source_target_anchor.py --if-ready
    source_target_anchor_status=$?
    if [ "$source_target_anchor_status" -ne 0 ]; then
      stage_status="$source_target_anchor_status"
      diagnostic_trigger=probe
      record_stage_failure source-target-anchor
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    source_target_section_projection_output="$(
      python tools/v5_1_source_target_section_projection.py --if-ready 2>&1
    )"
    source_target_section_projection_status=$?
    printf '%s\n' "$source_target_section_projection_output"
    if [ "$source_target_section_projection_status" -ne 0 ]; then
      stage_status="$source_target_section_projection_status"
      diagnostic_trigger=probe
      source_target_section_projection_failure_stage=source-target-section-projection
      case "$source_target_section_projection_output" in
        *"section projection identity disagrees"*|\
        *"section projection local quality identity disagrees"*)
          source_target_section_projection_failure_stage=section-projection-identity
          ;;
        *"section projection anchor is not unique"*)
          source_target_section_projection_failure_stage=section-projection-anchor
          ;;
        *"section projection target record is invalid"*|\
        *"section projection target aliases are missing"*)
          source_target_section_projection_failure_stage=section-projection-target
          ;;
        *"section projection source section is invalid"*|\
        *"section projection source annotations are missing"*|\
        *"section projection source line is invalid"*)
          source_target_section_projection_failure_stage=section-projection-source
          ;;
        *"section projection target quality tier is invalid"*)
          source_target_section_projection_failure_stage=section-projection-tier
          ;;
        *"section projection source speaker is invalid"*)
          source_target_section_projection_failure_stage=section-projection-speaker
          ;;
        *"section projection local inputs are missing"*|\
        *"source-target section projection input is missing"*)
          source_target_section_projection_failure_stage=section-projection-input
          ;;
        *"section projection result is inconsistent"*|\
        *"section projection counts do not match"*|\
        *"section projection policy is invalid"*)
          source_target_section_projection_failure_stage=section-projection-validation
          ;;
      esac
      record_stage_failure "$source_target_section_projection_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    source_target_structural_corroboration_output="$(
      python tools/v5_1_source_target_structural_corroboration.py --if-ready 2>&1
    )"
    source_target_structural_corroboration_status=$?
    printf '%s\n' "$source_target_structural_corroboration_output"
    if [ "$source_target_structural_corroboration_status" -ne 0 ]; then
      stage_status="$source_target_structural_corroboration_status"
      diagnostic_trigger=probe
      source_target_structural_corroboration_failure_stage=source-target-structural-corroboration
      case "$source_target_structural_corroboration_output" in
        *"structural corroboration projection identity disagrees"*|\
        *"structural corroboration identity is invalid"*)
          source_target_structural_corroboration_failure_stage=structural-corroboration-identity
          ;;
        *"structural corroboration pair"*)
          source_target_structural_corroboration_failure_stage=structural-corroboration-pair
          ;;
        *"structural corroboration speaker"*)
          source_target_structural_corroboration_failure_stage=structural-corroboration-speaker
          ;;
        *"structural corroboration target token"*|\
        *"structural corroboration control symbol"*)
          source_target_structural_corroboration_failure_stage=structural-corroboration-token
          ;;
        *"structural corroboration local projection is missing"*|\
        *"source-target structural corroboration input is missing"*)
          source_target_structural_corroboration_failure_stage=structural-corroboration-input
          ;;
        *"structural corroboration fields do not match"*|\
        *"structural corroboration counts do not match"*|\
        *"structural corroboration aggregates are inconsistent"*|\
        *"structural corroboration policy is invalid"*)
          source_target_structural_corroboration_failure_stage=structural-corroboration-validation
          ;;
      esac
      record_stage_failure "$source_target_structural_corroboration_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    source_target_runtime_sequence_output="$(
      run_source_target_runtime_sequence 2>&1
    )"
    source_target_runtime_sequence_status=$?
    printf '%s\n' "$source_target_runtime_sequence_output"
    if [ "$source_target_runtime_sequence_status" -ne 0 ]; then
      stage_status="$source_target_runtime_sequence_status"
      diagnostic_trigger=probe
      source_target_runtime_sequence_failure_stage=source-target-runtime-sequence
      case "$source_target_runtime_sequence_output" in
        *"runtime sequence input identity disagrees"*|\
        *"runtime sequence identity is invalid"*)
          source_target_runtime_sequence_failure_stage=runtime-sequence-identity
          ;;
        *"runtime sequence confirmed anchor was not reached"*|\
        *"runtime sequence anchor observation disagrees"*)
          source_target_runtime_sequence_failure_stage=runtime-sequence-anchor
          ;;
        *"runtime sequence registers"*|\
        *"runtime sequence observation"*)
          source_target_runtime_sequence_failure_stage=runtime-sequence-observation
          ;;
        *"runtime sequence input is missing"*|\
        *"runtime sequence ROM must stay under build"*)
          source_target_runtime_sequence_failure_stage=runtime-sequence-input
          ;;
        *"runtime sequence fields do not match"*|\
        *"runtime sequence counts do not match"*|\
        *"runtime sequence aggregates are inconsistent"*|\
        *"runtime sequence policy is invalid"*)
          source_target_runtime_sequence_failure_stage=runtime-sequence-validation
          ;;
      esac
      record_stage_failure "$source_target_runtime_sequence_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    source_target_runtime_context_output="$(
      python tools/v5_1_source_target_runtime_context.py --if-ready 2>&1
    )"
    source_target_runtime_context_status=$?
    printf '%s\n' "$source_target_runtime_context_output"
    if [ "$source_target_runtime_context_status" -ne 0 ]; then
      stage_status="$source_target_runtime_context_status"
      diagnostic_trigger=probe
      source_target_runtime_context_failure_stage=source-target-runtime-context
      case "$source_target_runtime_context_output" in
        *"runtime context input identity disagrees"*|\
        *"runtime context identity is invalid"*)
          source_target_runtime_context_failure_stage=runtime-context-identity
          ;;
        *"runtime context observation"*|\
        *"runtime context projection pair"*|\
        *"runtime context projection coordinates"*|\
        *"runtime context mapped pair"*|\
        *"runtime context speaker"*|\
        *"runtime context quality tier"*|\
        *"runtime context target text"*)
          source_target_runtime_context_failure_stage=runtime-context-mapping
          ;;
        *"runtime context local projection is missing"*|\
        *"runtime context local inputs are missing"*|\
        *"runtime context input is missing"*)
          source_target_runtime_context_failure_stage=runtime-context-input
          ;;
        *"runtime context fields do not match"*|\
        *"runtime context counts do not match"*|\
        *"runtime context aggregates are inconsistent"*|\
        *"runtime context policy is invalid"*)
          source_target_runtime_context_failure_stage=runtime-context-validation
          ;;
      esac
      record_stage_failure "$source_target_runtime_context_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    runtime_context_glyph_demand_output="$(
      python tools/v5_1_runtime_context_glyph_demand.py --if-ready 2>&1
    )"
    runtime_context_glyph_demand_status=$?
    printf '%s\n' "$runtime_context_glyph_demand_output"
    if [ "$runtime_context_glyph_demand_status" -ne 0 ]; then
      stage_status="$runtime_context_glyph_demand_status"
      diagnostic_trigger=probe
      runtime_context_glyph_demand_failure_stage=runtime-context-glyph-demand
      case "$runtime_context_glyph_demand_output" in
        *"runtime context glyph demand identity"*|\
        *"runtime context glyph demand input identity"*)
          runtime_context_glyph_demand_failure_stage=context-glyph-demand-identity
          ;;
        *"runtime context glyph demand pair"*|\
        *"runtime context glyph demand target record"*|\
        *"runtime context glyph demand token"*|\
        *"runtime context glyph demand coordinate"*|\
        *"runtime context glyph demand candidates"*|\
        *"runtime context glyph demand mapping"*)
          runtime_context_glyph_demand_failure_stage=context-glyph-demand-mapping
          ;;
        *"runtime context glyph demand local inputs"*|\
        *"runtime context glyph demand input is missing"*)
          runtime_context_glyph_demand_failure_stage=context-glyph-demand-input
          ;;
        *"runtime context glyph demand fields do not match"*|\
        *"runtime context glyph demand counts do not match"*|\
        *"runtime context glyph demand result is inconsistent"*|\
        *"runtime context glyph demand aggregates disagree"*)
          runtime_context_glyph_demand_failure_stage=context-glyph-demand-validation
          ;;
      esac
      record_stage_failure "$runtime_context_glyph_demand_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_active_vram_route.py --if-ready
    active_vram_route_status=$?
    if [ "$active_vram_route_status" -ne 0 ]; then
      stage_status="$active_vram_route_status"
      diagnostic_trigger=probe
      record_stage_failure active-vram-route
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_active_ram_producer.py --if-ready
    active_ram_producer_status=$?
    if [ "$active_ram_producer_status" -ne 0 ]; then
      stage_status="$active_ram_producer_status"
      diagnostic_trigger=probe
      record_stage_failure active-ram-buffer-producer
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_active_ram_writer_source.py --if-ready
    active_ram_writer_source_status=$?
    if [ "$active_ram_writer_source_status" -ne 0 ]; then
      stage_status="$active_ram_writer_source_status"
      diagnostic_trigger=probe
      record_stage_failure active-ram-writer-source
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    python tools/v5_1_active_ram_register_trace.py --if-ready
    active_ram_register_trace_status=$?
    if [ "$active_ram_register_trace_status" -ne 0 ]; then
      stage_status="$active_ram_register_trace_status"
      diagnostic_trigger=probe
      record_stage_failure active-ram-register-trace
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    run_active_register_rom_source
    active_register_rom_source_status=$?
    if [ "$active_register_rom_source_status" -ne 0 ]; then
      stage_status="$active_register_rom_source_status"
      diagnostic_trigger=probe
      record_stage_failure active-register-rom-source
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    runtime_context_glyph_candidates_output="$(
      python tools/v5_1_runtime_context_glyph_candidates.py --if-ready 2>&1
    )"
    runtime_context_glyph_candidates_status=$?
    printf '%s\n' "$runtime_context_glyph_candidates_output"
    if [ "$runtime_context_glyph_candidates_status" -ne 0 ]; then
      stage_status="$runtime_context_glyph_candidates_status"
      diagnostic_trigger=probe
      runtime_context_glyph_candidates_failure_stage=runtime-context-glyph-candidates
      case "$runtime_context_glyph_candidates_output" in
        *"runtime glyph candidate input identity"*|\
        *"runtime glyph candidate identity"*)
          runtime_context_glyph_candidates_failure_stage=context-glyph-candidates-identity
          ;;
        *"runtime glyph candidate demand"*|\
        *"runtime glyph candidate fuzzy"*|\
        *"runtime glyph candidate non-Hangul"*|\
        *"runtime glyph candidate coordinate"*)
          runtime_context_glyph_candidates_failure_stage=context-glyph-candidates-mapping
          ;;
        *"runtime glyph candidate local inputs"*|\
        *"runtime glyph candidate input is missing"*)
          runtime_context_glyph_candidates_failure_stage=context-glyph-candidates-input
          ;;
        *"runtime glyph candidate fields do not match"*|\
        *"runtime glyph candidate counts do not match"*|\
        *"runtime glyph candidate result is inconsistent"*|\
        *"runtime glyph candidate aggregates disagree"*)
          runtime_context_glyph_candidates_failure_stage=context-glyph-candidates-validation
          ;;
      esac
      record_stage_failure "$runtime_context_glyph_candidates_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    runtime_context_glyph_review_output="$(
      python tools/v5_1_runtime_context_glyph_review.py --if-ready 2>&1
    )"
    runtime_context_glyph_review_status=$?
    printf '%s\n' "$runtime_context_glyph_review_output"
    if [ "$runtime_context_glyph_review_status" -ne 0 ]; then
      stage_status="$runtime_context_glyph_review_status"
      diagnostic_trigger=probe
      runtime_context_glyph_review_failure_stage=runtime-context-glyph-review
      case "$runtime_context_glyph_review_output" in
        *"runtime glyph review input identity"*|\
        *"runtime glyph review identity"*)
          runtime_context_glyph_review_failure_stage=context-glyph-review-identity
          ;;
        *"runtime glyph review demand"*|\
        *"runtime glyph review candidate"*|\
        *"runtime glyph review fuzzy"*|\
        *"runtime glyph review non-Hangul"*|\
        *"runtime glyph review coordinate"*)
          runtime_context_glyph_review_failure_stage=context-glyph-review-mapping
          ;;
        *"runtime glyph review local inputs"*|\
        *"runtime glyph review input is missing"*)
          runtime_context_glyph_review_failure_stage=context-glyph-review-input
          ;;
        *"runtime glyph review fields do not match"*|\
        *"runtime glyph review counts do not match"*|\
        *"runtime glyph review result is inconsistent"*|\
        *"runtime glyph review aggregates disagree"*)
          runtime_context_glyph_review_failure_stage=context-glyph-review-validation
          ;;
      esac
      record_stage_failure "$runtime_context_glyph_review_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    runtime_context_glyph_preservation_output="$(
      python tools/v5_1_runtime_context_glyph_preservation.py --if-ready 2>&1
    )"
    runtime_context_glyph_preservation_status=$?
    printf '%s\n' "$runtime_context_glyph_preservation_output"
    if [ "$runtime_context_glyph_preservation_status" -ne 0 ]; then
      stage_status="$runtime_context_glyph_preservation_status"
      diagnostic_trigger=probe
      runtime_context_glyph_preservation_failure_stage=runtime-context-glyph-preservation
      case "$runtime_context_glyph_preservation_output" in
        *"runtime glyph preservation identity"*)
          runtime_context_glyph_preservation_failure_stage=context-glyph-preservation-identity
          ;;
        *"runtime glyph preservation card"*|\
        *"runtime glyph preservation coordinate"*|\
        *"runtime glyph preservation reviewed shapes"*|\
        *"runtime glyph preservation review evidence"*)
          runtime_context_glyph_preservation_failure_stage=context-glyph-preservation-classification
          ;;
        *"runtime glyph preservation local cards"*|\
        *"runtime glyph preservation input is missing"*)
          runtime_context_glyph_preservation_failure_stage=context-glyph-preservation-input
          ;;
        *"runtime glyph preservation fields do not match"*|\
        *"runtime glyph preservation counts do not match"*|\
        *"runtime glyph preservation result is inconsistent"*|\
        *"runtime glyph preservation aggregates disagree"*)
          runtime_context_glyph_preservation_failure_stage=context-glyph-preservation-validation
          ;;
      esac
      record_stage_failure "$runtime_context_glyph_preservation_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    first_context_translation_review_output="$(
      python tools/v5_1_first_context_translation_review.py --if-ready 2>&1
    )"
    first_context_translation_review_status=$?
    printf '%s\n' "$first_context_translation_review_output"
    if [ "$first_context_translation_review_status" -ne 0 ]; then
      stage_status="$first_context_translation_review_status"
      diagnostic_trigger=probe
      first_context_translation_review_failure_stage=first-context-translation-review
      case "$first_context_translation_review_output" in
        *"first context translation review identity"*)
          first_context_translation_review_failure_stage=first-context-review-identity
          ;;
        *"first context translation review row"*|\
        *"first context translation review mapping"*|\
        *"first context translation review source"*|\
        *"first context translation review speaker"*|\
        *"first context translation review lines"*)
          first_context_translation_review_failure_stage=first-context-review-mapping
          ;;
        *"first context translation review local rows"*|\
        *"first context translation review input is missing"*)
          first_context_translation_review_failure_stage=first-context-review-input
          ;;
        *"first context translation review fields do not match"*|\
        *"first context translation review counts do not match"*|\
        *"first context translation review result is inconsistent"*|\
        *"first context translation review aggregates disagree"*)
          first_context_translation_review_failure_stage=first-context-review-validation
          ;;
      esac
      record_stage_failure "$first_context_translation_review_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    first_context_translation_approval_output="$(
      python tools/v5_1_first_context_translation_approval.py --if-ready 2>&1
    )"
    first_context_translation_approval_status=$?
    printf '%s\n' "$first_context_translation_approval_output"
    if [ "$first_context_translation_approval_status" -ne 0 ]; then
      stage_status="$first_context_translation_approval_status"
      diagnostic_trigger=probe
      first_context_translation_approval_failure_stage=first-context-translation-approval
      case "$first_context_translation_approval_output" in
        *"translation approval identity"*)
          first_context_translation_approval_failure_stage=first-context-approval-identity
          ;;
        *"translation approval row"*|\
        *"translation approval target"*|\
        *"translation line count"*|\
        *"contains no Hangul"*)
          first_context_translation_approval_failure_stage=first-context-approval-payload
          ;;
        *"translation approval input is missing"*)
          first_context_translation_approval_failure_stage=first-context-approval-input
          ;;
        *"translation approval fields do not match"*|\
        *"translation approval counts do not match"*|\
        *"translation approval result is inconsistent"*)
          first_context_translation_approval_failure_stage=first-context-approval-validation
          ;;
      esac
      record_stage_failure "$first_context_translation_approval_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    first_context_translation_capacity_output="$(
      python tools/v5_1_first_context_translation_capacity.py --if-ready 2>&1
    )"
    first_context_translation_capacity_status=$?
    printf '%s\n' "$first_context_translation_capacity_output"
    if [ "$first_context_translation_capacity_status" -ne 0 ]; then
      stage_status="$first_context_translation_capacity_status"
      diagnostic_trigger=probe
      first_context_translation_capacity_failure_stage=first-context-translation-capacity
      case "$first_context_translation_capacity_output" in
        *"translation capacity identity"*)
          first_context_translation_capacity_failure_stage=first-context-capacity-identity
          ;;
        *"capacity row"*|\
        *"font catalogue"*|\
        *"Hangul demand"*|\
        *"Galmuri7"*|\
        *"font glyph mask"*|\
        *"font tile roundtrip"*|\
        *"source-dependent bytes"*)
          first_context_translation_capacity_failure_stage=first-context-capacity-font-plan
          ;;
        *"translation capacity input is missing"*|\
        *"translation capacity rows are missing"*)
          first_context_translation_capacity_failure_stage=first-context-capacity-input
          ;;
        *"translation capacity fields do not match"*|\
        *"translation capacity counts do not match"*|\
        *"translation capacity is inconsistent"*)
          first_context_translation_capacity_failure_stage=first-context-capacity-validation
          ;;
      esac
      record_stage_failure "$first_context_translation_capacity_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    if ! python -c 'import json; from pathlib import Path; from tools.v5_1_active_vram_route import validate_active_vram_route; path=Path("analysis/device/v5_1_latest_active_vram_route.json"); value=json.loads(path.read_text(encoding="utf-8")); validate_active_vram_route(value); print("yes" if value.get("translation_build_eligible") is True else "no")' 2>/dev/null |
      grep -qx yes; then
      printf '%s\n' \
        'First-context translation build waits for a measured active VRAM font route'
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    if command -v timeout >/dev/null 2>&1; then
      first_context_translation_encoding_output="$(
        timeout -k 5s 120s \
          python tools/v5_1_first_context_translation_encoding.py \
            --if-ready 2>&1
      )"
    else
      first_context_translation_encoding_output="$(
        python tools/v5_1_first_context_translation_encoding.py \
          --if-ready 2>&1
      )"
    fi
    first_context_translation_encoding_status=$?
    printf '%s\n' "$first_context_translation_encoding_output"
    if [ "$first_context_translation_encoding_status" -ne 0 ]; then
      stage_status="$first_context_translation_encoding_status"
      diagnostic_trigger=probe
      first_context_translation_encoding_failure_stage=first-context-translation-encoding
      case "$first_context_translation_encoding_output" in
        *"translation encoding identity"*)
          first_context_translation_encoding_failure_stage=first-context-encoding-identity
          ;;
        *"preserved glyph"*|\
        *"preserved visual"*|\
        *"custom font page"*|\
        *"visual row"*|\
        *"Huffman assignment"*|\
        *"Huffman symbol domain"*|\
        *"target character is unmapped"*|\
        *"Huffman roundtrip"*)
          first_context_translation_encoding_failure_stage=first-context-encoding-plan
          ;;
        *"translation encoding input is missing"*|\
        *"translation encoding rows are missing"*|\
        *"source tokens are missing"*)
          first_context_translation_encoding_failure_stage=first-context-encoding-input
          ;;
        *"translation encoding fields do not match"*|\
        *"translation encoding counts do not match"*|\
        *"translation encoding is inconsistent"*)
          first_context_translation_encoding_failure_stage=first-context-encoding-validation
          ;;
      esac
      record_stage_failure "$first_context_translation_encoding_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    first_context_record_reinsertion_output="$(
      python tools/v5_1_first_context_record_reinsertion.py --if-ready 2>&1
    )"
    first_context_record_reinsertion_status=$?
    printf '%s\n' "$first_context_record_reinsertion_output"
    if [ "$first_context_record_reinsertion_status" -ne 0 ]; then
      stage_status="$first_context_record_reinsertion_status"
      diagnostic_trigger=probe
      first_context_record_reinsertion_failure_stage=first-context-record-reinsertion
      case "$first_context_record_reinsertion_output" in
        *"reinsertion identity"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-identity
          ;;
        *"row count disagrees"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-row-count
          ;;
        *"projection is duplicated"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-duplicate-projection
          ;;
        *"projection is invalid"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-invalid-projection
          ;;
        *"context row is invalid"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-invalid-context-row
          ;;
        *"target record is missing"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-missing-target-record
          ;;
        *"record fields are invalid"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-invalid-record-fields
          ;;
        *"record bounds disagree"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-record-bounds
          ;;
        *"reinsertion input is missing"*|\
        *"reinsertion rows are missing"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-input
          ;;
        *"reinsertion fields do not match"*|\
        *"reinsertion counts do not match"*|\
        *"reinsertion result is inconsistent"*)
          first_context_record_reinsertion_failure_stage=first-context-reinsertion-validation
          ;;
      esac
      record_stage_failure "$first_context_record_reinsertion_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    first_context_translation_build_output="$(
      python tools/v5_1_first_context_translation_test_build.py --if-ready 2>&1
    )"
    first_context_translation_build_status=$?
    printf '%s\n' "$first_context_translation_build_output"
    if [ "$first_context_translation_build_status" -ne 0 ]; then
      stage_status="$first_context_translation_build_status"
      diagnostic_trigger=probe
      first_context_translation_build_failure_stage=first-context-translation-build
      case "$first_context_translation_build_output" in
        *"translation build identity"*)
          first_context_translation_build_failure_stage=first-context-build-identity
          ;;
        *"font overlay"*|\
        *"record write"*|\
        *"expected-write"*)
          first_context_translation_build_failure_stage=first-context-build-write
          ;;
        *"confirmed group alias is ambiguous"*)
          first_context_translation_build_failure_stage=first-context-build-group-alias
          ;;
        *"not a contiguous group tail"*)
          first_context_translation_build_failure_stage=first-context-build-group-tail
          ;;
        *"packed group tail exceeds"*)
          first_context_translation_build_failure_stage=first-context-build-group-overflow
          ;;
        *"group identity is invalid"*)
          first_context_translation_build_failure_stage=first-context-build-group-identity
          ;;
        *"verification row"*|\
        *"expected symbols"*|\
        *"font assignment"*)
          first_context_translation_build_failure_stage=first-context-build-verification
          ;;
        *"translation build input is missing"*|\
        *"translation build rows are missing"*)
          first_context_translation_build_failure_stage=first-context-build-input
          ;;
        *"translation build fields do not match"*|\
        *"translation build counts do not match"*|\
        *"translation build is inconsistent"*)
          first_context_translation_build_failure_stage=first-context-build-validation
          ;;
      esac
      record_stage_failure "$first_context_translation_build_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    if command -v timeout >/dev/null 2>&1; then
      first_context_translation_runtime_output="$(
        timeout -k 15s 360s \
          python tools/v5_1_first_context_translation_runtime_capture.py \
          --if-ready 2>&1
      )"
    else
      first_context_translation_runtime_output="$(
        python tools/v5_1_first_context_translation_runtime_capture.py \
          --if-ready 2>&1
      )"
    fi
    first_context_translation_runtime_status=$?
    printf '%s\n' "$first_context_translation_runtime_output"
    if [ "$first_context_translation_runtime_status" -ne 0 ]; then
      stage_status="$first_context_translation_runtime_status"
      diagnostic_trigger=probe
      first_context_translation_runtime_failure_stage=first-context-translation-runtime-capture
      case "$first_context_translation_runtime_output" in
        *"runtime capture identity"*)
          first_context_translation_runtime_failure_stage=first-context-runtime-capture-identity
          ;;
        *"runtime sequence is incomplete"*|\
        *"runtime screenshots are incomplete"*)
          first_context_translation_runtime_failure_stage=first-context-runtime-capture-sequence
          ;;
        *"runtime capture input is missing"*|\
        *"runtime capture inputs are invalid"*)
          first_context_translation_runtime_failure_stage=first-context-runtime-capture-input
          ;;
        *"runtime capture fields do not match"*|\
        *"runtime capture counts do not match"*|\
        *"runtime capture is inconsistent"*)
          first_context_translation_runtime_failure_stage=first-context-runtime-capture-validation
          ;;
      esac
      record_stage_failure "$first_context_translation_runtime_failure_stage"
    fi
  fi

  if [ "$stage_status" -eq 0 ]; then
    if command -v timeout >/dev/null 2>&1; then
      first_context_consumer_trace_output="$(
        timeout -k 15s 360s \
          python tools/v5_1_first_context_consumer_trace.py \
          --if-needed 2>&1
      )"
    else
      first_context_consumer_trace_output="$(
        python tools/v5_1_first_context_consumer_trace.py \
          --if-needed 2>&1
      )"
    fi
    first_context_consumer_trace_status=$?
    printf '%s\n' "$first_context_consumer_trace_output"
    if [ "$first_context_consumer_trace_status" -ne 0 ]; then
      stage_status="$first_context_consumer_trace_status"
      diagnostic_trigger=probe
      first_context_consumer_trace_failure_stage=first-context-consumer-trace
      case "$first_context_consumer_trace_output" in
        *"consumer trace identity"*)
          first_context_consumer_trace_failure_stage=first-context-consumer-trace-identity
          ;;
        *"confirmed anchor was not reached"*)
          first_context_consumer_trace_failure_stage=first-context-consumer-trace-anchor
          ;;
        *"encoding row"*|*"input is missing"*)
          first_context_consumer_trace_failure_stage=first-context-consumer-trace-input
          ;;
        *"fields do not match"*|*"counts do not match"*|*"is inconsistent"*)
          first_context_consumer_trace_failure_stage=first-context-consumer-trace-validation
          ;;
      esac
      record_stage_failure "$first_context_consumer_trace_failure_stage"
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
