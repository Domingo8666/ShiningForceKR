#!/usr/bin/env python3
"""Validate and atomically publish all sanitized S25U runtime artifacts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

try:
    from .patch_io import sha256_file
    from .v5_1_decoder_register_trace import (
        validate_decoder_register_trace,
    )
    from .v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from .v5_1_test_display_capture import (
        PUBLISH_RELATIVE_PATH as DISPLAY_CAPTURE_RELATIVE_PATH,
        validate_display_capture,
    )
    from .v5_1_test_display_comparison import validate_display_comparison
    from .v5_1_test_display_review import validate_display_review
    from .v5_1_visible_entry_proof import (
        PUBLISH_RELATIVE_PATH as VISIBLE_ENTRY_PROOF_RELATIVE_PATH,
        validate_visible_entry_proof,
    )
    from .v5_1_poc_expansion_proof import (
        PUBLISH_RELATIVE_PATH as POC_EXPANSION_PROOF_RELATIVE_PATH,
        validate_poc_expansion_proof,
    )
    from .v5_1_visible_script_record import (
        PUBLISH_RELATIVE_PATH as VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH,
        validate_visible_script_roundtrip,
    )
    from .v5_1_visible_unicode_mapping import (
        PUBLISH_RELATIVE_PATH as VISIBLE_UNICODE_MAPPING_RELATIVE_PATH,
        validate_visible_unicode_mapping,
    )
    from .v5_1_initial_font_page_trace import (
        PUBLISH_RELATIVE_PATH as INITIAL_FONT_PAGE_TRACE_RELATIVE_PATH,
        validate_initial_font_page_trace,
    )
    from .v5_1_font_transfer_source import (
        PUBLISH_RELATIVE_PATH as FONT_TRANSFER_SOURCE_RELATIVE_PATH,
        validate_font_transfer_source,
    )
    from .v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH,
        validate_confirmed_group_extract,
    )
    from .v5_1_group_context_resolution import (
        PUBLISH_RELATIVE_PATH as GROUP_CONTEXT_RESOLUTION_RELATIVE_PATH,
        validate_group_context_resolution,
    )
    from .v5_1_group_runtime_context import (
        PUBLISH_RELATIVE_PATH as GROUP_RUNTIME_CONTEXT_RELATIVE_PATH,
        validate_group_runtime_context,
    )
    from .v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as GROUP_SOURCE_DELTA_RELATIVE_PATH,
        validate_group_source_delta,
    )
    from .v5_1_source_group_codec_probe import (
        PUBLISH_RELATIVE_PATH as SOURCE_GROUP_CODEC_PROBE_RELATIVE_PATH,
        validate_source_group_codec_probe,
    )
    from .v5_1_source_huffman_locator import (
        PUBLISH_RELATIVE_PATH as SOURCE_HUFFMAN_LOCATOR_RELATIVE_PATH,
        validate_source_huffman_locator,
    )
    from .v5_1_source_record_pairing import (
        PUBLISH_RELATIVE_PATH as SOURCE_RECORD_PAIRING_RELATIVE_PATH,
        validate_source_record_pairing,
    )
    from .v5_1_target_group_usage import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_USAGE_RELATIVE_PATH,
        validate_target_group_usage,
    )
    from .v5_1_decoder_caller_resolution import (
        PUBLISH_RELATIVE_PATH as DECODER_CALLER_RESOLUTION_RELATIVE_PATH,
        validate_decoder_caller_resolution,
    )
    from .v5_1_target_group_stream_map import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_STREAM_MAP_RELATIVE_PATH,
        validate_target_group_stream_map,
    )
    from .v5_1_target_group_population import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_POPULATION_RELATIVE_PATH,
        validate_target_group_population,
    )
    from .v5_1_target_group_population_decode import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_POPULATION_DECODE_RELATIVE_PATH,
        validate_target_group_population_decode,
    )
    from .v5_1_target_group_expanded_corpus import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_EXPANDED_CORPUS_RELATIVE_PATH,
        validate_target_group_expanded_corpus,
    )
    from .v5_1_target_group_expanded_glyphs import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH,
        validate_target_group_expanded_glyphs,
    )
    from .v5_1_target_group_non_hangul_glyphs import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_NON_HANGUL_GLYPHS_RELATIVE_PATH,
        validate_target_group_non_hangul_glyphs,
    )
    from .v5_1_target_group_record_quality import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_RECORD_QUALITY_RELATIVE_PATH,
        validate_target_group_record_quality,
    )
    from .v5_1_source_script_reference import (
        PUBLISH_RELATIVE_PATH as SOURCE_SCRIPT_REFERENCE_RELATIVE_PATH,
        validate_source_script_reference,
    )
    from .v5_1_source_target_anchor import (
        PUBLISH_RELATIVE_PATH as SOURCE_TARGET_ANCHOR_RELATIVE_PATH,
        validate_source_target_anchor,
    )
    from .v5_1_source_target_section_projection import (
        PUBLISH_RELATIVE_PATH as SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH,
        validate_source_target_section_projection,
    )
    from .v5_1_source_target_structural_corroboration import (
        PUBLISH_RELATIVE_PATH
        as SOURCE_TARGET_STRUCTURAL_CORROBORATION_RELATIVE_PATH,
        validate_source_target_structural_corroboration,
    )
    from .v5_1_source_target_runtime_sequence import (
        PUBLISH_RELATIVE_PATH as SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH,
        validate_source_target_runtime_sequence,
    )
    from .v5_1_source_target_runtime_context import (
        PUBLISH_RELATIVE_PATH as SOURCE_TARGET_RUNTIME_CONTEXT_RELATIVE_PATH,
        validate_source_target_runtime_context,
    )
    from .v5_1_runtime_context_glyph_demand import (
        PUBLISH_RELATIVE_PATH as RUNTIME_CONTEXT_GLYPH_DEMAND_RELATIVE_PATH,
        validate_runtime_context_glyph_demand,
    )
    from .v5_1_active_vram_route import (
        PUBLISH_RELATIVE_PATH as ACTIVE_VRAM_ROUTE_RELATIVE_PATH,
        validate_active_vram_route,
    )
    from .v5_1_active_ram_producer import (
        PUBLISH_RELATIVE_PATH as ACTIVE_RAM_PRODUCER_RELATIVE_PATH,
        validate_active_ram_producer,
    )
    from .v5_1_active_ram_writer_source import (
        PUBLISH_RELATIVE_PATH as ACTIVE_RAM_WRITER_SOURCE_RELATIVE_PATH,
        validate_active_ram_writer_source,
    )
    from .v5_1_active_ram_register_trace import (
        PUBLISH_RELATIVE_PATH as ACTIVE_RAM_REGISTER_TRACE_RELATIVE_PATH,
        validate_active_ram_register_trace,
    )
    from .v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ACTIVE_REGISTER_ROM_SOURCE_RELATIVE_PATH,
        validate_active_register_rom_source,
    )
    from .v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_SOURCE_ROLE_RELATIVE_PATH,
        validate_active_rom_source_role,
    )
    from .v5_1_active_rom_read_block import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_READ_BLOCK_RELATIVE_PATH,
        validate_active_rom_read_block,
    )
    from .v5_1_active_rom_lookup_index_producer import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_LOOKUP_INDEX_RELATIVE_PATH,
        validate_active_rom_lookup_index_producer,
    )
    from .v5_1_active_rom_path_scope import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_PATH_SCOPE_RELATIVE_PATH,
        validate_active_rom_path_scope,
    )
    from .v5_1_first_context_translated_vram_diff import (
        PUBLISH_RELATIVE_PATH as TRANSLATED_VRAM_DIFF_RELATIVE_PATH,
        validate_first_context_translated_vram_diff,
    )
    from .v5_1_first_context_translated_glyph_route import (
        PUBLISH_RELATIVE_PATH as TRANSLATED_GLYPH_ROUTE_RELATIVE_PATH,
        validate_first_context_translated_glyph_route,
    )
    from .v5_1_first_context_direct_renderer_capture import (
        PUBLISH_RELATIVE_PATH as DIRECT_RENDERER_CAPTURE_RELATIVE_PATH,
        PUBLISH_IMAGE_RELATIVE_PATH as DIRECT_RENDERER_CAPTURE_IMAGE_RELATIVE_PATH,
        validate_first_context_direct_renderer_capture,
    )
    from .v5_1_active_rom_cursor_reset import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_CURSOR_RESET_RELATIVE_PATH,
        validate_active_rom_cursor_reset,
    )
    from .v5_1_critical_path import (
        PUBLISH_RELATIVE_PATH as CRITICAL_PATH_RELATIVE_PATH,
        validate_critical_path,
    )
    from .v5_1_runtime_context_glyph_candidates import (
        PUBLISH_RELATIVE_PATH
        as RUNTIME_CONTEXT_GLYPH_CANDIDATES_RELATIVE_PATH,
        validate_runtime_context_glyph_candidates,
    )
    from .v5_1_runtime_context_glyph_review import (
        PUBLISH_RELATIVE_PATH as RUNTIME_CONTEXT_GLYPH_REVIEW_RELATIVE_PATH,
        validate_runtime_context_glyph_review,
    )
    from .v5_1_runtime_context_glyph_preservation import (
        PUBLISH_RELATIVE_PATH
        as RUNTIME_CONTEXT_GLYPH_PRESERVATION_RELATIVE_PATH,
        validate_runtime_context_glyph_preservation,
    )
    from .v5_1_first_context_translation_review import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_REVIEW_RELATIVE_PATH,
        validate_first_context_translation_review,
    )
    from .v5_1_first_context_translation_approval import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_APPROVAL_RELATIVE_PATH,
        validate_first_context_translation_approval,
    )
    from .v5_1_first_context_translation_capacity import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_CAPACITY_RELATIVE_PATH,
        validate_first_context_translation_capacity,
    )
    from .v5_1_first_context_translation_encoding import (
        FAILURE_PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_ENCODING_FAILURE_RELATIVE_PATH,
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_ENCODING_RELATIVE_PATH,
        validate_first_context_translation_encoding,
        validate_first_context_translation_encoding_failure,
    )
    from .v5_1_first_context_record_reinsertion import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_RECORD_REINSERTION_RELATIVE_PATH,
        validate_first_context_record_reinsertion,
    )
    from .v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_TEST_BUILD_RELATIVE_PATH,
        validate_first_context_translation_test_build,
    )
    from .v5_1_first_context_translation_runtime_capture import (
        FAILURE_PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_FAILURE_RELATIVE_PATH,
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_RELATIVE_PATH,
        validate_first_context_translation_runtime_capture,
    )
    from .v5_1_first_context_translation_visual_review import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_VISUAL_REVIEW_RELATIVE_PATH,
        validate_first_context_translation_visual_review,
    )
    from .v5_1_first_context_consumer_trace import (
        PUBLISH_RELATIVE_PATH as FIRST_CONTEXT_CONSUMER_TRACE_RELATIVE_PATH,
        validate_first_context_consumer_trace,
    )
    from .v5_1_runtime_stage_failure import (
        validate_first_context_runtime_capture_failure,
    )
    from .v5_1_group_text_candidate_resolution import (
        PUBLISH_RELATIVE_PATH as GROUP_TEXT_CANDIDATE_RELATIVE_PATH,
        validate_group_text_candidate_resolution,
    )
    from .v5_1_unmatched_glyph_fuzzy import (
        PUBLISH_RELATIVE_PATH as UNMATCHED_GLYPH_FUZZY_RELATIVE_PATH,
        validate_unmatched_glyph_fuzzy,
    )
    from .v5_1_group_script_corpus import (
        PUBLISH_RELATIVE_PATH as GROUP_SCRIPT_CORPUS_RELATIVE_PATH,
        validate_group_script_corpus,
    )
    from .v5_1_confirmed_group_unicode import (
        PUBLISH_RELATIVE_PATH as CONFIRMED_GROUP_UNICODE_RELATIVE_PATH,
        validate_confirmed_group_unicode,
    )
    from .v5_1_progress_preview import (
        PUBLISH_IMAGE_RELATIVE_PATH,
        PUBLISH_RECEIPT_RELATIVE_PATH,
        load_validated_progress_image,
        validate_progress_preview,
    )
    from .v5_1_runtime_diagnostic import validate_runtime_diagnostic
    from .v5_1_runtime_hit_resolver import validate_consumer_resolution
    from .v5_1_runtime_observation import validate_runtime_observation
    from .v5_1_renderer_observation import validate_renderer_observation
    from .v5_1_renderer_output_trace import (
        PUBLISH_RELATIVE_PATH as RENDERER_OUTPUT_TRACE_RELATIVE_PATH,
        validate_renderer_output_trace,
    )
    from .v5_1_route_capture import validate_route_capture
    from .v5_1_safe_observation import _git, _normalized_remote
except ImportError:  # direct script execution
    from patch_io import sha256_file
    from v5_1_decoder_register_trace import validate_decoder_register_trace
    from v5_1_decoder_stream_resolution import (
        validate_decoder_stream_resolution,
    )
    from v5_1_test_display_capture import (
        PUBLISH_RELATIVE_PATH as DISPLAY_CAPTURE_RELATIVE_PATH,
        validate_display_capture,
    )
    from v5_1_test_display_comparison import validate_display_comparison
    from v5_1_test_display_review import validate_display_review
    from v5_1_visible_entry_proof import (
        PUBLISH_RELATIVE_PATH as VISIBLE_ENTRY_PROOF_RELATIVE_PATH,
        validate_visible_entry_proof,
    )
    from v5_1_poc_expansion_proof import (
        PUBLISH_RELATIVE_PATH as POC_EXPANSION_PROOF_RELATIVE_PATH,
        validate_poc_expansion_proof,
    )
    from v5_1_visible_script_record import (
        PUBLISH_RELATIVE_PATH as VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH,
        validate_visible_script_roundtrip,
    )
    from v5_1_visible_unicode_mapping import (
        PUBLISH_RELATIVE_PATH as VISIBLE_UNICODE_MAPPING_RELATIVE_PATH,
        validate_visible_unicode_mapping,
    )
    from v5_1_initial_font_page_trace import (
        PUBLISH_RELATIVE_PATH as INITIAL_FONT_PAGE_TRACE_RELATIVE_PATH,
        validate_initial_font_page_trace,
    )
    from v5_1_font_transfer_source import (
        PUBLISH_RELATIVE_PATH as FONT_TRANSFER_SOURCE_RELATIVE_PATH,
        validate_font_transfer_source,
    )
    from v5_1_confirmed_group_extract import (
        PUBLISH_RELATIVE_PATH as CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH,
        validate_confirmed_group_extract,
    )
    from v5_1_group_context_resolution import (
        PUBLISH_RELATIVE_PATH as GROUP_CONTEXT_RESOLUTION_RELATIVE_PATH,
        validate_group_context_resolution,
    )
    from v5_1_group_runtime_context import (
        PUBLISH_RELATIVE_PATH as GROUP_RUNTIME_CONTEXT_RELATIVE_PATH,
        validate_group_runtime_context,
    )
    from v5_1_group_source_delta import (
        PUBLISH_RELATIVE_PATH as GROUP_SOURCE_DELTA_RELATIVE_PATH,
        validate_group_source_delta,
    )
    from v5_1_source_group_codec_probe import (
        PUBLISH_RELATIVE_PATH as SOURCE_GROUP_CODEC_PROBE_RELATIVE_PATH,
        validate_source_group_codec_probe,
    )
    from v5_1_source_huffman_locator import (
        PUBLISH_RELATIVE_PATH as SOURCE_HUFFMAN_LOCATOR_RELATIVE_PATH,
        validate_source_huffman_locator,
    )
    from v5_1_source_record_pairing import (
        PUBLISH_RELATIVE_PATH as SOURCE_RECORD_PAIRING_RELATIVE_PATH,
        validate_source_record_pairing,
    )
    from v5_1_target_group_usage import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_USAGE_RELATIVE_PATH,
        validate_target_group_usage,
    )
    from v5_1_decoder_caller_resolution import (
        PUBLISH_RELATIVE_PATH as DECODER_CALLER_RESOLUTION_RELATIVE_PATH,
        validate_decoder_caller_resolution,
    )
    from v5_1_target_group_stream_map import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_STREAM_MAP_RELATIVE_PATH,
        validate_target_group_stream_map,
    )
    from v5_1_target_group_population import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_POPULATION_RELATIVE_PATH,
        validate_target_group_population,
    )
    from v5_1_target_group_population_decode import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_POPULATION_DECODE_RELATIVE_PATH,
        validate_target_group_population_decode,
    )
    from v5_1_target_group_expanded_corpus import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_EXPANDED_CORPUS_RELATIVE_PATH,
        validate_target_group_expanded_corpus,
    )
    from v5_1_target_group_expanded_glyphs import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH,
        validate_target_group_expanded_glyphs,
    )
    from v5_1_target_group_non_hangul_glyphs import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_NON_HANGUL_GLYPHS_RELATIVE_PATH,
        validate_target_group_non_hangul_glyphs,
    )
    from v5_1_target_group_record_quality import (
        PUBLISH_RELATIVE_PATH as TARGET_GROUP_RECORD_QUALITY_RELATIVE_PATH,
        validate_target_group_record_quality,
    )
    from v5_1_source_script_reference import (
        PUBLISH_RELATIVE_PATH as SOURCE_SCRIPT_REFERENCE_RELATIVE_PATH,
        validate_source_script_reference,
    )
    from v5_1_source_target_anchor import (
        PUBLISH_RELATIVE_PATH as SOURCE_TARGET_ANCHOR_RELATIVE_PATH,
        validate_source_target_anchor,
    )
    from v5_1_source_target_section_projection import (
        PUBLISH_RELATIVE_PATH as SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH,
        validate_source_target_section_projection,
    )
    from v5_1_source_target_structural_corroboration import (
        PUBLISH_RELATIVE_PATH
        as SOURCE_TARGET_STRUCTURAL_CORROBORATION_RELATIVE_PATH,
        validate_source_target_structural_corroboration,
    )
    from v5_1_source_target_runtime_sequence import (
        PUBLISH_RELATIVE_PATH as SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH,
        validate_source_target_runtime_sequence,
    )
    from v5_1_source_target_runtime_context import (
        PUBLISH_RELATIVE_PATH as SOURCE_TARGET_RUNTIME_CONTEXT_RELATIVE_PATH,
        validate_source_target_runtime_context,
    )
    from v5_1_runtime_context_glyph_demand import (
        PUBLISH_RELATIVE_PATH as RUNTIME_CONTEXT_GLYPH_DEMAND_RELATIVE_PATH,
        validate_runtime_context_glyph_demand,
    )
    from v5_1_active_vram_route import (
        PUBLISH_RELATIVE_PATH as ACTIVE_VRAM_ROUTE_RELATIVE_PATH,
        validate_active_vram_route,
    )
    from v5_1_active_ram_producer import (
        PUBLISH_RELATIVE_PATH as ACTIVE_RAM_PRODUCER_RELATIVE_PATH,
        validate_active_ram_producer,
    )
    from v5_1_active_ram_writer_source import (
        PUBLISH_RELATIVE_PATH as ACTIVE_RAM_WRITER_SOURCE_RELATIVE_PATH,
        validate_active_ram_writer_source,
    )
    from v5_1_active_ram_register_trace import (
        PUBLISH_RELATIVE_PATH as ACTIVE_RAM_REGISTER_TRACE_RELATIVE_PATH,
        validate_active_ram_register_trace,
    )
    from v5_1_active_register_rom_source import (
        PUBLISH_RELATIVE_PATH as ACTIVE_REGISTER_ROM_SOURCE_RELATIVE_PATH,
        validate_active_register_rom_source,
    )
    from v5_1_active_rom_source_role import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_SOURCE_ROLE_RELATIVE_PATH,
        validate_active_rom_source_role,
    )
    from v5_1_active_rom_read_block import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_READ_BLOCK_RELATIVE_PATH,
        validate_active_rom_read_block,
    )
    from v5_1_active_rom_lookup_index_producer import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_LOOKUP_INDEX_RELATIVE_PATH,
        validate_active_rom_lookup_index_producer,
    )
    from v5_1_active_rom_path_scope import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_PATH_SCOPE_RELATIVE_PATH,
        validate_active_rom_path_scope,
    )
    from v5_1_first_context_translated_vram_diff import (
        PUBLISH_RELATIVE_PATH as TRANSLATED_VRAM_DIFF_RELATIVE_PATH,
        validate_first_context_translated_vram_diff,
    )
    from v5_1_first_context_translated_glyph_route import (
        PUBLISH_RELATIVE_PATH as TRANSLATED_GLYPH_ROUTE_RELATIVE_PATH,
        validate_first_context_translated_glyph_route,
    )
    from v5_1_first_context_direct_renderer_capture import (
        PUBLISH_RELATIVE_PATH as DIRECT_RENDERER_CAPTURE_RELATIVE_PATH,
        PUBLISH_IMAGE_RELATIVE_PATH as DIRECT_RENDERER_CAPTURE_IMAGE_RELATIVE_PATH,
        validate_first_context_direct_renderer_capture,
    )
    from v5_1_active_rom_cursor_reset import (
        PUBLISH_RELATIVE_PATH as ACTIVE_ROM_CURSOR_RESET_RELATIVE_PATH,
        validate_active_rom_cursor_reset,
    )
    from v5_1_critical_path import (
        PUBLISH_RELATIVE_PATH as CRITICAL_PATH_RELATIVE_PATH,
        validate_critical_path,
    )
    from v5_1_runtime_context_glyph_candidates import (
        PUBLISH_RELATIVE_PATH
        as RUNTIME_CONTEXT_GLYPH_CANDIDATES_RELATIVE_PATH,
        validate_runtime_context_glyph_candidates,
    )
    from v5_1_runtime_context_glyph_review import (
        PUBLISH_RELATIVE_PATH as RUNTIME_CONTEXT_GLYPH_REVIEW_RELATIVE_PATH,
        validate_runtime_context_glyph_review,
    )
    from v5_1_runtime_context_glyph_preservation import (
        PUBLISH_RELATIVE_PATH
        as RUNTIME_CONTEXT_GLYPH_PRESERVATION_RELATIVE_PATH,
        validate_runtime_context_glyph_preservation,
    )
    from v5_1_first_context_translation_review import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_REVIEW_RELATIVE_PATH,
        validate_first_context_translation_review,
    )
    from v5_1_first_context_translation_approval import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_APPROVAL_RELATIVE_PATH,
        validate_first_context_translation_approval,
    )
    from v5_1_first_context_translation_capacity import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_CAPACITY_RELATIVE_PATH,
        validate_first_context_translation_capacity,
    )
    from v5_1_first_context_translation_encoding import (
        FAILURE_PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_ENCODING_FAILURE_RELATIVE_PATH,
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_ENCODING_RELATIVE_PATH,
        validate_first_context_translation_encoding,
        validate_first_context_translation_encoding_failure,
    )
    from v5_1_first_context_record_reinsertion import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_RECORD_REINSERTION_RELATIVE_PATH,
        validate_first_context_record_reinsertion,
    )
    from v5_1_first_context_translation_test_build import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_TEST_BUILD_RELATIVE_PATH,
        validate_first_context_translation_test_build,
    )
    from v5_1_first_context_translation_runtime_capture import (
        FAILURE_PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_FAILURE_RELATIVE_PATH,
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_RELATIVE_PATH,
        validate_first_context_translation_runtime_capture,
    )
    from v5_1_first_context_translation_visual_review import (
        PUBLISH_RELATIVE_PATH
        as FIRST_CONTEXT_TRANSLATION_VISUAL_REVIEW_RELATIVE_PATH,
        validate_first_context_translation_visual_review,
    )
    from v5_1_first_context_consumer_trace import (
        PUBLISH_RELATIVE_PATH as FIRST_CONTEXT_CONSUMER_TRACE_RELATIVE_PATH,
        validate_first_context_consumer_trace,
    )
    from v5_1_runtime_stage_failure import (
        validate_first_context_runtime_capture_failure,
    )
    from v5_1_group_text_candidate_resolution import (
        PUBLISH_RELATIVE_PATH as GROUP_TEXT_CANDIDATE_RELATIVE_PATH,
        validate_group_text_candidate_resolution,
    )
    from v5_1_unmatched_glyph_fuzzy import (
        PUBLISH_RELATIVE_PATH as UNMATCHED_GLYPH_FUZZY_RELATIVE_PATH,
        validate_unmatched_glyph_fuzzy,
    )
    from v5_1_group_script_corpus import (
        PUBLISH_RELATIVE_PATH as GROUP_SCRIPT_CORPUS_RELATIVE_PATH,
        validate_group_script_corpus,
    )
    from v5_1_confirmed_group_unicode import (
        PUBLISH_RELATIVE_PATH as CONFIRMED_GROUP_UNICODE_RELATIVE_PATH,
        validate_confirmed_group_unicode,
    )
    from v5_1_progress_preview import (
        PUBLISH_IMAGE_RELATIVE_PATH,
        PUBLISH_RECEIPT_RELATIVE_PATH,
        load_validated_progress_image,
        validate_progress_preview,
    )
    from v5_1_runtime_diagnostic import validate_runtime_diagnostic
    from v5_1_runtime_hit_resolver import validate_consumer_resolution
    from v5_1_runtime_observation import validate_runtime_observation
    from v5_1_renderer_observation import validate_renderer_observation
    from v5_1_renderer_output_trace import (
        PUBLISH_RELATIVE_PATH as RENDERER_OUTPUT_TRACE_RELATIVE_PATH,
        validate_renderer_output_trace,
    )
    from v5_1_route_capture import validate_route_capture
    from v5_1_safe_observation import _git, _normalized_remote

EXPECTED_REMOTE = "github.com/Domingo8666/ShiningForceKR"
DEFAULT_GIT_NAME = "Domingo8666"
DEFAULT_GIT_EMAIL = "145947995+Domingo8666@users.noreply.github.com"
DIRECT_RENDERER_CAPTURE_FAILURE_STAGE_RELATIVE_PATH = Path(
    "analysis/device/"
    "v5_1_latest_first_context_direct_renderer_capture_failure_stage.txt"
)
DIRECT_RENDERER_CAPTURE_FAILURE_STAGES = {
    "first-context-direct-renderer-initialize",
    "first-context-direct-renderer-media",
    "first-context-direct-renderer-anchor",
    "first-context-direct-renderer-context",
    "first-context-direct-renderer-vram",
    "first-context-direct-renderer-screenshot",
    "first-context-direct-renderer-screenshot-get",
    "first-context-direct-renderer-screenshot-parse",
    "first-context-direct-renderer-screenshot-write",
    "first-context-direct-renderer-alignment",
    "first-context-direct-renderer-local-report",
    "first-context-direct-renderer-publish-image",
    "first-context-direct-renderer-artifact",
    "unavailable",
}

SAFE_ARTIFACTS = {
    Path("analysis/device/v5_1_latest_decoder_register_trace.json"):
        validate_decoder_register_trace,
    Path("analysis/device/v5_1_latest_decoder_stream_resolution.json"):
        validate_decoder_stream_resolution,
    Path("analysis/device/v5_1_latest_runtime_observation.json"):
        validate_runtime_observation,
    Path("analysis/device/v5_1_latest_renderer_observation.json"):
        validate_renderer_observation,
    Path("analysis/device/v5_1_latest_route_capture.json"):
        validate_route_capture,
    Path("analysis/device/v5_1_latest_runtime_diagnostic.json"):
        validate_runtime_diagnostic,
    Path("analysis/device/v5_1_latest_consumer_resolution.json"):
        validate_consumer_resolution,
    DISPLAY_CAPTURE_RELATIVE_PATH: validate_display_capture,
    Path("analysis/device/v5_1_latest_display_comparison.json"):
        validate_display_comparison,
    Path("analysis/device/v5_1_latest_display_review.json"):
        validate_display_review,
    VISIBLE_ENTRY_PROOF_RELATIVE_PATH: validate_visible_entry_proof,
    POC_EXPANSION_PROOF_RELATIVE_PATH: validate_poc_expansion_proof,
    VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH:
        validate_visible_script_roundtrip,
    RENDERER_OUTPUT_TRACE_RELATIVE_PATH:
        validate_renderer_output_trace,
    VISIBLE_UNICODE_MAPPING_RELATIVE_PATH:
        validate_visible_unicode_mapping,
    INITIAL_FONT_PAGE_TRACE_RELATIVE_PATH:
        validate_initial_font_page_trace,
    FONT_TRANSFER_SOURCE_RELATIVE_PATH:
        validate_font_transfer_source,
    CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH:
        validate_confirmed_group_extract,
    GROUP_CONTEXT_RESOLUTION_RELATIVE_PATH:
        validate_group_context_resolution,
    GROUP_RUNTIME_CONTEXT_RELATIVE_PATH:
        validate_group_runtime_context,
    GROUP_SOURCE_DELTA_RELATIVE_PATH:
        validate_group_source_delta,
    SOURCE_GROUP_CODEC_PROBE_RELATIVE_PATH:
        validate_source_group_codec_probe,
    SOURCE_HUFFMAN_LOCATOR_RELATIVE_PATH:
        validate_source_huffman_locator,
    SOURCE_RECORD_PAIRING_RELATIVE_PATH:
        validate_source_record_pairing,
    TARGET_GROUP_USAGE_RELATIVE_PATH:
        validate_target_group_usage,
    DECODER_CALLER_RESOLUTION_RELATIVE_PATH:
        validate_decoder_caller_resolution,
    TARGET_GROUP_STREAM_MAP_RELATIVE_PATH:
        validate_target_group_stream_map,
    TARGET_GROUP_POPULATION_RELATIVE_PATH:
        validate_target_group_population,
    TARGET_GROUP_POPULATION_DECODE_RELATIVE_PATH:
        validate_target_group_population_decode,
    TARGET_GROUP_EXPANDED_CORPUS_RELATIVE_PATH:
        validate_target_group_expanded_corpus,
    TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH:
        validate_target_group_expanded_glyphs,
    TARGET_GROUP_NON_HANGUL_GLYPHS_RELATIVE_PATH:
        validate_target_group_non_hangul_glyphs,
    TARGET_GROUP_RECORD_QUALITY_RELATIVE_PATH:
        validate_target_group_record_quality,
    SOURCE_SCRIPT_REFERENCE_RELATIVE_PATH:
        validate_source_script_reference,
    SOURCE_TARGET_ANCHOR_RELATIVE_PATH:
        validate_source_target_anchor,
    SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH:
        validate_source_target_section_projection,
    SOURCE_TARGET_STRUCTURAL_CORROBORATION_RELATIVE_PATH:
        validate_source_target_structural_corroboration,
    SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH:
        validate_source_target_runtime_sequence,
    SOURCE_TARGET_RUNTIME_CONTEXT_RELATIVE_PATH:
        validate_source_target_runtime_context,
    RUNTIME_CONTEXT_GLYPH_DEMAND_RELATIVE_PATH:
        validate_runtime_context_glyph_demand,
    ACTIVE_VRAM_ROUTE_RELATIVE_PATH:
        validate_active_vram_route,
    ACTIVE_RAM_PRODUCER_RELATIVE_PATH:
        validate_active_ram_producer,
    ACTIVE_RAM_WRITER_SOURCE_RELATIVE_PATH:
        validate_active_ram_writer_source,
    ACTIVE_RAM_REGISTER_TRACE_RELATIVE_PATH:
        validate_active_ram_register_trace,
    ACTIVE_REGISTER_ROM_SOURCE_RELATIVE_PATH:
        validate_active_register_rom_source,
    ACTIVE_ROM_SOURCE_ROLE_RELATIVE_PATH:
        validate_active_rom_source_role,
    ACTIVE_ROM_READ_BLOCK_RELATIVE_PATH:
        validate_active_rom_read_block,
    ACTIVE_ROM_LOOKUP_INDEX_RELATIVE_PATH:
        validate_active_rom_lookup_index_producer,
    ACTIVE_ROM_PATH_SCOPE_RELATIVE_PATH:
        validate_active_rom_path_scope,
    TRANSLATED_VRAM_DIFF_RELATIVE_PATH:
        validate_first_context_translated_vram_diff,
    TRANSLATED_GLYPH_ROUTE_RELATIVE_PATH:
        validate_first_context_translated_glyph_route,
    DIRECT_RENDERER_CAPTURE_RELATIVE_PATH:
        validate_first_context_direct_renderer_capture,
    ACTIVE_ROM_CURSOR_RESET_RELATIVE_PATH:
        validate_active_rom_cursor_reset,
    CRITICAL_PATH_RELATIVE_PATH:
        validate_critical_path,
    RUNTIME_CONTEXT_GLYPH_CANDIDATES_RELATIVE_PATH:
        validate_runtime_context_glyph_candidates,
    RUNTIME_CONTEXT_GLYPH_REVIEW_RELATIVE_PATH:
        validate_runtime_context_glyph_review,
    RUNTIME_CONTEXT_GLYPH_PRESERVATION_RELATIVE_PATH:
        validate_runtime_context_glyph_preservation,
    FIRST_CONTEXT_TRANSLATION_REVIEW_RELATIVE_PATH:
        validate_first_context_translation_review,
    FIRST_CONTEXT_TRANSLATION_APPROVAL_RELATIVE_PATH:
        validate_first_context_translation_approval,
    FIRST_CONTEXT_TRANSLATION_CAPACITY_RELATIVE_PATH:
        validate_first_context_translation_capacity,
    FIRST_CONTEXT_TRANSLATION_ENCODING_RELATIVE_PATH:
        validate_first_context_translation_encoding,
    FIRST_CONTEXT_TRANSLATION_ENCODING_FAILURE_RELATIVE_PATH:
        validate_first_context_translation_encoding_failure,
    FIRST_CONTEXT_RECORD_REINSERTION_RELATIVE_PATH:
        validate_first_context_record_reinsertion,
    FIRST_CONTEXT_TRANSLATION_TEST_BUILD_RELATIVE_PATH:
        validate_first_context_translation_test_build,
    FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_RELATIVE_PATH:
        validate_first_context_translation_runtime_capture,
    FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_FAILURE_RELATIVE_PATH:
        validate_first_context_runtime_capture_failure,
    FIRST_CONTEXT_TRANSLATION_VISUAL_REVIEW_RELATIVE_PATH:
        validate_first_context_translation_visual_review,
    FIRST_CONTEXT_CONSUMER_TRACE_RELATIVE_PATH:
        validate_first_context_consumer_trace,
    GROUP_TEXT_CANDIDATE_RELATIVE_PATH:
        validate_group_text_candidate_resolution,
    UNMATCHED_GLYPH_FUZZY_RELATIVE_PATH:
        validate_unmatched_glyph_fuzzy,
    GROUP_SCRIPT_CORPUS_RELATIVE_PATH:
        validate_group_script_corpus,
    CONFIRMED_GROUP_UNICODE_RELATIVE_PATH:
        validate_confirmed_group_unicode,
    PUBLISH_RECEIPT_RELATIVE_PATH: validate_progress_preview,
}
SAFE_BINARY_ARTIFACTS = {
    PUBLISH_IMAGE_RELATIVE_PATH: PUBLISH_RECEIPT_RELATIVE_PATH,
    DIRECT_RENDERER_CAPTURE_IMAGE_RELATIVE_PATH:
        DIRECT_RENDERER_CAPTURE_RELATIVE_PATH,
}
SAFE_TEXT_ARTIFACTS = {
    DIRECT_RENDERER_CAPTURE_FAILURE_STAGE_RELATIVE_PATH:
        DIRECT_RENDERER_CAPTURE_FAILURE_STAGES,
}


def _load_validated_artifacts(root: Path) -> dict[Path, dict[str, object]]:
    artifacts: dict[Path, dict[str, object]] = {}
    for relative, validator in SAFE_ARTIFACTS.items():
        path = root / relative
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError(f"{relative} must contain a JSON object")
            validator(value)
        except (OSError, ValueError, json.JSONDecodeError):
            # A stale or malformed local artifact must never block publication
            # of newly validated safe artifacts, and is never staged itself.
            continue
        artifacts[relative] = value
    if not artifacts:
        raise ValueError("no sanitized runtime artifacts are available")

    observation = artifacts.get(
        Path("analysis/device/v5_1_latest_runtime_observation.json")
    )
    resolution = artifacts.get(
        Path("analysis/device/v5_1_latest_consumer_resolution.json")
    )
    if (
        observation is not None
        and resolution is not None
        and observation["target_sha256"] != resolution["target_sha256"]
    ):
        raise ValueError("runtime observation and resolution identities disagree")
    renderer = artifacts.get(
        Path("analysis/device/v5_1_latest_renderer_observation.json")
    )
    if (
        renderer is not None
        and observation is not None
        and renderer["target_sha256"] != observation["target_sha256"]
    ):
        raise ValueError("runtime and renderer observation identities disagree")
    route_capture = artifacts.get(
        Path("analysis/device/v5_1_latest_route_capture.json")
    )
    if (
        route_capture is not None
        and renderer is not None
        and route_capture["target_sha256"] != renderer["target_sha256"]
    ):
        raise ValueError("route and renderer observation identities disagree")
    display_capture = artifacts.get(
        Path("analysis/device/v5_1_latest_display_capture.json")
    )
    if (
        display_capture is not None
        and resolution is not None
        and display_capture["baseline_target_sha256"]
        != resolution["target_sha256"]
    ):
        raise ValueError("display capture and resolution identities disagree")
    display_review = artifacts.get(
        Path("analysis/device/v5_1_latest_display_review.json")
    )
    display_comparison = artifacts.get(
        Path("analysis/device/v5_1_latest_display_comparison.json")
    )
    if (
        display_comparison is not None
        and resolution is not None
        and display_comparison["baseline_target_sha256"]
        != resolution["target_sha256"]
    ):
        raise ValueError("display comparison and resolution identities disagree")
    if (
        display_comparison is not None
        and display_capture is not None
        and display_comparison["test_target_sha256"]
        == display_capture["test_target_sha256"]
        and display_comparison["baseline_target_sha256"]
        != display_capture["baseline_target_sha256"]
    ):
        raise ValueError("display capture and comparison identities disagree")
    if (
        display_review is not None
        and display_capture is not None
        and display_review["test_target_sha256"]
        == display_capture["test_target_sha256"]
    ):
        if (
            display_review["baseline_target_sha256"]
            != display_capture["baseline_target_sha256"]
        ):
            raise ValueError("display capture and review identities disagree")
        expected_hashes: list[str] = []
        for item in display_capture["captures"]:
            digest = str(item["png_sha256"])
            if digest not in expected_hashes:
                expected_hashes.append(digest)
        post_advance = display_capture["post_advance_capture"]
        if (
            post_advance is not None
            and post_advance["png_sha256"] not in expected_hashes
        ):
            expected_hashes.append(post_advance["png_sha256"])
        if display_review["capture_png_sha256s"] != expected_hashes:
            raise ValueError("display capture and review PNG identities disagree")
    progress_preview = artifacts.get(PUBLISH_RECEIPT_RELATIVE_PATH)
    if progress_preview is not None:
        if (
            display_capture is None
            or display_capture["status"]
            != "capture-ready-human-review-required"
            or progress_preview["baseline_target_sha256"]
            != display_capture["baseline_target_sha256"]
            or progress_preview["test_target_sha256"]
            != display_capture["test_target_sha256"]
            or progress_preview["capture_png_sha256"]
            not in {
                item["png_sha256"]
                for item in display_capture["captures"]
            } | (
                {
                    display_capture["post_advance_capture"]["png_sha256"]
                }
                if display_capture["post_advance_capture"] is not None
                else set()
            )
        ):
            artifacts.pop(PUBLISH_RECEIPT_RELATIVE_PATH)
    visible_entry_proof = artifacts.get(VISIBLE_ENTRY_PROOF_RELATIVE_PATH)
    if visible_entry_proof is not None:
        if (
            display_capture is None
            or display_comparison is None
            or display_review is None
            or visible_entry_proof["baseline_target_sha256"]
            != display_capture["baseline_target_sha256"]
            or visible_entry_proof["test_target_sha256"]
            != display_capture["test_target_sha256"]
            or visible_entry_proof["baseline_target_sha256"]
            != display_comparison["baseline_target_sha256"]
            or visible_entry_proof["test_target_sha256"]
            != display_comparison["test_target_sha256"]
            or visible_entry_proof["baseline_target_sha256"]
            != display_review["baseline_target_sha256"]
            or visible_entry_proof["test_target_sha256"]
            != display_review["test_target_sha256"]
            or visible_entry_proof["runtime_entry"]["physical_start"]
            != display_review["reviewed_stream"]["physical_start"]
            or visible_entry_proof["runtime_entry"]["logical_start"]
            != display_review["reviewed_stream"]["logical_start"]
            or visible_entry_proof["runtime_entry"]["mapped_bank"]
            != display_review["reviewed_stream"]["mapped_bank"]
        ):
            artifacts.pop(VISIBLE_ENTRY_PROOF_RELATIVE_PATH)
    poc_expansion_proof = artifacts.get(POC_EXPANSION_PROOF_RELATIVE_PATH)
    if poc_expansion_proof is not None:
        if (
            display_capture is None
            or display_comparison is None
            or display_review is None
            or progress_preview is None
            or poc_expansion_proof["baseline_target_sha256"]
            != display_capture["baseline_target_sha256"]
            or poc_expansion_proof["test_target_sha256"]
            != display_capture["test_target_sha256"]
            or poc_expansion_proof["test_target_sha256"]
            != display_comparison["test_target_sha256"]
            or poc_expansion_proof["test_target_sha256"]
            != display_review["test_target_sha256"]
            or poc_expansion_proof["display_proof"]["capture_png_sha256"]
            != progress_preview["capture_png_sha256"]
        ):
            artifacts.pop(POC_EXPANSION_PROOF_RELATIVE_PATH)
    visible_script_roundtrip = artifacts.get(
        VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH
    )
    if visible_script_roundtrip is not None:
        if (
            poc_expansion_proof is None
            or visible_script_roundtrip["baseline_target_sha256"]
            != poc_expansion_proof["baseline_target_sha256"]
            or visible_script_roundtrip["source_expansion_test_sha256"]
            != poc_expansion_proof["test_target_sha256"]
            or visible_script_roundtrip["runtime_entry"]["physical_start"]
            != poc_expansion_proof["runtime_entry"]["physical_start"]
            or visible_script_roundtrip["runtime_entry"]["logical_start"]
            != poc_expansion_proof["runtime_entry"]["logical_start"]
        ):
            artifacts.pop(VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH)
    visible_script_roundtrip = artifacts.get(
        VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH
    )
    renderer_output_trace = artifacts.get(
        RENDERER_OUTPUT_TRACE_RELATIVE_PATH
    )
    if renderer_output_trace is not None:
        if (
            visible_script_roundtrip is None
            or renderer_output_trace["target_sha256"]
            != visible_script_roundtrip["baseline_target_sha256"]
            or renderer_output_trace["runtime_entry"]["physical_start"]
            != visible_script_roundtrip["runtime_entry"]["physical_start"]
            or renderer_output_trace["runtime_entry"]["logical_start"]
            != visible_script_roundtrip["runtime_entry"]["logical_start"]
            or renderer_output_trace["runtime_entry"]["mapped_bank"]
            != visible_script_roundtrip["runtime_entry"]["mapped_bank"]
        ):
            artifacts.pop(RENDERER_OUTPUT_TRACE_RELATIVE_PATH)
    renderer_output_trace = artifacts.get(
        RENDERER_OUTPUT_TRACE_RELATIVE_PATH
    )
    visible_unicode_mapping = artifacts.get(
        VISIBLE_UNICODE_MAPPING_RELATIVE_PATH
    )
    if visible_unicode_mapping is not None:
        if (
            renderer_output_trace is None
            or visible_script_roundtrip is None
            or visible_unicode_mapping["target_sha256"]
            != renderer_output_trace["target_sha256"]
            or visible_unicode_mapping["target_sha256"]
            != visible_script_roundtrip["baseline_target_sha256"]
            or visible_unicode_mapping["runtime_entry"]
            != visible_script_roundtrip["runtime_entry"]
            or visible_unicode_mapping["renderer_chain_confirmed"] is not True
            or renderer_output_trace["consumer_chain_confirmed"] is not True
        ):
            artifacts.pop(VISIBLE_UNICODE_MAPPING_RELATIVE_PATH)
    visible_unicode_mapping = artifacts.get(
        VISIBLE_UNICODE_MAPPING_RELATIVE_PATH
    )
    initial_font_page_trace = artifacts.get(
        INITIAL_FONT_PAGE_TRACE_RELATIVE_PATH
    )
    if initial_font_page_trace is not None:
        if (
            visible_unicode_mapping is None
            or visible_unicode_mapping["next_checkpoint"]
            != "confirm-runtime-initial-font-page"
            or initial_font_page_trace["target_sha256"]
            != visible_unicode_mapping["target_sha256"]
            or initial_font_page_trace["runtime_entry"]
            != visible_unicode_mapping["runtime_entry"]
            or initial_font_page_trace["candidate_page_count_before"]
            != visible_unicode_mapping["mapping"][
                "initial_page_candidate_count"
            ]
            or initial_font_page_trace["source_mapping_sha256"]
            != sha256_file(root / VISIBLE_UNICODE_MAPPING_RELATIVE_PATH)
        ):
            artifacts.pop(INITIAL_FONT_PAGE_TRACE_RELATIVE_PATH)
    initial_font_page_trace = artifacts.get(
        INITIAL_FONT_PAGE_TRACE_RELATIVE_PATH
    )
    font_transfer_source = artifacts.get(
        FONT_TRANSFER_SOURCE_RELATIVE_PATH
    )
    if font_transfer_source is not None:
        if (
            visible_unicode_mapping is None
            or renderer_output_trace is None
            or initial_font_page_trace is None
            or initial_font_page_trace["next_checkpoint"]
            != "trace-font-transfer-source"
            or font_transfer_source["target_sha256"]
            != visible_unicode_mapping["target_sha256"]
            or font_transfer_source["runtime_entry"]
            != visible_unicode_mapping["runtime_entry"]
            or font_transfer_source["source_mapping_sha256"]
            != sha256_file(root / VISIBLE_UNICODE_MAPPING_RELATIVE_PATH)
            or font_transfer_source["source_renderer_trace_sha256"]
            != sha256_file(root / RENDERER_OUTPUT_TRACE_RELATIVE_PATH)
            or font_transfer_source["source_initial_trace_sha256"]
            != sha256_file(root / INITIAL_FONT_PAGE_TRACE_RELATIVE_PATH)
            or font_transfer_source["candidate_page_count_before"]
            != initial_font_page_trace["candidate_page_count_before"]
        ):
            artifacts.pop(FONT_TRANSFER_SOURCE_RELATIVE_PATH)
    confirmed_group_extract = artifacts.get(
        CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH
    )
    decoder_register_trace = artifacts.get(
        Path("analysis/device/v5_1_latest_decoder_register_trace.json")
    )
    if confirmed_group_extract is not None:
        if (
            decoder_register_trace is None
            or visible_script_roundtrip is None
            or confirmed_group_extract["target_sha256"]
            != visible_script_roundtrip["baseline_target_sha256"]
            or confirmed_group_extract["target_sha256"]
            != decoder_register_trace["target_sha256"]
            or confirmed_group_extract["source_register_trace_sha256"]
            != sha256_file(
                root
                / "analysis/device/v5_1_latest_decoder_register_trace.json"
            )
            or confirmed_group_extract["source_visible_roundtrip_sha256"]
            != sha256_file(root / VISIBLE_SCRIPT_ROUNDTRIP_RELATIVE_PATH)
        ):
            artifacts.pop(CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
    confirmed_group_extract = artifacts.get(
        CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH
    )
    target_group_usage = artifacts.get(TARGET_GROUP_USAGE_RELATIVE_PATH)
    if target_group_usage is not None:
        if (
            confirmed_group_extract is None
            or target_group_usage["target_sha256"]
            != confirmed_group_extract["target_sha256"]
            or target_group_usage["source_group_extract_sha256"]
            != sha256_file(root / CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
        ):
            artifacts.pop(TARGET_GROUP_USAGE_RELATIVE_PATH)
    decoder_caller_resolution = artifacts.get(
        DECODER_CALLER_RESOLUTION_RELATIVE_PATH
    )
    if decoder_caller_resolution is not None:
        if (
            TARGET_GROUP_USAGE_RELATIVE_PATH not in artifacts
            or decoder_caller_resolution["target_sha256"]
            != target_group_usage["target_sha256"]
            or decoder_caller_resolution[
                "source_target_group_usage_sha256"
            ]
            != sha256_file(root / TARGET_GROUP_USAGE_RELATIVE_PATH)
        ):
            artifacts.pop(DECODER_CALLER_RESOLUTION_RELATIVE_PATH)
    target_group_stream_map = artifacts.get(
        TARGET_GROUP_STREAM_MAP_RELATIVE_PATH
    )
    if target_group_stream_map is not None:
        if (
            TARGET_GROUP_USAGE_RELATIVE_PATH not in artifacts
            or confirmed_group_extract is None
            or target_group_stream_map["target_sha256"]
            != target_group_usage["target_sha256"]
            or target_group_stream_map[
                "source_target_group_usage_sha256"
            ]
            != sha256_file(root / TARGET_GROUP_USAGE_RELATIVE_PATH)
            or target_group_stream_map[
                "source_confirmed_group_extract_sha256"
            ]
            != sha256_file(root / CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
        ):
            artifacts.pop(TARGET_GROUP_STREAM_MAP_RELATIVE_PATH)
    target_group_population = artifacts.get(
        TARGET_GROUP_POPULATION_RELATIVE_PATH
    )
    if target_group_population is not None:
        if (
            TARGET_GROUP_USAGE_RELATIVE_PATH not in artifacts
            or TARGET_GROUP_STREAM_MAP_RELATIVE_PATH not in artifacts
            or confirmed_group_extract is None
            or target_group_population["target_sha256"]
            != target_group_usage["target_sha256"]
            or target_group_population[
                "source_target_group_usage_sha256"
            ]
            != sha256_file(root / TARGET_GROUP_USAGE_RELATIVE_PATH)
            or target_group_population["source_stream_map_sha256"]
            != sha256_file(root / TARGET_GROUP_STREAM_MAP_RELATIVE_PATH)
            or target_group_population[
                "source_confirmed_group_extract_sha256"
            ]
            != sha256_file(root / CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
        ):
            artifacts.pop(TARGET_GROUP_POPULATION_RELATIVE_PATH)
    target_group_population_decode = artifacts.get(
        TARGET_GROUP_POPULATION_DECODE_RELATIVE_PATH
    )
    if target_group_population_decode is not None:
        if (
            TARGET_GROUP_POPULATION_RELATIVE_PATH not in artifacts
            or target_group_population_decode["target_sha256"]
            != target_group_population["target_sha256"]
            or target_group_population_decode["source_population_sha256"]
            != sha256_file(root / TARGET_GROUP_POPULATION_RELATIVE_PATH)
        ):
            artifacts.pop(TARGET_GROUP_POPULATION_DECODE_RELATIVE_PATH)
    target_group_expanded_glyphs = artifacts.get(
        TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH
    )
    if target_group_expanded_glyphs is not None:
        if (
            TARGET_GROUP_POPULATION_DECODE_RELATIVE_PATH not in artifacts
            or target_group_expanded_glyphs["target_sha256"]
            != target_group_population_decode["target_sha256"]
            or target_group_expanded_glyphs[
                "source_population_decode_sha256"
            ]
            != sha256_file(
                root / TARGET_GROUP_POPULATION_DECODE_RELATIVE_PATH
            )
        ):
            artifacts.pop(TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH)
    target_group_non_hangul_glyphs = artifacts.get(
        TARGET_GROUP_NON_HANGUL_GLYPHS_RELATIVE_PATH
    )
    if target_group_non_hangul_glyphs is not None:
        if (
            TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH not in artifacts
            or target_group_non_hangul_glyphs["target_sha256"]
            != target_group_expanded_glyphs["target_sha256"]
            or target_group_non_hangul_glyphs[
                "source_expanded_glyphs_sha256"
            ]
            != sha256_file(root / TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH)
        ):
            artifacts.pop(TARGET_GROUP_NON_HANGUL_GLYPHS_RELATIVE_PATH)
    target_group_expanded_corpus = artifacts.get(
        TARGET_GROUP_EXPANDED_CORPUS_RELATIVE_PATH
    )
    if target_group_expanded_corpus is not None:
        if (
            TARGET_GROUP_POPULATION_DECODE_RELATIVE_PATH not in artifacts
            or TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH not in artifacts
            or TARGET_GROUP_NON_HANGUL_GLYPHS_RELATIVE_PATH not in artifacts
            or target_group_expanded_corpus["target_sha256"]
            != target_group_population_decode["target_sha256"]
            or target_group_expanded_corpus[
                "source_population_decode_sha256"
            ]
            != sha256_file(
                root / TARGET_GROUP_POPULATION_DECODE_RELATIVE_PATH
            )
            or target_group_expanded_corpus[
                "source_expanded_glyphs_sha256"
            ]
            != sha256_file(root / TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH)
            or target_group_expanded_corpus[
                "source_non_hangul_glyphs_sha256"
            ]
            != sha256_file(
                root / TARGET_GROUP_NON_HANGUL_GLYPHS_RELATIVE_PATH
            )
        ):
            artifacts.pop(TARGET_GROUP_EXPANDED_CORPUS_RELATIVE_PATH)
    target_group_record_quality = artifacts.get(
        TARGET_GROUP_RECORD_QUALITY_RELATIVE_PATH
    )
    if target_group_record_quality is not None:
        if (
            TARGET_GROUP_EXPANDED_CORPUS_RELATIVE_PATH not in artifacts
            or target_group_record_quality["target_sha256"]
            != target_group_expanded_corpus["target_sha256"]
            or target_group_record_quality[
                "source_expanded_corpus_sha256"
            ]
            != sha256_file(root / TARGET_GROUP_EXPANDED_CORPUS_RELATIVE_PATH)
        ):
            artifacts.pop(TARGET_GROUP_RECORD_QUALITY_RELATIVE_PATH)
    source_target_anchor = artifacts.get(SOURCE_TARGET_ANCHOR_RELATIVE_PATH)
    if source_target_anchor is not None:
        if (
            TARGET_GROUP_RECORD_QUALITY_RELATIVE_PATH not in artifacts
            or SOURCE_SCRIPT_REFERENCE_RELATIVE_PATH not in artifacts
            or source_target_anchor["target_sha256"]
            != target_group_record_quality["target_sha256"]
            or source_target_anchor["source_record_quality_sha256"]
            != sha256_file(root / TARGET_GROUP_RECORD_QUALITY_RELATIVE_PATH)
            or source_target_anchor["source_script_reference_sha256"]
            != sha256_file(root / SOURCE_SCRIPT_REFERENCE_RELATIVE_PATH)
        ):
            artifacts.pop(SOURCE_TARGET_ANCHOR_RELATIVE_PATH)
    source_target_section_projection = artifacts.get(
        SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH
    )
    if source_target_section_projection is not None:
        if (
            TARGET_GROUP_RECORD_QUALITY_RELATIVE_PATH not in artifacts
            or SOURCE_SCRIPT_REFERENCE_RELATIVE_PATH not in artifacts
            or SOURCE_TARGET_ANCHOR_RELATIVE_PATH not in artifacts
            or source_target_section_projection["target_sha256"]
            != target_group_record_quality["target_sha256"]
            or source_target_section_projection[
                "source_record_quality_sha256"
            ]
            != sha256_file(root / TARGET_GROUP_RECORD_QUALITY_RELATIVE_PATH)
            or source_target_section_projection[
                "source_script_reference_sha256"
            ]
            != sha256_file(root / SOURCE_SCRIPT_REFERENCE_RELATIVE_PATH)
            or source_target_section_projection[
                "source_target_anchor_sha256"
            ]
            != sha256_file(root / SOURCE_TARGET_ANCHOR_RELATIVE_PATH)
        ):
            artifacts.pop(SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH)
    source_target_structural_corroboration = artifacts.get(
        SOURCE_TARGET_STRUCTURAL_CORROBORATION_RELATIVE_PATH
    )
    if source_target_structural_corroboration is not None:
        if (
            SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH not in artifacts
            or source_target_structural_corroboration["target_sha256"]
            != source_target_section_projection["target_sha256"]
            or source_target_structural_corroboration[
                "source_section_projection_sha256"
            ]
            != sha256_file(
                root / SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH
            )
        ):
            artifacts.pop(
                SOURCE_TARGET_STRUCTURAL_CORROBORATION_RELATIVE_PATH
            )
    source_target_runtime_sequence = artifacts.get(
        SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH
    )
    if source_target_runtime_sequence is not None:
        if (
            DISPLAY_CAPTURE_RELATIVE_PATH not in artifacts
            or SOURCE_TARGET_STRUCTURAL_CORROBORATION_RELATIVE_PATH
            not in artifacts
            or source_target_runtime_sequence["baseline_target_sha256"]
            != source_target_structural_corroboration["target_sha256"]
            or source_target_runtime_sequence["test_target_sha256"]
            != artifacts[DISPLAY_CAPTURE_RELATIVE_PATH][
                "test_target_sha256"
            ]
            or source_target_runtime_sequence["display_capture_sha256"]
            != sha256_file(root / DISPLAY_CAPTURE_RELATIVE_PATH)
            or source_target_runtime_sequence[
                "structural_corroboration_sha256"
            ]
            != sha256_file(
                root
                / SOURCE_TARGET_STRUCTURAL_CORROBORATION_RELATIVE_PATH
            )
        ):
            artifacts.pop(SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH)
    source_target_runtime_context = artifacts.get(
        SOURCE_TARGET_RUNTIME_CONTEXT_RELATIVE_PATH
    )
    if source_target_runtime_context is not None:
        if (
            SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH not in artifacts
            or SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH not in artifacts
            or source_target_runtime_context["target_sha256"]
            != source_target_section_projection["target_sha256"]
            or source_target_runtime_context[
                "source_section_projection_sha256"
            ]
            != sha256_file(
                root / SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH
            )
            or source_target_runtime_context["runtime_sequence_sha256"]
            != sha256_file(root / SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH)
        ):
            artifacts.pop(SOURCE_TARGET_RUNTIME_CONTEXT_RELATIVE_PATH)
    runtime_context_glyph_demand = artifacts.get(
        RUNTIME_CONTEXT_GLYPH_DEMAND_RELATIVE_PATH
    )
    if runtime_context_glyph_demand is not None:
        if (
            SOURCE_TARGET_RUNTIME_CONTEXT_RELATIVE_PATH not in artifacts
            or SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH not in artifacts
            or SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH not in artifacts
            or runtime_context_glyph_demand["target_sha256"]
            != source_target_runtime_context["target_sha256"]
            or runtime_context_glyph_demand["runtime_context_sha256"]
            != sha256_file(root / SOURCE_TARGET_RUNTIME_CONTEXT_RELATIVE_PATH)
            or runtime_context_glyph_demand[
                "source_section_projection_sha256"
            ]
            != sha256_file(
                root / SOURCE_TARGET_SECTION_PROJECTION_RELATIVE_PATH
            )
            or runtime_context_glyph_demand["runtime_sequence_sha256"]
            != sha256_file(root / SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH)
        ):
            artifacts.pop(RUNTIME_CONTEXT_GLYPH_DEMAND_RELATIVE_PATH)
    runtime_context_glyph_candidates = artifacts.get(
        RUNTIME_CONTEXT_GLYPH_CANDIDATES_RELATIVE_PATH
    )
    if runtime_context_glyph_candidates is not None:
        if (
            RUNTIME_CONTEXT_GLYPH_DEMAND_RELATIVE_PATH not in artifacts
            or TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH not in artifacts
            or TARGET_GROUP_NON_HANGUL_GLYPHS_RELATIVE_PATH not in artifacts
            or runtime_context_glyph_candidates["target_sha256"]
            != runtime_context_glyph_demand["target_sha256"]
            or runtime_context_glyph_candidates[
                "runtime_context_glyph_demand_sha256"
            ]
            != sha256_file(root / RUNTIME_CONTEXT_GLYPH_DEMAND_RELATIVE_PATH)
            or runtime_context_glyph_candidates[
                "target_group_expanded_glyphs_sha256"
            ]
            != sha256_file(root / TARGET_GROUP_EXPANDED_GLYPHS_RELATIVE_PATH)
            or runtime_context_glyph_candidates[
                "target_group_non_hangul_glyphs_sha256"
            ]
            != sha256_file(
                root / TARGET_GROUP_NON_HANGUL_GLYPHS_RELATIVE_PATH
            )
        ):
            artifacts.pop(RUNTIME_CONTEXT_GLYPH_CANDIDATES_RELATIVE_PATH)
    runtime_context_glyph_review = artifacts.get(
        RUNTIME_CONTEXT_GLYPH_REVIEW_RELATIVE_PATH
    )
    if runtime_context_glyph_review is not None:
        if (
            RUNTIME_CONTEXT_GLYPH_DEMAND_RELATIVE_PATH not in artifacts
            or RUNTIME_CONTEXT_GLYPH_CANDIDATES_RELATIVE_PATH
            not in artifacts
            or runtime_context_glyph_review["target_sha256"]
            != runtime_context_glyph_candidates["target_sha256"]
            or runtime_context_glyph_review[
                "runtime_context_glyph_demand_sha256"
            ]
            != sha256_file(root / RUNTIME_CONTEXT_GLYPH_DEMAND_RELATIVE_PATH)
            or runtime_context_glyph_review[
                "runtime_context_glyph_candidates_sha256"
            ]
            != sha256_file(
                root / RUNTIME_CONTEXT_GLYPH_CANDIDATES_RELATIVE_PATH
            )
        ):
            artifacts.pop(RUNTIME_CONTEXT_GLYPH_REVIEW_RELATIVE_PATH)
    runtime_context_glyph_preservation = artifacts.get(
        RUNTIME_CONTEXT_GLYPH_PRESERVATION_RELATIVE_PATH
    )
    if runtime_context_glyph_preservation is not None:
        if (
            RUNTIME_CONTEXT_GLYPH_CANDIDATES_RELATIVE_PATH not in artifacts
            or RUNTIME_CONTEXT_GLYPH_REVIEW_RELATIVE_PATH not in artifacts
            or runtime_context_glyph_preservation["target_sha256"]
            != runtime_context_glyph_review["target_sha256"]
            or runtime_context_glyph_preservation[
                "runtime_context_glyph_candidates_sha256"
            ]
            != sha256_file(
                root / RUNTIME_CONTEXT_GLYPH_CANDIDATES_RELATIVE_PATH
            )
            or runtime_context_glyph_preservation[
                "runtime_context_glyph_review_sha256"
            ]
            != sha256_file(root / RUNTIME_CONTEXT_GLYPH_REVIEW_RELATIVE_PATH)
        ):
            artifacts.pop(RUNTIME_CONTEXT_GLYPH_PRESERVATION_RELATIVE_PATH)
    first_context_translation_review = artifacts.get(
        FIRST_CONTEXT_TRANSLATION_REVIEW_RELATIVE_PATH
    )
    if first_context_translation_review is not None:
        if (
            SOURCE_TARGET_RUNTIME_CONTEXT_RELATIVE_PATH not in artifacts
            or RUNTIME_CONTEXT_GLYPH_PRESERVATION_RELATIVE_PATH
            not in artifacts
            or first_context_translation_review["target_sha256"]
            != runtime_context_glyph_preservation["target_sha256"]
            or first_context_translation_review[
                "source_target_runtime_context_sha256"
            ]
            != sha256_file(
                root / SOURCE_TARGET_RUNTIME_CONTEXT_RELATIVE_PATH
            )
            or first_context_translation_review[
                "runtime_context_glyph_preservation_sha256"
            ]
            != sha256_file(
                root / RUNTIME_CONTEXT_GLYPH_PRESERVATION_RELATIVE_PATH
            )
        ):
            artifacts.pop(FIRST_CONTEXT_TRANSLATION_REVIEW_RELATIVE_PATH)
    first_context_translation_approval = artifacts.get(
        FIRST_CONTEXT_TRANSLATION_APPROVAL_RELATIVE_PATH
    )
    if first_context_translation_approval is not None:
        if (
            FIRST_CONTEXT_TRANSLATION_REVIEW_RELATIVE_PATH not in artifacts
            or first_context_translation_approval["target_sha256"]
            != first_context_translation_review["target_sha256"]
            or first_context_translation_approval[
                "review_batch_sha256"
            ]
            != first_context_translation_review["review_batch_sha256"]
        ):
            artifacts.pop(FIRST_CONTEXT_TRANSLATION_APPROVAL_RELATIVE_PATH)
    first_context_translation_capacity = artifacts.get(
        FIRST_CONTEXT_TRANSLATION_CAPACITY_RELATIVE_PATH
    )
    if first_context_translation_capacity is not None:
        if (
            FIRST_CONTEXT_TRANSLATION_APPROVAL_RELATIVE_PATH not in artifacts
            or first_context_translation_capacity["target_sha256"]
            != first_context_translation_approval["target_sha256"]
            or first_context_translation_capacity["review_batch_sha256"]
            != first_context_translation_approval["review_batch_sha256"]
            or first_context_translation_capacity[
                "first_context_translation_approval_sha256"
            ]
            != sha256_file(
                root / FIRST_CONTEXT_TRANSLATION_APPROVAL_RELATIVE_PATH
            )
        ):
            artifacts.pop(FIRST_CONTEXT_TRANSLATION_CAPACITY_RELATIVE_PATH)
    first_context_translation_encoding = artifacts.get(
        FIRST_CONTEXT_TRANSLATION_ENCODING_RELATIVE_PATH
    )
    if first_context_translation_encoding is not None:
        if (
            FIRST_CONTEXT_TRANSLATION_CAPACITY_RELATIVE_PATH not in artifacts
            or RUNTIME_CONTEXT_GLYPH_PRESERVATION_RELATIVE_PATH not in artifacts
            or first_context_translation_encoding["target_sha256"]
            != first_context_translation_capacity["target_sha256"]
            or first_context_translation_encoding["review_batch_sha256"]
            != first_context_translation_capacity["review_batch_sha256"]
            or first_context_translation_encoding[
                "first_context_translation_capacity_sha256"
            ]
            != sha256_file(
                root / FIRST_CONTEXT_TRANSLATION_CAPACITY_RELATIVE_PATH
            )
            or first_context_translation_encoding[
                "runtime_context_glyph_preservation_sha256"
            ]
            != sha256_file(
                root / RUNTIME_CONTEXT_GLYPH_PRESERVATION_RELATIVE_PATH
            )
        ):
            artifacts.pop(FIRST_CONTEXT_TRANSLATION_ENCODING_RELATIVE_PATH)
    first_context_record_reinsertion = artifacts.get(
        FIRST_CONTEXT_RECORD_REINSERTION_RELATIVE_PATH
    )
    if first_context_record_reinsertion is not None:
        if (
            FIRST_CONTEXT_TRANSLATION_ENCODING_RELATIVE_PATH not in artifacts
            or first_context_record_reinsertion["target_sha256"]
            != first_context_translation_encoding["target_sha256"]
            or first_context_record_reinsertion["review_batch_sha256"]
            != first_context_translation_encoding["review_batch_sha256"]
            or first_context_record_reinsertion[
                "first_context_translation_encoding_sha256"
            ]
            != sha256_file(
                root / FIRST_CONTEXT_TRANSLATION_ENCODING_RELATIVE_PATH
            )
        ):
            artifacts.pop(FIRST_CONTEXT_RECORD_REINSERTION_RELATIVE_PATH)
    first_context_translation_test_build = artifacts.get(
        FIRST_CONTEXT_TRANSLATION_TEST_BUILD_RELATIVE_PATH
    )
    if first_context_translation_test_build is not None:
        if (
            FIRST_CONTEXT_RECORD_REINSERTION_RELATIVE_PATH not in artifacts
            or first_context_translation_test_build["baseline_target_sha256"]
            != first_context_record_reinsertion["target_sha256"]
            or first_context_translation_test_build[
                "first_context_record_reinsertion_sha256"
            ]
            != sha256_file(root / FIRST_CONTEXT_RECORD_REINSERTION_RELATIVE_PATH)
        ):
            artifacts.pop(FIRST_CONTEXT_TRANSLATION_TEST_BUILD_RELATIVE_PATH)
    first_context_translation_runtime_capture = artifacts.get(
        FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_RELATIVE_PATH
    )
    if first_context_translation_runtime_capture is not None:
        if (
            FIRST_CONTEXT_TRANSLATION_TEST_BUILD_RELATIVE_PATH
            not in artifacts
            or SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH not in artifacts
            or first_context_translation_runtime_capture[
                "baseline_target_sha256"
            ]
            != first_context_translation_test_build[
                "baseline_target_sha256"
            ]
            or first_context_translation_runtime_capture[
                "test_target_sha256"
            ]
            != first_context_translation_test_build["test_target_sha256"]
            or first_context_translation_runtime_capture[
                "first_context_translation_test_build_sha256"
            ]
            != sha256_file(
                root / FIRST_CONTEXT_TRANSLATION_TEST_BUILD_RELATIVE_PATH
            )
            or first_context_translation_runtime_capture[
                "source_runtime_sequence_sha256"
            ]
            != sha256_file(root / SOURCE_TARGET_RUNTIME_SEQUENCE_RELATIVE_PATH)
        ):
            artifacts.pop(
                FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_RELATIVE_PATH
            )
    first_context_translation_visual_review = artifacts.get(
        FIRST_CONTEXT_TRANSLATION_VISUAL_REVIEW_RELATIVE_PATH
    )
    if first_context_translation_visual_review is not None:
        if (
            FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_RELATIVE_PATH
            not in artifacts
            or first_context_translation_visual_review["test_target_sha256"]
            != first_context_translation_runtime_capture["test_target_sha256"]
        ):
            artifacts.pop(FIRST_CONTEXT_TRANSLATION_VISUAL_REVIEW_RELATIVE_PATH)
    first_context_consumer_trace = artifacts.get(
        FIRST_CONTEXT_CONSUMER_TRACE_RELATIVE_PATH
    )
    if first_context_consumer_trace is not None:
        normal_consumer_inputs_ready = (
            FIRST_CONTEXT_TRANSLATION_TEST_BUILD_RELATIVE_PATH in artifacts
            and FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_RELATIVE_PATH
            in artifacts
            and FIRST_CONTEXT_TRANSLATION_VISUAL_REVIEW_RELATIVE_PATH
            in artifacts
            and first_context_consumer_trace["test_target_sha256"]
            == first_context_translation_test_build["test_target_sha256"]
            and first_context_consumer_trace[
                "first_context_translation_test_build_sha256"
            ]
            == sha256_file(
                root / FIRST_CONTEXT_TRANSLATION_TEST_BUILD_RELATIVE_PATH
            )
            and first_context_consumer_trace[
                "first_context_translation_runtime_capture_sha256"
            ]
            == sha256_file(
                root / FIRST_CONTEXT_TRANSLATION_RUNTIME_CAPTURE_RELATIVE_PATH
            )
            and first_context_consumer_trace[
                "first_context_translation_visual_review_sha256"
            ]
            == sha256_file(
                root / FIRST_CONTEXT_TRANSLATION_VISUAL_REVIEW_RELATIVE_PATH
            )
        )
        direct_renderer_capture = artifacts.get(
            DIRECT_RENDERER_CAPTURE_RELATIVE_PATH
        )
        direct_consumer_inputs_ready = (
            direct_renderer_capture is not None
            and first_context_consumer_trace["baseline_target_sha256"]
            == direct_renderer_capture["baseline_target_sha256"]
            and first_context_consumer_trace["test_target_sha256"]
            == direct_renderer_capture["test_target_sha256"]
            and first_context_consumer_trace[
                "first_context_translation_test_build_sha256"
            ]
            == direct_renderer_capture[
                "first_context_translation_test_build_sha256"
            ]
            and first_context_consumer_trace[
                "first_context_translation_runtime_capture_sha256"
            ]
            == sha256_file(root / DIRECT_RENDERER_CAPTURE_RELATIVE_PATH)
            and first_context_consumer_trace[
                "first_context_translation_visual_review_sha256"
            ]
            == sha256_file(root / DIRECT_RENDERER_CAPTURE_RELATIVE_PATH)
        )
        if not normal_consumer_inputs_ready and not direct_consumer_inputs_ready:
            artifacts.pop(FIRST_CONTEXT_CONSUMER_TRACE_RELATIVE_PATH)
    group_context_resolution = artifacts.get(
        GROUP_CONTEXT_RESOLUTION_RELATIVE_PATH
    )
    if group_context_resolution is not None:
        if (
            confirmed_group_extract is None
            or group_context_resolution["target_sha256"]
            != confirmed_group_extract["target_sha256"]
            or group_context_resolution["source_group_extract_sha256"]
            != sha256_file(root / CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
            or group_context_resolution["group"]["selector"]
            != confirmed_group_extract["group"]["selector"]
            or group_context_resolution["group"]["record_count"]
            != confirmed_group_extract["group"]["declared_entry_count"]
        ):
            artifacts.pop(GROUP_CONTEXT_RESOLUTION_RELATIVE_PATH)
    group_context_resolution = artifacts.get(
        GROUP_CONTEXT_RESOLUTION_RELATIVE_PATH
    )
    group_runtime_context = artifacts.get(
        GROUP_RUNTIME_CONTEXT_RELATIVE_PATH
    )
    if group_runtime_context is not None:
        if (
            confirmed_group_extract is None
            or group_context_resolution is None
            or renderer is None
            or group_runtime_context["target_sha256"]
            != confirmed_group_extract["target_sha256"]
            or group_runtime_context["source_group_extract_sha256"]
            != sha256_file(root / CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
            or group_runtime_context["source_context_resolution_sha256"]
            != sha256_file(root / GROUP_CONTEXT_RESOLUTION_RELATIVE_PATH)
            or group_runtime_context["source_renderer_observation_sha256"]
            != sha256_file(
                root
                / "analysis/device/v5_1_latest_renderer_observation.json"
            )
            or group_runtime_context["group"]["selector"]
            != confirmed_group_extract["group"]["selector"]
            or group_runtime_context["group"]["declared_record_count"]
            != confirmed_group_extract["group"]["declared_entry_count"]
        ):
            artifacts.pop(GROUP_RUNTIME_CONTEXT_RELATIVE_PATH)
    group_runtime_context = artifacts.get(
        GROUP_RUNTIME_CONTEXT_RELATIVE_PATH
    )
    group_source_delta = artifacts.get(GROUP_SOURCE_DELTA_RELATIVE_PATH)
    if group_source_delta is not None:
        if (
            confirmed_group_extract is None
            or group_runtime_context is None
            or group_source_delta["target_sha256"]
            != confirmed_group_extract["target_sha256"]
            or group_source_delta["source_group_extract_sha256"]
            != sha256_file(root / CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
            or group_source_delta["source_runtime_context_sha256"]
            != sha256_file(root / GROUP_RUNTIME_CONTEXT_RELATIVE_PATH)
            or group_source_delta["group"]["selector"]
            != confirmed_group_extract["group"]["selector"]
            or group_source_delta["group"]["record_count"]
            != confirmed_group_extract["group"]["declared_entry_count"]
        ):
            artifacts.pop(GROUP_SOURCE_DELTA_RELATIVE_PATH)
    group_source_delta = artifacts.get(GROUP_SOURCE_DELTA_RELATIVE_PATH)
    source_huffman_locator = artifacts.get(
        SOURCE_HUFFMAN_LOCATOR_RELATIVE_PATH
    )
    if source_huffman_locator is not None:
        if (
            group_source_delta is None
            or source_huffman_locator["source_sha256"]
            != group_source_delta["source_sha256"]
            or source_huffman_locator["target_sha256"]
            != group_source_delta["target_sha256"]
            or source_huffman_locator["source_group_delta_sha256"]
            != sha256_file(root / GROUP_SOURCE_DELTA_RELATIVE_PATH)
        ):
            artifacts.pop(SOURCE_HUFFMAN_LOCATOR_RELATIVE_PATH)
    source_huffman_locator = artifacts.get(
        SOURCE_HUFFMAN_LOCATOR_RELATIVE_PATH
    )
    source_group_codec_probe = artifacts.get(
        SOURCE_GROUP_CODEC_PROBE_RELATIVE_PATH
    )
    if source_group_codec_probe is not None:
        if (
            confirmed_group_extract is None
            or group_source_delta is None
            or source_huffman_locator is None
            or source_group_codec_probe["target_sha256"]
            != confirmed_group_extract["target_sha256"]
            or source_group_codec_probe["source_group_extract_sha256"]
            != sha256_file(root / CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
            or source_group_codec_probe["source_group_delta_sha256"]
            != sha256_file(root / GROUP_SOURCE_DELTA_RELATIVE_PATH)
            or source_group_codec_probe["source_vector_locator_sha256"]
            != sha256_file(root / SOURCE_HUFFMAN_LOCATOR_RELATIVE_PATH)
            or source_group_codec_probe["source_sha256"]
            != group_source_delta["source_sha256"]
            or source_group_codec_probe["group"]["selector"]
            != confirmed_group_extract["group"]["selector"]
            or source_group_codec_probe["group"]["record_count"]
            != confirmed_group_extract["group"]["declared_entry_count"]
        ):
            artifacts.pop(SOURCE_GROUP_CODEC_PROBE_RELATIVE_PATH)
    group_text_candidates = artifacts.get(
        GROUP_TEXT_CANDIDATE_RELATIVE_PATH
    )
    if group_text_candidates is not None:
        if (
            group_context_resolution is None
            or group_source_delta is None
            or visible_unicode_mapping is None
            or group_text_candidates["target_sha256"]
            != group_context_resolution["target_sha256"]
            or group_text_candidates["source_context_resolution_sha256"]
            != sha256_file(root / GROUP_CONTEXT_RESOLUTION_RELATIVE_PATH)
            or group_text_candidates["source_group_delta_sha256"]
            != sha256_file(root / GROUP_SOURCE_DELTA_RELATIVE_PATH)
            or group_text_candidates["source_visible_mapping_sha256"]
            != sha256_file(root / VISIBLE_UNICODE_MAPPING_RELATIVE_PATH)
            or group_text_candidates["group"]["selector"]
            != group_context_resolution["group"]["selector"]
            or group_text_candidates["group"]["record_count"]
            != group_context_resolution["group"]["record_count"]
        ):
            artifacts.pop(GROUP_TEXT_CANDIDATE_RELATIVE_PATH)
    group_text_candidates = artifacts.get(
        GROUP_TEXT_CANDIDATE_RELATIVE_PATH
    )
    unmatched_glyph_fuzzy = artifacts.get(
        UNMATCHED_GLYPH_FUZZY_RELATIVE_PATH
    )
    if unmatched_glyph_fuzzy is not None:
        if (
            group_text_candidates is None
            or unmatched_glyph_fuzzy["target_sha256"]
            != group_text_candidates["target_sha256"]
            or unmatched_glyph_fuzzy["source_text_candidate_sha256"]
            != sha256_file(root / GROUP_TEXT_CANDIDATE_RELATIVE_PATH)
        ):
            artifacts.pop(UNMATCHED_GLYPH_FUZZY_RELATIVE_PATH)
    unmatched_glyph_fuzzy = artifacts.get(
        UNMATCHED_GLYPH_FUZZY_RELATIVE_PATH
    )
    group_script_corpus = artifacts.get(GROUP_SCRIPT_CORPUS_RELATIVE_PATH)
    if group_script_corpus is not None:
        if (
            group_text_candidates is None
            or unmatched_glyph_fuzzy is None
            or group_script_corpus["target_sha256"]
            != group_text_candidates["target_sha256"]
            or group_script_corpus["source_text_candidate_sha256"]
            != sha256_file(root / GROUP_TEXT_CANDIDATE_RELATIVE_PATH)
            or group_script_corpus["source_fuzzy_glyph_sha256"]
            != sha256_file(root / UNMATCHED_GLYPH_FUZZY_RELATIVE_PATH)
            or group_script_corpus["group"]["selector"]
            != group_text_candidates["group"]["selector"]
            or group_script_corpus["group"]["candidate_record_count"]
            != group_text_candidates["resolution"]["unique_best_record_count"]
        ):
            artifacts.pop(GROUP_SCRIPT_CORPUS_RELATIVE_PATH)
    group_script_corpus = artifacts.get(GROUP_SCRIPT_CORPUS_RELATIVE_PATH)
    source_record_pairing = artifacts.get(SOURCE_RECORD_PAIRING_RELATIVE_PATH)
    if source_record_pairing is not None:
        if (
            confirmed_group_extract is None
            or group_source_delta is None
            or group_script_corpus is None
            or source_record_pairing["source_sha256"]
            != group_source_delta["source_sha256"]
            or source_record_pairing["target_sha256"]
            != confirmed_group_extract["target_sha256"]
            or source_record_pairing["source_group_extract_sha256"]
            != sha256_file(root / CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
            or source_record_pairing["source_group_delta_sha256"]
            != sha256_file(root / GROUP_SOURCE_DELTA_RELATIVE_PATH)
            or source_record_pairing["source_target_corpus_sha256"]
            != sha256_file(root / GROUP_SCRIPT_CORPUS_RELATIVE_PATH)
            or source_record_pairing["group"]["selector"]
            != confirmed_group_extract["group"]["selector"]
            or source_record_pairing["group"]["source_record_count"]
            != confirmed_group_extract["group"]["declared_entry_count"]
            or source_record_pairing["group"]["target_candidate_record_count"]
            != group_script_corpus["group"]["candidate_record_count"]
        ):
            artifacts.pop(SOURCE_RECORD_PAIRING_RELATIVE_PATH)
    confirmed_group_unicode = artifacts.get(
        CONFIRMED_GROUP_UNICODE_RELATIVE_PATH
    )
    if confirmed_group_unicode is not None:
        if (
            confirmed_group_extract is None
            or group_context_resolution is None
            or group_runtime_context is None
            or visible_unicode_mapping is None
            or confirmed_group_unicode["target_sha256"]
            != confirmed_group_extract["target_sha256"]
            or confirmed_group_unicode["source_group_extract_sha256"]
            != sha256_file(root / CONFIRMED_GROUP_EXTRACT_RELATIVE_PATH)
            or confirmed_group_unicode[
                "source_group_context_resolution_sha256"
            ]
            != sha256_file(root / GROUP_CONTEXT_RESOLUTION_RELATIVE_PATH)
            or confirmed_group_unicode[
                "source_group_runtime_context_sha256"
            ]
            != sha256_file(root / GROUP_RUNTIME_CONTEXT_RELATIVE_PATH)
            or confirmed_group_unicode["source_visible_mapping_sha256"]
            != sha256_file(root / VISIBLE_UNICODE_MAPPING_RELATIVE_PATH)
            or confirmed_group_unicode["group"]["selector"]
            != confirmed_group_extract["group"]["selector"]
            or confirmed_group_unicode["group"]["record_count"]
            != group_runtime_context["coverage"][
                "runtime_context_exact_entry_count"
            ]
        ):
            artifacts.pop(CONFIRMED_GROUP_UNICODE_RELATIVE_PATH)
    return artifacts


def _load_validated_binary_artifacts(
    root: Path,
    artifacts: dict[Path, dict[str, object]],
) -> set[Path]:
    binaries: set[Path] = set()
    for relative, receipt_relative in SAFE_BINARY_ARTIFACTS.items():
        receipt = artifacts.get(receipt_relative)
        if receipt is None:
            continue
        try:
            if relative == DIRECT_RENDERER_CAPTURE_IMAGE_RELATIVE_PATH:
                image_path = (root / relative).resolve()
                image_path.relative_to(root.resolve())
                data = image_path.read_bytes()
                if (
                    not data.startswith(b"\x89PNG\r\n\x1a\n")
                    or sha256_file(image_path) != receipt["capture_png_sha256"]
                ):
                    raise ValueError(
                        "direct renderer capture PNG and receipt disagree"
                    )
            else:
                load_validated_progress_image(root, receipt)
        except (OSError, ValueError):
            continue
        binaries.add(relative)
    return binaries


def _load_validated_text_artifacts(root: Path) -> set[Path]:
    texts: set[Path] = set()
    for relative, allowed_values in SAFE_TEXT_ARTIFACTS.items():
        path = root / relative
        if not path.is_file():
            continue
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value in allowed_values:
            texts.add(relative)
    return texts


def _porcelain_path(line: str) -> str:
    if len(line) < 4:
        raise ValueError("unexpected git status entry")
    path = line[3:]
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    return path.replace("\\", "/")


def publish_runtime_bundle(
    root: Path,
    *,
    push: bool = True,
) -> dict[str, object]:
    root = root.resolve()
    artifacts = _load_validated_artifacts(root)
    binaries = _load_validated_binary_artifacts(root, artifacts)
    texts = _load_validated_text_artifacts(root)
    top = Path(
        _git(root, "rev-parse", "--show-toplevel").stdout.strip()
    ).resolve()
    if top != root:
        raise ValueError("repository root mismatch")
    if _git(root, "branch", "--show-current").stdout.strip() != "main":
        raise ValueError("runtime artifacts may only be published from main")
    remote = _normalized_remote(
        _git(root, "remote", "get-url", "origin").stdout
    )
    if EXPECTED_REMOTE not in remote:
        raise ValueError("origin is not the canonical repository")

    allowed = {
        str(relative).replace("\\", "/") for relative in SAFE_ARTIFACTS
    } | {
        str(relative).replace("\\", "/") for relative in SAFE_BINARY_ARTIFACTS
    } | {
        str(relative).replace("\\", "/") for relative in SAFE_TEXT_ARTIFACTS
    }
    porcelain = _git(root, "status", "--porcelain").stdout.splitlines()
    changed_paths = {_porcelain_path(line) for line in porcelain}
    deleted_safe_paths = {
        _porcelain_path(line)
        for line in porcelain
        if "D" in line[:2] and _porcelain_path(line) in allowed
    }

    selected = sorted(
        {
            str(relative).replace("\\", "/")
            for relative in set(artifacts) | binaries | texts
            if str(relative).replace("\\", "/") in changed_paths
        }
        | deleted_safe_paths
    )
    if selected:
        if not _git(root, "config", "user.name").stdout.strip():
            _git(root, "config", "user.name", DEFAULT_GIT_NAME)
        if not _git(root, "config", "user.email").stdout.strip():
            _git(root, "config", "user.email", DEFAULT_GIT_EMAIL)
        _git(root, "add", "--", *selected)
        _git(
            root,
            "commit",
            "-m",
            "Record sanitized S25U runtime bundle",
            "--",
            *selected,
        )
    if push:
        _git(root, "push", "origin", "HEAD:main")
    return {
        "changed": bool(selected),
        "commit": _git(root, "rev-parse", "HEAD").stdout.strip(),
        "ignored_paths": sorted(changed_paths - allowed),
        "paths": sorted(
            str(relative).replace("\\", "/")
            for relative in set(artifacts) | binaries | texts
        ),
        "pushed": push,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--no-push", action="store_true")
    args = parser.parse_args()
    if args.no_push and not args.publish:
        parser.error("--no-push requires --publish")
    root = Path(__file__).resolve().parents[1]
    artifacts = _load_validated_artifacts(root)
    binaries = _load_validated_binary_artifacts(root, artifacts)
    print(
        "SFKR sanitized runtime bundle: "
        f"{len(artifacts) + len(binaries)} artifact(s)"
    )
    if args.publish:
        defer_push = args.no_push or os.environ.get(
            "SFKR_DEFER_RUNTIME_BUNDLE_PUSH"
        ) == "1"
        result = publish_runtime_bundle(root, push=not defer_push)
        action = "Prepared" if defer_push else "Published"
        print(
            f"{action} sanitized runtime bundle: "
            f"{len(result['paths'])} artifact(s) @ {result['commit']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
