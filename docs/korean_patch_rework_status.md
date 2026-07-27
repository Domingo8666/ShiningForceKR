# Shining Force Gaiden - Final Conflict Korean Patch Rework Status

## Current conclusion

Do not ship the previous Korean probe IPS files as a final patch. They are useful
only as diagnostics. They overwrite or reuse character slots in a way that can
collide with the English patch renderer, which explains the mixed English and
garbled Korean-looking output seen in RetroArch PicoDrive.

The safe base is:

1. Clean Japanese ROM.
2. Official/known English IPS patch (`fcpatch_070706.ips`).
3. Korean patch layered on top of that, while preserving the English patch's
   renderer and banking assumptions unless deliberately replacing them.

## Confirmed facts

- Original ROM size: 524288 bytes.
- English patch applies cleanly and produces `analysis/final_conflict_english.gg`.
- English patch text uses a custom byte encoding for direct strings:
  - `0x00` space
  - `0x01` line break
  - uppercase, lowercase, digits, punctuation in compact ranges
- Font data for the English patch is around `0x28920`.
- Direct script/list/menu strings exist and can be extracted/rewritten safely.
- The visible intro sentence, for example `And so began Mishaela's new ambition...`,
  is not stored as plain direct text in the ROM.
- Public technical notes for a related project identify the script engine as
  using word substitution plus semi-adaptive Huffman compression derived from
  Shining Force Gaiden: Final Conflict.

## Why the earlier probes failed

The probes changed glyphs and text bytes before the full renderer/code mapping
was solved. In PicoDrive this causes:

- Latin text falling back through unchanged English slots.
- Korean glyph slots being addressed by unintended bytes.
- State files preserving old VRAM/font state, making probe verification noisy.
- Direct-string patches not touching compressed story text.

## Required final-patch architecture

For a compatibility-focused PicoDrive patch, the final Korean patch needs four
parts:

1. Korean font table
   - Must not destroy required ASCII/control glyphs.
   - Must be mapped through the actual renderer table, not guessed by tile
     preview alone.

2. Korean text table
   - A `.tbl`-style mapping for Korean syllable/word tokens.
   - Control codes kept byte-for-byte compatible with the English script engine.

3. Script encoder
   - Recreate the English patch's word-token plus adaptive Huffman script data.
   - Regenerate script lookup/pointer patches.
   - Confirm that the generated compressed stream decodes back to the intended
     Korean text before applying to ROM.

4. Direct text/menu patcher
   - Patch non-compressed menu/list strings separately.
   - Keep window widths and buffers within the existing English patch limits.

## Sources found during rework

- `analysis/psrp/technical.md` documents the relevant technique:
  word substitution, then per-previous-byte Huffman trees.
- `analysis/psrp/psrp/tools.py` contains a modern Python implementation of the
  script insertion pipeline for the related Phantasy Star project.
- `analysis/psrp/psrp/asm/text-renderer.asm` contains an `SFGDecoder` section
  explicitly labeled as Shining Force Gaiden: Final Conflict derived code.

## Next implementation checkpoint

The next real milestone is not another user-facing probe. It is a local decoder
test:

1. Locate the exact Huffman tree vector, script lookup table, dictionary, and
   compressed script bank in `analysis/final_conflict_english.gg`.
2. Implement a Python decoder matching `SFGDecoder`.
3. Decode at least the current intro line from the ROM into English:
   `And so began Mishaela's new ambition...`
4. Only after that succeeds, generate Korean compressed data and build an IPS.

Until step 3 passes, a "complete Korean patch" claim would be false.

