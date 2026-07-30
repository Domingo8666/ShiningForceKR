#!/usr/bin/env python3
"""Collect a local-only English script reference with speaker labels.

The reference is used only to align extracted target records and assign
speakers.  Full page text, dialogue, speaker names, URLs, and page HTML remain
under ignored reports/local paths.  The published receipt contains counts and
content hashes only.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
import hashlib
import json
from pathlib import Path
import re
from urllib.error import URLError
from urllib.parse import parse_qs, urljoin, urlparse
from urllib.request import Request, urlopen

try:
    from .v5_1_renderer_output_trace import _load_json_object
except ImportError:  # direct script execution
    from v5_1_renderer_output_trace import _load_json_object


ARTIFACT_KIND = "sanitized-v5-1-source-script-reference"
SCHEMA_VERSION = 1
INDEX_URL = "https://www.shiningforcecentral.com/?id=sfgfc&p=scripts"
PUBLISH_RELATIVE_PATH = Path(
    "analysis/device/v5_1_latest_source_script_reference.json"
)
LOCAL_REPORT_PATH = Path(
    "reports/local/v5_1_source_script_reference.json"
)
TOP_LEVEL_KEYS = {
    "artifact_kind",
    "schema_version",
    "status",
    "source_host",
    "local_reference_sha256",
    "captured_utc",
    "reference",
    "local_payload_policy",
    "source_pairing_complete",
    "speaker_assignment_complete",
    "translation_build_eligible",
    "next_checkpoint",
}
REFERENCE_KEYS = {
    "section_count",
    "script_line_count",
    "speaker_label_count",
    "unique_speaker_count",
    "narration_line_count",
}
SPEAKER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 .,&'()/\\-]{0,80}:$")


class _TextParser(HTMLParser):
    BREAK_TAGS = {
        "br",
        "div",
        "p",
        "li",
        "tr",
        "td",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "blockquote",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skipped_depth = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del attrs
        if tag in {"script", "style"}:
            self.skipped_depth += 1
        elif self.skipped_depth == 0 and tag in self.BREAK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.skipped_depth > 0:
            self.skipped_depth -= 1
        elif self.skipped_depth == 0 and tag in self.BREAK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.skipped_depth == 0:
            self.parts.append(data)


def discover_script_urls(index_html: str) -> list[str]:
    urls: dict[tuple[int, int], str] = {}
    for match in re.finditer(
        r"""href\s*=\s*["']([^"']+)["']""",
        index_html,
        flags=re.IGNORECASE,
    ):
        url = urljoin(INDEX_URL, unescape(match.group(1)))
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if (
            parsed.netloc.lower() != "www.shiningforcecentral.com"
            or query.get("id") != ["sfgfc"]
            or query.get("p") != ["scripts"]
            or "ch" not in query
            or "se" not in query
        ):
            continue
        try:
            key = (int(query["ch"][0]), int(query["se"][0]))
        except (ValueError, IndexError):
            continue
        urls[key] = url
    return [urls[key] for key in sorted(urls)]


def extract_script_lines(page_html: str) -> list[str]:
    parser = _TextParser()
    parser.feed(page_html)
    lines = [
        re.sub(r"\s+", " ", line).strip()
        for line in "".join(parser.parts).splitlines()
    ]
    lines = [line for line in lines if line]
    start = next(
        (
            index + 1
            for index, line in enumerate(lines)
            if line.startswith("Script translated by:")
        ),
        None,
    )
    if start is None:
        raise ValueError("script page translation marker is missing")
    end = next(
        (
            index
            for index in range(start, len(lines))
            if lines[index].startswith("View Printer-Friendly Version")
            or lines[index] == "Previous Chapter"
            or lines[index] == "Back to Script Index"
        ),
        len(lines),
    )
    return lines[start:end]


def summarize_sections(
    sections: list[dict[str, object]],
) -> dict[str, int]:
    if not sections:
        raise ValueError("source script sections are missing")
    line_count = 0
    speaker_labels = 0
    narration = 0
    speakers: set[str] = set()
    for section in sections:
        if not isinstance(section, dict):
            raise ValueError("source script section is invalid")
        lines = section.get("lines")
        if not isinstance(lines, list) or not lines:
            raise ValueError("source script section lines are missing")
        current_speaker: str | None = None
        annotated: list[dict[str, str | None]] = []
        for line in lines:
            if not isinstance(line, str) or not line:
                raise ValueError("source script line is invalid")
            if SPEAKER_RE.fullmatch(line):
                current_speaker = line[:-1]
                speakers.add(current_speaker)
                speaker_labels += 1
                continue
            annotated.append({"speaker": current_speaker, "text": line})
            line_count += 1
            narration += int(current_speaker is None)
        section["annotated_lines"] = annotated
    return {
        "section_count": len(sections),
        "script_line_count": line_count,
        "speaker_label_count": speaker_labels,
        "unique_speaker_count": len(speakers),
        "narration_line_count": narration,
    }


def build_source_script_reference(
    *,
    local_reference_sha256: str,
    reference: dict[str, object],
    captured_utc: str,
) -> dict[str, object]:
    value = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "status": "source-script-reference-collected",
        "source_host": "www.shiningforcecentral.com",
        "local_reference_sha256": local_reference_sha256,
        "captured_utc": captured_utc,
        "reference": {
            key: int(reference[key])
            for key in REFERENCE_KEYS
        },
        "local_payload_policy": (
            "source-urls-html-dialogue-speaker-names-and-annotations-local-only"
        ),
        "source_pairing_complete": False,
        "speaker_assignment_complete": False,
        "translation_build_eligible": False,
        "next_checkpoint": "align-source-reference-to-target-record-order",
    }
    validate_source_script_reference(value)
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _bounded_int(value: object, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def validate_source_script_reference(value: dict[str, object]) -> None:
    if set(value) != TOP_LEVEL_KEYS:
        raise ValueError("source script reference fields do not match")
    if (
        value["artifact_kind"] != ARTIFACT_KIND
        or value["schema_version"] != SCHEMA_VERSION
        or value["status"] != "source-script-reference-collected"
        or value["source_host"] != "www.shiningforcecentral.com"
        or not _is_sha256(value["local_reference_sha256"])
    ):
        raise ValueError("source script reference policy is invalid")
    captured = value["captured_utc"]
    if not isinstance(captured, str):
        raise ValueError("source script reference timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(captured.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("source script reference timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise ValueError("source script reference timestamp needs UTC")
    reference = value["reference"]
    if not isinstance(reference, dict) or set(reference) != REFERENCE_KEYS:
        raise ValueError("source script reference counts do not match")
    for key in REFERENCE_KEYS:
        if not _bounded_int(reference[key], 0, 0x1000000):
            raise ValueError(f"source script reference {key} is invalid")
    if (
        reference["section_count"] < 1
        or reference["script_line_count"] < 1
        or reference["speaker_label_count"] < 1
        or reference["unique_speaker_count"] < 1
        or reference["narration_line_count"] > reference["script_line_count"]
        or value["local_payload_policy"]
        != "source-urls-html-dialogue-speaker-names-and-annotations-local-only"
        or value["source_pairing_complete"] is not False
        or value["speaker_assignment_complete"] is not False
        or value["translation_build_eligible"] is not False
        or value["next_checkpoint"]
        != "align-source-reference-to-target-record-order"
    ):
        raise ValueError("source script reference result is inconsistent")


def _fetch_text(url: str) -> str:
    request = Request(
        url,
        headers={"User-Agent": "ShiningForceKR/1.0 script-reference"},
    )
    with urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--if-ready", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    local_path = root / LOCAL_REPORT_PATH
    local: dict[str, object] | None = None
    if local_path.is_file() and not args.refresh:
        candidate = _load_json_object(local_path)
        if (
            candidate.get("artifact_kind")
            == "local-v5-1-source-script-reference"
            and isinstance(candidate.get("sections"), list)
        ):
            local = candidate
    if local is None:
        try:
            index_html = _fetch_text(INDEX_URL)
            urls = discover_script_urls(index_html)
            if not urls:
                raise ValueError("source script index has no sections")
            sections: list[dict[str, object]] = []
            for url in urls:
                sections.append(
                    {
                        "url": url,
                        "lines": extract_script_lines(_fetch_text(url)),
                    }
                )
            local = {
                "artifact_kind": "local-v5-1-source-script-reference",
                "schema_version": 1,
                "source_index_url": INDEX_URL,
                "sections": sections,
                "publication_policy": (
                    "never-publish-source-urls-html-dialogue-speakers-or-annotations"
                ),
            }
        except (OSError, URLError, ValueError) as error:
            if args.if_ready:
                print(f"Source script reference is not ready: {error}")
                return 0
            raise
    sections = local.get("sections")
    if not isinstance(sections, list):
        raise ValueError("source script reference local sections are missing")
    reference = summarize_sections(sections)
    captured_utc = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    local["captured_utc"] = captured_utc
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(local, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    local_reference_sha256 = hashlib.sha256(local_path.read_bytes()).hexdigest()
    safe = build_source_script_reference(
        local_reference_sha256=local_reference_sha256,
        reference=reference,
        captured_utc=captured_utc,
    )
    safe_path = root / PUBLISH_RELATIVE_PATH
    safe_path.parent.mkdir(parents=True, exist_ok=True)
    safe_path.write_text(
        json.dumps(safe, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"SFKR source script reference: {safe_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
