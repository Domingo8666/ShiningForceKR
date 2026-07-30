from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.v5_1_source_script_reference import (  # noqa: E402
    build_source_script_reference,
    discover_script_urls,
    extract_script_lines,
    summarize_sections,
    validate_source_script_reference,
)


class SourceScriptReferenceTests(unittest.TestCase):
    def test_discovers_and_sorts_only_final_conflict_sections(self) -> None:
        html = """
        <a href="?se=2&amp;p=scripts&amp;id=sfgfc&amp;ch=1">two</a>
        <a href="/?ch=1&amp;id=sfgfc&amp;p=scripts&amp;se=1">one</a>
        <a href="?ch=1&amp;id=other&amp;p=scripts&amp;se=1">other</a>
        """
        urls = discover_script_urls(html)
        self.assertEqual(len(urls), 2)
        self.assertIn("se=1", urls[0])
        self.assertIn("se=2", urls[1])

    def test_extracts_only_script_body(self) -> None:
        html = """
        <html><body><div>navigation</div>
        <p>Script translated by: Translator</p>
        <p>Max:</p><p>Just a test.</p>
        <p>View Printer-Friendly Version</p><p>footer</p>
        </body></html>
        """
        self.assertEqual(
            extract_script_lines(html),
            ["Max:", "Just a test."],
        )

    def test_summarizes_speakers_locally(self) -> None:
        sections = [
            {
                "url": "local-only",
                "lines": ["Narration", "Max:", "Line one", "Max:", "Line two"],
            }
        ]
        counts = summarize_sections(sections)
        self.assertEqual(counts["section_count"], 1)
        self.assertEqual(counts["script_line_count"], 3)
        self.assertEqual(counts["speaker_label_count"], 2)
        self.assertEqual(counts["unique_speaker_count"], 1)
        self.assertEqual(counts["narration_line_count"], 1)
        self.assertEqual(
            sections[0]["annotated_lines"][1],
            {"speaker": "Max", "text": "Line one"},
        )

    def test_builds_safe_counts_without_script(self) -> None:
        artifact = build_source_script_reference(
            local_reference_sha256="1" * 64,
            reference={
                "section_count": 25,
                "script_line_count": 1000,
                "speaker_label_count": 400,
                "unique_speaker_count": 30,
                "narration_line_count": 20,
            },
            captured_utc="2026-07-30T18:00:00Z",
        )
        validate_source_script_reference(artifact)
        self.assertNotIn("sections", artifact)
        self.assertNotIn("speakers", artifact)
        self.assertFalse(artifact["translation_build_eligible"])


if __name__ == "__main__":
    unittest.main()
