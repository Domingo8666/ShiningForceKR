from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from tools.v5_1_route_capture import (
    EXPECTED_STAGES,
    PUBLISH_RELATIVE_PATH,
    build_route_capture,
    validate_route_capture,
    write_route_capture,
)


def captures(*, stable_tail: bool = False) -> list[dict[str, object]]:
    frames = (180, 420, 600, 1140, 3300)
    inputs = (0, 1, 2, 5, 17)
    values: list[dict[str, object]] = []
    for index, stage in enumerate(EXPECTED_STAGES):
        digest_character = str(index + 1)
        if stable_tail and index == len(EXPECTED_STAGES) - 1:
            digest_character = str(index)
        values.append(
            {
                "stage": stage,
                "frame_total": frames[index],
                "input_count": inputs[index],
                "width": 160,
                "height": 144,
                "png_sha256": digest_character * 64,
            }
        )
    return values


class RouteCaptureTests(unittest.TestCase):
    def test_builds_image_free_route_observation(self) -> None:
        observation = build_route_capture(
            target_sha256="a" * 64,
            emulator_version="3.9.14",
            route="cold-boot-start-confirm-story",
            frame_budget=3300,
            captures=captures(),
        )
        validate_route_capture(observation)
        encoded = json.dumps(observation)
        self.assertEqual(observation["distinct_frame_count"], 5)
        self.assertFalse(observation["stable_tail"])
        self.assertFalse(observation["route_state_verified"])
        self.assertFalse(observation["translation_build_eligible"])
        self.assertNotIn(".png", encoded)
        self.assertNotIn("file", encoded)

    def test_stable_tail_requires_human_route_review(self) -> None:
        observation = build_route_capture(
            target_sha256="b" * 64,
            emulator_version="3.9.14",
            route="cold-boot-start-confirm-story",
            frame_budget=3300,
            captures=captures(stable_tail=True),
        )
        self.assertTrue(observation["stable_tail"])
        self.assertEqual(
            observation["next_checkpoint"],
            "human-identify-stable-route-screen",
        )
        validate_route_capture(observation)

    def test_validator_rejects_semantic_route_claim(self) -> None:
        observation = build_route_capture(
            target_sha256="c" * 64,
            emulator_version="3.9.14",
            route="cold-boot-start-confirm-story",
            frame_budget=3300,
            captures=captures(),
        )
        unsafe = copy.deepcopy(observation)
        unsafe["route_state_verified"] = True
        with self.assertRaisesRegex(ValueError, "cannot verify"):
            validate_route_capture(unsafe)

    def test_writer_uses_fixed_device_path(self) -> None:
        observation = build_route_capture(
            target_sha256="d" * 64,
            emulator_version="3.9.14",
            route="cold-boot-start-confirm-story",
            frame_budget=3300,
            captures=captures(),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_route_capture(root, observation)
            self.assertEqual(path, root / PUBLISH_RELATIVE_PATH)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                observation,
            )


if __name__ == "__main__":
    unittest.main()

