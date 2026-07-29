from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.run_s25u_route_capture import (
    ROUTE_STEPS,
    _capture_route,
    _frame_budget,
)


class S25URouteCaptureTests(unittest.TestCase):
    def test_fixed_route_captures_five_checkpoints(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.calls: list[tuple[str, dict[str, object]]] = []

            def call(
                self,
                name: str,
                arguments: dict[str, object] | None = None,
            ) -> dict[str, object]:
                self.calls.append((name, arguments or {}))
                if name == "debug_get_status":
                    return {"paused": True, "at_breakpoint": False}
                return {}

        metadata = [
            {"width": 160, "height": 144, "png_sha256": str(index) * 64}
            for index in (1, 2, 3, 4, 4)
        ]
        client = FakeClient()
        with tempfile.TemporaryDirectory() as directory, patch(
            "tools.run_s25u_route_capture._parse_screenshot",
            side_effect=[(b"png", item) for item in metadata],
        ), patch(
            "tools.run_s25u_route_capture._write_bytes_atomic"
        ) as write_png:
            safe, local = _capture_route(client, Path(directory))

        self.assertEqual(len(safe), 5)
        self.assertEqual(len(local), 5)
        self.assertEqual(safe[-1]["stage"], "confirm-16")
        self.assertEqual(safe[-1]["frame_total"], 3300)
        self.assertEqual(safe[-1]["input_count"], 17)
        self.assertEqual(write_png.call_count, 5)
        buttons = [
            arguments["button"]
            for name, arguments in client.calls
            if name == "controller_button"
        ]
        self.assertEqual(buttons[0], "start")
        self.assertEqual(buttons[1:], ["2"] * 16)
        self.assertEqual(_frame_budget(), 3300)

    def test_only_named_route_steps_create_captures(self) -> None:
        self.assertEqual(
            [stage for _, _, stage in ROUTE_STEPS if stage is not None],
            [
                "boot-idle",
                "post-start",
                "confirm-01",
                "confirm-04",
                "confirm-16",
            ],
        )


if __name__ == "__main__":
    unittest.main()

