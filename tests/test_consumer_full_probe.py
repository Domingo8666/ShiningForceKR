from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.patch_io import PatchError
from tools.v5_1_consumer import _full_decode_metrics


class FullDecodeProbeTests(unittest.TestCase):
    def test_every_target_is_counted_without_sharing_decoded_content(self) -> None:
        def fake_decode(
            rom: bytes,
            known: bytes,
            trees: dict[int, object],
            target: int,
            **kwargs: object,
        ) -> tuple[list[int], int]:
            if target == 20:
                raise PatchError("synthetic bounded-decode failure")
            lengths = {10: 2, 30: 4}
            return [1] * lengths[target], target

        with patch("tools.v5_1_consumer.decode_symbols", side_effect=fake_decode):
            metrics = _full_decode_metrics(
                b"\x00" * 64,
                b"\x01" * 64,
                {},
                [10, 20, 30, 10],
            )

        self.assertEqual(metrics["attempted"], 4)
        self.assertEqual(metrics["bounded_terminations"], 3)
        self.assertEqual(metrics["termination_ratio"], 0.75)
        self.assertEqual(metrics["min_symbols"], 2)
        self.assertEqual(metrics["median_symbols"], 2)
        self.assertEqual(metrics["max_symbols"], 4)
        self.assertEqual(metrics["distinct_targets"], 3)
        self.assertEqual(metrics["distinct_target_ratio"], 0.75)
        self.assertEqual(metrics["target_span"], 20)
        self.assertNotIn("symbols", metrics)


if __name__ == "__main__":
    unittest.main()
