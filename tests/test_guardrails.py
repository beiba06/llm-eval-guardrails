"""Offline tests: no API key needed. Run with: python -m unittest discover tests"""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent))
import anthropic  # noqa: E402

import eval as ev  # noqa: E402

CASE = {"id": "c1", "category": "math", "prompt": "2+2?", "expected": r"\b4\b"}


def reply(text="Answer: 4", stop="end_turn", model="claude-haiku-5-5"):
    return NS(content=[NS(type="thinking", thinking=""), NS(type="text", text=text)], stop_reason=stop, model=model,
              usage=NS(input_tokens=1_000_000, output_tokens=1_000_000))


class QualityScorer(unittest.TestCase):
    def test_oracle_passes_every_case(self):
        for case in ev.load_suite("quality"):
            with self.subTest(case["id"]):
                self.assertTrue(ev.score_quality(case, f"Some working.\n\nAnswer: {case['answer']}"))

    def test_null_answers_fail_every_case(self):
        for case in ev.load_suite("quality"):
            for text in ("", "I don't know.", "Answer:", "Answer: none of the above"):
                with self.subTest(case["id"], text=text):
                    self.assertFalse(ev.score_quality(case, text))

    def test_only_the_final_answer_line_counts(self):
        self.assertFalse(ev.score_quality(CASE, "It might be 4, but I think 5.\nAnswer: 5"))
        self.assertFalse(ev.score_quality(CASE, "The result is 4."))  # the requested line is missing

    def test_markdown_and_commas_are_ignored(self):
        self.assertTrue(ev.score_quality({"expected": r"\b1234\b"}, "**Answer:** `1,234`"))


class Pipeline(unittest.TestCase):
    def run_with(self, **fake):
        with mock.patch.object(ev.client.messages, "create", **fake), mock.patch.object(ev.time, "sleep"):
            return ev.run_case(CASE, "claude-haiku-5-5", 0)

    def test_pass_records_tokens_and_cost(self):
        row = self.run_with(return_value=reply())
        self.assertEqual((row["status"], row["passed"], row["attempts"]), ("ok", 1, 1))
        self.assertAlmostEqual(row["cost"], 0.60)  # 1M tokens each way at $0.10 and $0.50

    def test_wrong_answer_is_a_fail(self):
        self.assertEqual(self.run_with(return_value=reply("Answer: 5"))["passed"], 0)

    def test_refusal_and_truncation_are_not_scored(self):
        self.assertEqual(self.run_with(return_value=reply("", "refusal"))["status"], "refused")
        self.assertIsNone(self.run_with(return_value=reply("", "refusal"))["passed"])
        self.assertEqual(self.run_with(return_value=reply("Answer: 4", "max_tokens"))["status"], "truncated")
        self.assertIsNone(self.run_with(return_value=reply("Answer: 4", "max_tokens"))["passed"])

    def test_another_model_answering_is_an_error(self):
        row = self.run_with(return_value=reply(model="claude-opus-5-5"))
        self.assertEqual((row["status"], row["passed"]), ("error", None))

    def test_api_failure_is_an_error_not_a_verdict(self):
        row = self.run_with(side_effect=anthropic.APIConnectionError(request=mock.Mock()))
        self.assertEqual((row["status"], row["passed"], row["cost"]), ("error", None, 0.0))

    def test_a_retry_is_counted(self):
        failure = anthropic.APIConnectionError(request=mock.Mock())
        row = self.run_with(side_effect=[failure, reply()])
        self.assertEqual((row["status"], row["passed"], row["attempts"]), ("ok", 1, 2))


class Storage(unittest.TestCase):
    def test_saved_rows_recompute_the_pass_count(self):
        rows = [ev.run_case_row(CASE, 0) | {"status": "ok", "passed": passed, "response": "x", "stop_reason": "end_turn",
                                            "tokens_in": 1, "tokens_out": 1, "cost": 0.0, "latency": 1.0, "attempts": 1}
                for passed in (1, 1, 0)]
        meta = {"suite": "quality", "target": "t", "guardrails": 0, "split": None, "repeats": 3, "commit_sha": "x", "started_at": "now"}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "r.db"
            run_id = ev.save(path, meta, rows)
            count = sqlite3.connect(path).execute("SELECT SUM(passed), COUNT(*) FROM results WHERE run_id = ?", (run_id,)).fetchone()
        self.assertEqual(count, (2, 3))


if __name__ == "__main__":
    unittest.main()
