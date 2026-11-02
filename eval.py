"""Eval CLI: run a YAML suite against a target, score each answer, print a table, save it to SQLite.

Usage: python eval.py run --suite quality --target claude-haiku-5-5
"""
import argparse
import hashlib
import random
import re
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import anthropic
import yaml

ROOT = Path(__file__).parent
DB_PATH = ROOT / "results/results.db"
PRICES = {  # $ per 1M tokens in/out
    "claude-opus-5-5": (4, 20), "claude-sonnet-5-5": (2, 10), "claude-haiku-5-5": (0.10, 0.50),
}
QUALITY_SYSTEM = "Finish your reply with a final line in exactly this form: Answer: <your answer>"
MAX_TOKENS = 16000  # long working must never be clipped and read as a wrong answer
EFFORT = "low"  # the same for every model, so differences come from the model
REPEATS = 3  # models are non-deterministic
WORKERS = 4  # stay well inside the API rate limits
ATTEMPTS = 5
SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY, suite TEXT, target TEXT, guardrails INTEGER, split TEXT, repeats INTEGER,
    commit_sha TEXT, started_at TEXT
);
CREATE TABLE IF NOT EXISTS results (
    run_id INTEGER REFERENCES runs(id), case_id TEXT, category TEXT, split TEXT, repeat INTEGER,
    status TEXT,            -- ok, refused, truncated, error (error rows never count towards a pass rate)
    passed INTEGER,         -- 1 pass, 0 fail, NULL when there was no scorable answer
    response TEXT, stop_reason TEXT, tokens_in INTEGER, tokens_out INTEGER, cost REAL,
    latency REAL,           -- seconds of the final attempt only, so retries can't flatter or hurt a model
    attempts INTEGER
);
"""

client = anthropic.Anthropic(max_retries=0, timeout=120)  # retries are counted in call_model


@dataclass
class Reply:
    text: str
    stop_reason: str
    tokens_in: int
    tokens_out: int
    cost: float
    latency: float
    attempts: int


def call_model(model: str, system: str, messages: list) -> Reply:
    """Make one Messages API call. No refusal fallback: a score must come from the model that was named."""
    for attempt in range(1, ATTEMPTS + 1):
        began = time.monotonic()
        try:
            msg = client.messages.create(model=model, max_tokens=MAX_TOKENS, system=system, messages=messages,
                                         output_config={"effort": EFFORT})
            latency = time.monotonic() - began
            break
        except (anthropic.RateLimitError, anthropic.InternalServerError, anthropic.APIConnectionError):
            if attempt == ATTEMPTS:
                raise
            time.sleep(min(2 ** attempt + random.random(), 30))
    if msg.model != model:
        raise RuntimeError(f"asked for {model}, served by {msg.model}")
    price_in, price_out = PRICES[model]
    messages.append({"role": "assistant", "content": msg.content})  # whole content, so a later turn keeps its thinking
    return Reply("".join(b.text for b in msg.content if b.type == "text"), msg.stop_reason,
                 msg.usage.input_tokens, msg.usage.output_tokens,
                 (msg.usage.input_tokens * price_in + msg.usage.output_tokens * price_out) / 1e6, latency, attempt)


def score_quality(case: dict, text: str) -> bool:
    """Match the expected regex against the final "Answer:" line only, so working shown earlier can't pass by accident.
    Markdown and commas are dropped first, so **Answer:** 1,234 equals Answer: 1234."""
    final = re.sub(r"[*`,]", "", text).lower().rpartition("answer:")
    return bool(final[1]) and re.search(case["expected"], final[2], re.I) is not None


def load_suite(name: str, split: str | None = None) -> list[dict]:
    cases = yaml.safe_load((ROOT / "suites" / f"{name}.yaml").read_text())
    return [case for case in cases if split is None or case.get("split") == split]


def run_case_row(case: dict, repeat: int) -> dict:
    return {"case_id": case["id"], "category": case.get("category"), "split": case.get("split"), "repeat": repeat}


def run_case(case: dict, target: str, repeat: int) -> dict:
    """Run one (case, repeat) from a clean state. A failure of the plumbing is an error row, never a verdict."""
    row = run_case_row(case, repeat)
    try:
        reply = call_model(target, QUALITY_SYSTEM, [{"role": "user", "content": case["prompt"]}])
    except (anthropic.AnthropicError, RuntimeError) as e:
        return row | {"status": "error", "passed": None, "response": f"{type(e).__name__}: {e}", "stop_reason": None,
                      "tokens_in": 0, "tokens_out": 0, "cost": 0.0, "latency": None, "attempts": None}
    status = {"refusal": "refused", "max_tokens": "truncated"}.get(reply.stop_reason, "ok")
    return row | {"status": status, "passed": int(score_quality(case, reply.text)) if status == "ok" else None,
                  "response": reply.text, "stop_reason": reply.stop_reason, "tokens_in": reply.tokens_in,
                  "tokens_out": reply.tokens_out, "cost": reply.cost, "latency": reply.latency, "attempts": reply.attempts}


def save(db_path: Path, meta: dict, rows: list[dict]) -> int:
    db_path.parent.mkdir(exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.executescript(SCHEMA)
        run_id = db.execute("INSERT INTO runs (suite, target, guardrails, split, repeats, commit_sha, started_at) "
                            "VALUES (:suite, :target, :guardrails, :split, :repeats, :commit_sha, :started_at)", meta).lastrowid
        db.executemany("INSERT INTO results VALUES (:run_id, :case_id, :category, :split, :repeat, :status, :passed, "
                       ":response, :stop_reason, :tokens_in, :tokens_out, :cost, :latency, :attempts)",
                       [row | {"run_id": run_id} for row in rows])
    return run_id


def table(rows: list[dict], target: str) -> str:
    """One line for a run: errors stay out of the pass rate and are shown next to it."""
    scored = [r for r in rows if r["passed"] is not None]
    timed = [r["latency"] for r in rows if r["latency"] is not None]
    count = lambda status: sum(r["status"] == status for r in rows)
    answered = max(len(rows) - count("error"), 1)
    return (f"{'target':<20} {'passed':>9} {'refused':>8} {'cut off':>8} {'errors':>7} {'tokens in/out':>15} "
            f"{'$ total':>9} {'$/query':>9} {'avg s':>6}\n"
            f"{target:<20} {sum(r['passed'] for r in scored):>4}/{len(scored):<4} {count('refused'):>8} {count('truncated'):>8} "
            f"{count('error'):>7} {sum(r['tokens_in'] for r in rows):>7}/{sum(r['tokens_out'] for r in rows):<7} "
            f"{sum(r['cost'] for r in rows):>9.4f} {sum(r['cost'] for r in rows) / answered:>9.5f} "
            f"{sum(timed) / max(len(timed), 1):>6.1f}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a suite against a target.")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--suite", required=True, choices=["quality"])
    run.add_argument("--target", required=True, choices=sorted(PRICES))
    run.add_argument("--repeats", type=int, default=REPEATS)
    run.add_argument("--db", type=Path, default=DB_PATH)
    args = parser.parse_args()

    cases = load_suite(args.suite)
    jobs = [(case, repeat) for case in cases for repeat in range(args.repeats)]
    with ThreadPoolExecutor(WORKERS) as pool:
        rows = list(pool.map(lambda job: run_case(job[0], args.target, job[1]), jobs))
    if all(row["status"] == "error" for row in rows):
        raise SystemExit(f"Nothing saved: every call failed. First error: {rows[0]['response']}")
    sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
    run_id = save(args.db, {"suite": args.suite, "target": args.target, "guardrails": 0, "split": None, "repeats": args.repeats,
                            "commit_sha": sha, "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}, rows)
    print(table(rows, args.target))
    for row in rows:
        if row["passed"] == 0 or row["status"] == "error":
            print(f"  {row['status'].upper() if row['status'] != 'ok' else 'FAIL'} {row['case_id']}#{row['repeat']}: "
                  f"{row['response'][:100]!r}")
    print(f"saved as run {run_id} in {args.db}")


if __name__ == "__main__":
    main()
