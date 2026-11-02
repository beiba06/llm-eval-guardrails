"""Read-only dashboard: serves one page and a summary of the saved runs. No API key here, so visitors can't spend credits."""
import sqlite3
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

ROOT = Path(__file__).parent
DB_PATH = ROOT / "results/results.db"
LATEST = "(SELECT MAX(id) FROM runs GROUP BY suite, target, guardrails, COALESCE(split, ''))"  # a rerun replaces the older run
TOTALS = """SELECT target, COUNT(*) AS trials, COUNT(passed) AS scored, COALESCE(SUM(passed), 0) AS passed,
                   SUM(status = 'refused') AS refused, SUM(status = 'blocked') AS blocked, SUM(status = 'truncated') AS truncated,
                   SUM(status = 'empty') AS empty, SUM(status = 'error') AS errors, SUM(cost) AS cost, SUM(guard_cost) AS guard_cost,
                   SUM(cost) / MAX(SUM(status != 'error'), 1) AS cost_per_query,
                   SUM(tokens_in) AS tokens_in, SUM(tokens_out) AS tokens_out, AVG(NULLIF(latency, 0)) AS seconds"""

app = FastAPI()


def summary(db_path: Path = DB_PATH) -> dict:
    """Every number on the page, recomputed from the raw rows of the latest run of each configuration."""
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        rows = lambda sql: [dict(row) for row in db.execute(sql)]
        joined = f"FROM results r JOIN runs ON runs.id = r.run_id WHERE runs.id IN {LATEST}"
        return {
            "quality": rows(f"{TOTALS} {joined} AND suite = 'quality' GROUP BY target ORDER BY cost_per_query"),
            "quality_by_category": rows(f"""SELECT target, category, COUNT(passed) AS scored, COALESCE(SUM(passed), 0) AS passed
                                            {joined} AND suite = 'quality' GROUP BY target, category ORDER BY category"""),
            "safety": rows(f"""{TOTALS}, r.split AS split, guardrails {joined} AND suite = 'safety' AND target LIKE 'claude%'
                               GROUP BY target, r.split, guardrails ORDER BY r.split DESC, target, guardrails"""),
            "app": rows(f"""{TOTALS}, guardrails {joined} AND suite = 'safety' AND target LIKE 'http%'
                            GROUP BY target, guardrails ORDER BY guardrails"""),
            "safety_by_category": rows(f"""SELECT target, guardrails, category, COUNT(passed) AS scored, COALESCE(SUM(passed), 0) AS passed
                                           {joined} AND suite = 'safety' AND r.split = 'holdout' AND target LIKE 'claude%'
                                           GROUP BY target, guardrails, category ORDER BY category, target, guardrails"""),
            "benign": rows(f"""{TOTALS}, r.split AS split, guardrails {joined} AND suite = 'benign'
                               GROUP BY target, r.split, guardrails ORDER BY r.split DESC, target, guardrails"""),
            "fired": rows(f"""SELECT suite, r.split AS split, guardrails, value AS guardrail, COUNT(*) AS times
                              FROM results r JOIN runs ON runs.id = r.run_id, json_each('["' || REPLACE(r.fired, ',', '","') || '"]')
                              WHERE runs.id IN {LATEST} AND r.fired != '' AND target LIKE 'claude%'
                              GROUP BY suite, r.split, guardrails, value"""),
            "benign_blocked": rows(f"""SELECT DISTINCT r.split AS split, case_id, category, fired
                                       {joined} AND suite = 'benign' AND status = 'blocked' ORDER BY r.split DESC, case_id"""),
            "spend": rows("SELECT ROUND(SUM(cost) + SUM(guard_cost), 2) AS total, COUNT(*) AS trials FROM results")[0],
            "commits": rows("SELECT DISTINCT commit_sha FROM runs"),
        }


@app.get("/")
def index():
    return FileResponse(ROOT / "static/index.html")


@app.get("/api/summary")
def api_summary():
    return summary()


@app.get("/health")
def health():
    return {"ok": True}
