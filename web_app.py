from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from flask import Flask, jsonify, render_template, request

from log_analyzer import analyze, build_report

BASE_DIR = Path(__file__).resolve().parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

DEFAULT_MIN_FAILS = 3
DEFAULT_FAIL_WINDOW = 60
DEFAULT_PORT_THRESHOLD = 10
DEFAULT_PORT_WINDOW = 300
DEFAULT_TOP = 5


def _lines_from_text(text: str) -> Iterable[str]:
    for line in text.splitlines():
        yield line + "\n"


def _parse_blacklist(text: str) -> set[str]:
    ips: set[str] = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        ips.add(s)
    return ips


def _collect_input() -> tuple[Optional[str], set[str], Optional[str]]:
    pasted_logs = request.form.get("logs", "")
    blacklist_text = request.form.get("blacklist", "")
    blacklist = _parse_blacklist(blacklist_text)

    log_text: Optional[str] = None
    if pasted_logs.strip():
        log_text = pasted_logs
    else:
        upload = request.files.get("logfile")
        if upload and upload.filename:
            log_text = upload.read().decode("utf-8", errors="replace")

    if not log_text or not log_text.strip():
        return None, blacklist, "Please upload a log file or paste logs."

    return log_text, blacklist, None


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    if request.method == "POST":
        log_text, blacklist, error = _collect_input()
        if not error:
            alerts, stats = analyze(
                _lines_from_text(log_text),
                blacklist,
                min_fails=DEFAULT_MIN_FAILS,
                fail_window=DEFAULT_FAIL_WINDOW,
                port_threshold=DEFAULT_PORT_THRESHOLD,
                port_window=DEFAULT_PORT_WINDOW,
            )
            result = build_report(alerts, stats, DEFAULT_TOP)

    return render_template("index.html", result=result, error=error)


@app.route("/export", methods=["POST"])
def export_json():
    log_text, blacklist, error = _collect_input()
    if error:
        return jsonify({"error": error}), 400

    alerts, stats = analyze(
        _lines_from_text(log_text),
        blacklist,
        min_fails=DEFAULT_MIN_FAILS,
        fail_window=DEFAULT_FAIL_WINDOW,
        port_threshold=DEFAULT_PORT_THRESHOLD,
        port_window=DEFAULT_PORT_WINDOW,
    )
    report = build_report(alerts, stats, DEFAULT_TOP)
    return jsonify(report)


if __name__ == "__main__":
    app.run(debug=True)
