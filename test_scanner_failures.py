"""外部検査が完了していないのに「検出なし」としないことを確認する。"""
import json
import subprocess
from types import SimpleNamespace

import pytest
from openpyxl import load_workbook

import security_check


SCANNERS = [
    ("bandit", "run_bandit", {"results": []}),
    ("pip-audit", "run_pip_audit", {"dependencies": []}),
    ("detect-secrets", "run_detect_secrets", {"results": {}}),
]


def run_scanner(monkeypatch, tmp_path, runner, returncode, stdout):
    (tmp_path / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
    monkeypatch.setattr(
        security_check.subprocess, "run",
        lambda *a, **k: SimpleNamespace(
            returncode=returncode, stdout=stdout, stderr="scanner diagnostic"
        ),
    )
    return getattr(security_check, runner)(str(tmp_path))


@pytest.mark.parametrize("tool,runner,valid", SCANNERS)
@pytest.mark.parametrize("failure", [
    "error_empty", "error_json", "success_empty", "missing_key",
    "not_object", "wrong_container", "invalid_json",
])
def test_incomplete_scan_is_an_error(monkeypatch, tmp_path, tool, runner, valid, failure):
    cases = {
        "error_empty": (2, ""),
        "error_json": (2, json.dumps(valid)),
        "success_empty": (0, ""),
        "missing_key": (0, "{}"),
        "not_object": (0, "[]"),
        "wrong_container": (0, json.dumps({
            key: [] if isinstance(value, dict) else {} for key, value in valid.items()
        })),
        "invalid_json": (0, "not json"),
    }
    findings, error = run_scanner(monkeypatch, tmp_path, runner, *cases[failure])
    assert findings == []
    assert error and tool in error


@pytest.mark.parametrize("tool,runner,valid", SCANNERS)
def test_successful_scan_without_findings_is_not_an_error(
    monkeypatch, tmp_path, tool, runner, valid
):
    findings, error = run_scanner(monkeypatch, tmp_path, runner, 0, json.dumps(valid))
    assert findings == []
    assert error is None


@pytest.mark.parametrize("runner,valid", [
    ("run_bandit", {"results": []}),
    ("run_pip_audit", {"dependencies": []}),
])
def test_exit_one_without_findings_is_not_success(monkeypatch, tmp_path, runner, valid):
    findings, error = run_scanner(monkeypatch, tmp_path, runner, 1, json.dumps(valid))
    assert findings == []
    assert error is not None


def test_detect_secrets_exit_one_is_an_error(monkeypatch, tmp_path):
    findings, error = run_scanner(
        monkeypatch, tmp_path, "run_detect_secrets", 1, '{"results": {}}'
    )
    assert findings == []
    assert error is not None


def test_bandit_file_scan_errors_are_not_hidden(monkeypatch, tmp_path):
    findings, error = run_scanner(
        monkeypatch, tmp_path, "run_bandit", 0,
        json.dumps({"results": [], "errors": [{"filename": "bad.py", "reason": "syntax"}]}),
    )
    assert findings == []
    assert error is not None


def test_unexamined_dependency_is_not_hidden(monkeypatch, tmp_path):
    findings, error = run_scanner(
        monkeypatch, tmp_path, "run_pip_audit", 0,
        json.dumps({"dependencies": [{"name": "private", "skip_reason": "not on PyPI"}]}),
    )
    assert findings == []
    assert error is not None


def test_report_marks_failed_checks_as_incomplete(monkeypatch, tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
    monkeypatch.setattr(
        security_check.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a[0], 2, stdout="", stderr="scanner failed"
        ),
    )
    report = tmp_path / "result.xlsx"
    security_check.build_report(str(target), str(report))
    workbook = load_workbook(report)
    summary = workbook["検査結果サマリー"]
    judge = next(row[1] for row in summary.values if row[0] == "総合判定")
    assert "実行できませんでした" in judge
    assert "検出なし" not in judge
    for tool, _, _ in SCANNERS:
        assert any(row[0] == tool for row in summary.values)
    details = str(workbook["自動チェック結果"]["E2"].value)
    assert "未完了" in details
    assert "見つかりませんでした" not in details
