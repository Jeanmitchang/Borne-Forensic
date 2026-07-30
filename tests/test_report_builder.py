"""Tests des générateurs de livrables (``guardian.report.builder``) — sous-lot 8.1."""

from __future__ import annotations

import json
from pathlib import Path

from guardian.core.provenance import (
    CommandTrace,
    Confidence,
    Finding,
    Reproducibility,
    Severity,
)
from guardian.report.builder import (
    ecrire_journal_html,
    ecrire_journal_jsonl,
    ecrire_replay_manifest,
    rendre_journal_html,
)


def _finding(
    *,
    fid: str = "F-0001",
    value: str = "observation",
    severity: Severity = Severity.STRONG,
    reproducibility: Reproducibility = Reproducibility.POINT_IN_TIME,
) -> Finding:
    trace = CommandTrace(
        binary="adb",
        binary_version="35.0.2",
        args=("adb", "shell", "settings"),
        cwd=".",
        exit_code=0,
        duration_ms=12,
        stderr_ref=None,
        stderr_sha256=None,
    )
    return Finding(
        finding_id=fid,
        value=value,
        severity=severity,
        confidence=Confidence.HIGH,
        trace=trace,
        raw_output_ref=f"raw/{fid}.out",
        raw_output_sha256="0" * 64,
        timestamp_utc="2026-01-01T00:00:00.000Z",
        operator="expert.forensic",
        reproducibility=reproducibility,
    )


# --- JSONL -----------------------------------------------------------------
def test_journal_jsonl(tmp_path: Path) -> None:
    chemin = ecrire_journal_jsonl(
        tmp_path / "journal_probatoire.jsonl",
        [_finding(fid="F-0001"), _finding(fid="F-0002")],
    )
    lignes = chemin.read_text(encoding="utf-8").strip().splitlines()
    assert len(lignes) == 2
    assert json.loads(lignes[0])["finding_id"] == "F-0001"
    assert json.loads(lignes[1])["trace"]["binary"] == "adb"


def test_journal_jsonl_vide(tmp_path: Path) -> None:
    chemin = ecrire_journal_jsonl(tmp_path / "j.jsonl", [])
    assert chemin.read_text(encoding="utf-8") == ""


# --- replay_manifest -------------------------------------------------------
def test_replay_manifest_ne_garde_que_deterministic(tmp_path: Path) -> None:
    findings = [
        _finding(fid="F-0001", reproducibility=Reproducibility.POINT_IN_TIME),
        _finding(fid="F-0002", reproducibility=Reproducibility.DETERMINISTIC),
        _finding(fid="F-0003", reproducibility=Reproducibility.ENVIRONMENT_DEPENDENT),
    ]
    chemin = ecrire_replay_manifest(tmp_path / "replay_manifest.jsonl", findings)
    lignes = chemin.read_text(encoding="utf-8").strip().splitlines()
    assert len(lignes) == 1
    assert json.loads(lignes[0])["finding_id"] == "F-0002"


def test_replay_manifest_vide_si_aucun_deterministic(tmp_path: Path) -> None:
    chemin = ecrire_replay_manifest(
        tmp_path / "replay.jsonl", [_finding(reproducibility=Reproducibility.POINT_IN_TIME)]
    )
    assert chemin.read_text(encoding="utf-8") == ""


# --- HTML ------------------------------------------------------------------
def test_journal_html_contient_ancres_et_gravite(tmp_path: Path) -> None:
    chemin = ecrire_journal_html(
        tmp_path / "journal_probatoire.html",
        [_finding(fid="F-0007", severity=Severity.STRONG)],
    )
    texte = chemin.read_text(encoding="utf-8")
    assert 'id="F-0007"' in texte
    assert "sev-STRONG" in texte
    assert "[F-0007]" in texte


def test_journal_html_echappe_le_contenu() -> None:
    # Une valeur hostile ne doit pas être injectée telle quelle dans le HTML.
    texte = rendre_journal_html([_finding(value="<script>alert(1)</script>")])
    assert "<script>alert(1)</script>" not in texte
    assert "&lt;script&gt;" in texte


def test_journal_html_vide() -> None:
    assert "Aucun finding" in rendre_journal_html([])
