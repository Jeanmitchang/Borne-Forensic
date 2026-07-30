"""Tests du corrélateur (``guardian.analysis.correlator``)."""

from __future__ import annotations

import json
from pathlib import Path

from guardian.analysis.correlator import Correlateur, NiveauIndices
from guardian.core.custody import JournalCustody
from guardian.core.provenance import (
    CommandTrace,
    Confidence,
    Finding,
    Reproducibility,
    Severity,
)


def _finding(
    severity: Severity,
    confidence: Confidence = Confidence.HIGH,
    value: str = "observation",
    fid: str = "F-0001",
) -> Finding:
    trace = CommandTrace(
        binary="outil",
        binary_version=None,
        args=("outil",),
        cwd=".",
        exit_code=0,
        duration_ms=1,
        stderr_ref=None,
        stderr_sha256=None,
    )
    return Finding(
        finding_id=fid,
        value=value,
        severity=severity,
        confidence=confidence,
        trace=trace,
        raw_output_ref="raw/x.out",
        raw_output_sha256="0" * 64,
        timestamp_utc="2026-01-01T00:00:00.000Z",
        operator="expert.forensic",
        reproducibility=Reproducibility.POINT_IN_TIME,
    )


def _correler(*findings: Finding) -> object:
    return Correlateur(findings).correler()


# --- Niveaux ---------------------------------------------------------------
def test_strong_confiant_est_forts() -> None:
    assert _correler(_finding(Severity.STRONG, Confidence.HIGH)).niveau is NiveauIndices.FORTS
    assert (
        _correler(_finding(Severity.STRONG, Confidence.MEDIUM)).niveau is NiveauIndices.FORTS
    )


def test_strong_peu_fiable_est_modere() -> None:
    synthese = _correler(_finding(Severity.STRONG, Confidence.LOW))
    assert synthese.niveau is NiveauIndices.MODERES


def test_medium_confiant_est_modere() -> None:
    synthese = _correler(_finding(Severity.MEDIUM, Confidence.HIGH))
    assert synthese.niveau is NiveauIndices.MODERES


def test_weak_est_faible() -> None:
    assert _correler(_finding(Severity.WEAK)).niveau is NiveauIndices.FAIBLES


def test_info_seul_est_aucun_observable() -> None:
    assert _correler(_finding(Severity.INFO)).niveau is NiveauIndices.AUCUN_OBSERVABLE


def test_vide_est_aucun_observable() -> None:
    assert Correlateur([]).correler().niveau is NiveauIndices.AUCUN_OBSERVABLE


# --- Formulation épistémique -----------------------------------------------
def test_formulation_aucun_ne_dit_jamais_sain() -> None:
    texte = _correler(_finding(Severity.INFO)).formulation()
    assert "PARMI CEUX OBSERVABLES" in texte
    assert "ne signifie PAS que l'appareil est sain" in texte


def test_formulation_forts_oriente_vers_plainte() -> None:
    texte = _correler(_finding(Severity.STRONG)).formulation()
    assert "dépôt de plainte" in texte
    assert "ne conclut pas à la culpabilité" in texte


def test_limites_toujours_presentes() -> None:
    # Même avec des indices FORTS, les limites accompagnent la synthèse.
    synthese = _correler(_finding(Severity.STRONG))
    assert len(synthese.limites) >= 4
    assert "Limites de l'analyse" in synthese.formulation()


# --- Agrégation ------------------------------------------------------------
def test_comptes_par_gravite() -> None:
    synthese = _correler(
        _finding(Severity.STRONG),
        _finding(Severity.STRONG),
        _finding(Severity.MEDIUM),
        _finding(Severity.INFO),
    )
    comptes = synthese.comptes()
    assert comptes["STRONG"] == 2
    assert comptes["MEDIUM"] == 1
    assert comptes["INFO"] == 1
    assert comptes["WEAK"] == 0


def test_findings_tries_par_gravite_decroissante() -> None:
    synthese = _correler(
        _finding(Severity.WEAK),
        _finding(Severity.STRONG),
        _finding(Severity.MEDIUM),
    )
    assert synthese.findings[0].severity is Severity.STRONG
    assert synthese.findings[-1].severity is Severity.WEAK


def test_score_pondere() -> None:
    # STRONG×HIGH = 10 ; MEDIUM×HIGH = 4 → 14.
    synthese = _correler(
        _finding(Severity.STRONG, Confidence.HIGH),
        _finding(Severity.MEDIUM, Confidence.HIGH),
    )
    assert synthese.score == 14.0


def test_vers_dict_est_serialisable() -> None:
    synthese = _correler(_finding(Severity.STRONG))
    dico = synthese.vers_dict()
    json.dumps(dico)  # ne doit pas lever
    assert dico["niveau"] == "FORTS"
    assert dico["findings"][0]["finding_id"] == "F-0001"


def test_journal_consigne_la_synthese(tmp_path: Path) -> None:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    Correlateur([_finding(Severity.STRONG)], journal=journal).correler()
    contenu = (tmp_path / "custody.jsonl").read_text(encoding="utf-8")
    assert "synthese_correlation" in contenu
    assert "FORTS" in contenu
