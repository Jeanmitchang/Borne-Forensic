"""Tests des runners LEAPP (``guardian.analysis.leapp_runner``)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from guardian.analysis.leapp_runner import (
    ALEAPPRunner,
    ILEAPPRunner,
    _trouver_rapport,
)
from guardian.core.custody import JournalCustody
from guardian.core.exceptions import ValidationError
from guardian.core.provenance import Confidence, Severity, TracedExecutor

# leapp simulé : lit -o pour créer un dossier de rapport avec index.html + artefact.
_LEAPP_OK = """
import os, sys
argv = sys.argv
out = argv[argv.index("-o") + 1]
rep = os.path.join(out, "LEAPP_Reports_2026")
os.makedirs(rep, exist_ok=True)
with open(os.path.join(rep, "index.html"), "w") as f:
    f.write("<html>report</html>")
with open(os.path.join(rep, "Accounts.html"), "w") as f:
    f.write("<html>comptes</html>")
"""
_LEAPP_VIDE = "import sys"  # ne crée aucun fichier de sortie
_LEAPP_ECHEC = "import sys; sys.exit(1)"


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


def _cible(tmp_path: Path) -> Path:
    dossier = tmp_path / "acquisition"
    dossier.mkdir()
    (dossier / "donnee.txt").write_text("x", encoding="utf-8")
    return dossier


# --- Helper pur ------------------------------------------------------------
def test_trouver_rapport(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "index.html").write_text("<html/>", encoding="utf-8")
    rapport = _trouver_rapport(tmp_path)
    assert rapport is not None and rapport.name == "index.html"


def test_trouver_rapport_absent(tmp_path: Path) -> None:
    assert _trouver_rapport(tmp_path) is None


# --- ALEAPP (Android) ------------------------------------------------------
def test_aleapp_genere_un_rapport(tmp_path: Path) -> None:
    runner = ALEAPPRunner(
        _executor(tmp_path),
        _cible(tmp_path),
        commande_leapp=[sys.executable, "-c", _LEAPP_OK],
    )
    resultat = runner.analyser()
    assert resultat.complete is True
    finding = resultat.findings[0]
    # Corroboration : gravité INFO, pas STRONG.
    assert finding.severity is Severity.INFO
    assert finding.confidence is Confidence.HIGH
    assert any(ref.endswith("index.html") for ref in resultat.artefacts)


def test_aleapp_sortie_vide_est_non_concluante(tmp_path: Path) -> None:
    runner = ALEAPPRunner(
        _executor(tmp_path),
        _cible(tmp_path),
        commande_leapp=[sys.executable, "-c", _LEAPP_VIDE],
    )
    resultat = runner.analyser()
    assert resultat.complete is False
    assert resultat.findings[0].confidence is Confidence.LOW


def test_aleapp_echec(tmp_path: Path) -> None:
    runner = ALEAPPRunner(
        _executor(tmp_path),
        _cible(tmp_path),
        commande_leapp=[sys.executable, "-c", _LEAPP_ECHEC],
    )
    assert runner.analyser().complete is False


# --- iLEAPP (iOS) ----------------------------------------------------------
def test_ileapp_outil_et_rapport(tmp_path: Path) -> None:
    runner = ILEAPPRunner(
        _executor(tmp_path),
        _cible(tmp_path),
        commande_leapp=[sys.executable, "-c", _LEAPP_OK],
    )
    assert runner.outil == "ileapp"
    resultat = runner.analyser()
    assert resultat.complete is True
    assert "ileapp" in resultat.findings[0].value


# --- Validation ------------------------------------------------------------
def test_type_entree_invalide(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        ALEAPPRunner(
            _executor(tmp_path),
            _cible(tmp_path),
            commande_leapp=[sys.executable, "-c", _LEAPP_OK],
            type_entree="raw",
        )


def test_cible_introuvable(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        ILEAPPRunner(
            _executor(tmp_path),
            tmp_path / "absent",
            commande_leapp=[sys.executable, "-c", _LEAPP_OK],
        )
