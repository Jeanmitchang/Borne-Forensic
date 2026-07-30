"""Tests du runner Autopsy (``guardian.analysis.autopsy_runner``) — Étape 10."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from guardian.analysis.autopsy_runner import AutopsyRunner, _trouver_rapport
from guardian.core.custody import JournalCustody
from guardian.core.exceptions import ValidationError
from guardian.core.provenance import Confidence, Severity, TracedExecutor

# autopsy simulé : lit --output pour créer un rapport de corroboration.
_AUTOPSY_OK = """
import os, sys
argv = sys.argv
out = argv[argv.index("--output") + 1]
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "report.html"), "w") as f:
    f.write("<html>autopsy</html>")
with open(os.path.join(out, "timeline.csv"), "w") as f:
    f.write("t,evt\\n")
"""
_AUTOPSY_VIDE = "import sys"
_AUTOPSY_ECHEC = "import sys; sys.exit(1)"


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "image.dd").write_bytes(b"donnees")
    return source


def _runner(tmp_path: Path, prog: str) -> AutopsyRunner:
    return AutopsyRunner(
        _executor(tmp_path),
        _source(tmp_path),
        commande_autopsy=[sys.executable, "-c", prog],
    )


def test_trouver_rapport(tmp_path: Path) -> None:
    (tmp_path / "report.html").write_text("<html/>", encoding="utf-8")
    rapport = _trouver_rapport(tmp_path)
    assert rapport is not None and rapport.name == "report.html"


def test_outil_est_autopsy(tmp_path: Path) -> None:
    assert _runner(tmp_path, _AUTOPSY_VIDE).outil == "autopsy"


def test_corroboration_est_info(tmp_path: Path) -> None:
    resultat = _runner(tmp_path, _AUTOPSY_OK).analyser()
    assert resultat.complete is True
    finding = resultat.findings[0]
    # Corroboration : INFO, pas STRONG.
    assert finding.severity is Severity.INFO
    assert finding.confidence is Confidence.HIGH
    assert any(ref.endswith("report.html") for ref in resultat.artefacts)

    evenements = [
        json.loads(ligne)["evenement"]
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert "analyse_demarree" in evenements
    assert "analyse_terminee" in evenements


def test_sortie_vide_est_non_concluante(tmp_path: Path) -> None:
    resultat = _runner(tmp_path, _AUTOPSY_VIDE).analyser()
    assert resultat.complete is False
    assert resultat.findings[0].confidence is Confidence.LOW


def test_echec_est_non_concluant(tmp_path: Path) -> None:
    assert _runner(tmp_path, _AUTOPSY_ECHEC).analyser().complete is False


def test_source_introuvable(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        AutopsyRunner(
            _executor(tmp_path),
            tmp_path / "absente",
            commande_autopsy=[sys.executable, "-c", _AUTOPSY_OK],
        )


def test_flags_et_args_configurables(tmp_path: Path) -> None:
    """Les drapeaux et args supplémentaires apparaissent dans la commande tracée."""
    prog = """
import os, sys
argv = sys.argv
out = argv[argv.index("-o") + 1]
os.makedirs(out, exist_ok=True)
open(os.path.join(out, "report.html"), "w").write("<html/>")
"""
    runner = AutopsyRunner(
        _executor(tmp_path),
        _source(tmp_path),
        commande_autopsy=[sys.executable, "-c", prog],
        flag_entree="-i",
        flag_sortie="-o",
        args_supplementaires=["--nosplash"],
    )
    runner.analyser()
    entrees = [
        json.loads(ligne)
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    commande = next(e for e in entrees if e["evenement"] == "commande_executee")
    args = commande["details"]["args"]
    assert "--nosplash" in args
    assert "-i" in args and "-o" in args
