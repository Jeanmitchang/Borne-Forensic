"""Tests du runner MVT (``guardian.analysis.mvt_runner``) — Android (sous-lot 5.1)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from guardian.analysis.mvt_runner import (
    MVTAndroidRunner,
    _empreinte_base_ioc,
    _fichiers_detection,
)
from guardian.core.custody import JournalCustody, hacher_fichier
from guardian.core.exceptions import ValidationError
from guardian.core.provenance import Confidence, Severity, TracedExecutor

# mvt simulé : lit --output pour créer le dossier de résultats et, selon le cas,
# un fichier de détection « *_detected.json ».
_MVT_DETECTE = """
import os, sys
argv = sys.argv
out = argv[argv.index("--output") + 1]
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "packages_detected.json"), "w") as f:
    f.write("[]")
"""
_MVT_RIEN = """
import os, sys
argv = sys.argv
out = argv[argv.index("--output") + 1]
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "packages.json"), "w") as f:
    f.write("[]")
"""
_MVT_ECHEC = "import sys; sys.exit(1)"


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


def _runner(tmp_path: Path, prog: str, **options: object) -> MVTAndroidRunner:
    bugreport = tmp_path / "bugreport.zip"
    bugreport.write_bytes(b"FAKE_BUGREPORT")
    return MVTAndroidRunner(
        _executor(tmp_path),
        bugreport,
        commande_mvt=[sys.executable, "-c", prog],
        **options,  # type: ignore[arg-type]
    )


# --- Helpers purs ----------------------------------------------------------
def test_fichiers_detection(tmp_path: Path) -> None:
    (tmp_path / "a_detected.json").write_text("[]", encoding="utf-8")
    (tmp_path / "b.json").write_text("[]", encoding="utf-8")
    (tmp_path / "c_detected.json").write_text("[]", encoding="utf-8")
    assert [p.name for p in _fichiers_detection(tmp_path)] == [
        "a_detected.json",
        "c_detected.json",
    ]


def test_empreinte_base_ioc_fichier(tmp_path: Path) -> None:
    fichier = tmp_path / "ioc.stix2"
    fichier.write_bytes(b"indicateurs")
    assert _empreinte_base_ioc(fichier) == hacher_fichier(fichier)


def test_empreinte_base_ioc_dossier_est_stable(tmp_path: Path) -> None:
    dossier = tmp_path / "iocs"
    dossier.mkdir()
    (dossier / "a.json").write_text("A", encoding="utf-8")
    (dossier / "b.json").write_text("B", encoding="utf-8")
    empreinte = _empreinte_base_ioc(dossier)
    assert empreinte == _empreinte_base_ioc(dossier)
    assert len(empreinte) == 64


# --- Runner Android --------------------------------------------------------
def test_analyse_detection_est_forte(tmp_path: Path) -> None:
    resultat = _runner(tmp_path, _MVT_DETECTE).analyser()
    assert resultat.complete is True
    finding = resultat.findings[0]
    assert finding.severity is Severity.STRONG
    assert "packages" in finding.value
    assert any(ref.endswith("packages_detected.json") for ref in resultat.artefacts)

    evenements = _evenements(tmp_path)
    assert "analyse_demarree" in evenements
    assert "analyse_terminee" in evenements


def test_analyse_sans_detection_est_info(tmp_path: Path) -> None:
    resultat = _runner(tmp_path, _MVT_RIEN).analyser()
    assert resultat.complete is True
    finding = resultat.findings[0]
    assert finding.severity is Severity.INFO
    assert "aucun IOC" in finding.value


def test_analyse_en_echec_est_non_concluante(tmp_path: Path) -> None:
    resultat = _runner(tmp_path, _MVT_ECHEC).analyser()
    assert resultat.complete is False
    assert resultat.findings[0].confidence is Confidence.LOW
    assert "NON CONCLUANTE" in resultat.resume()


def test_base_ioc_fournie_est_consignee(tmp_path: Path) -> None:
    iocs = tmp_path / "iocs"
    iocs.mkdir()
    (iocs / "stalkerware.stix2").write_text("{}", encoding="utf-8")

    resultat = _runner(tmp_path, _MVT_DETECTE, dossier_ioc=iocs).analyser()
    assert "base IOC" in resultat.findings[0].value
    assert "base_ioc" in (tmp_path / "custody.jsonl").read_text(encoding="utf-8")


def test_sans_ioc_signale_detections_integrees(tmp_path: Path) -> None:
    resultat = _runner(tmp_path, _MVT_RIEN).analyser()
    assert "intégrées" in resultat.findings[0].value


def test_cible_introuvable_leve_validation(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        MVTAndroidRunner(
            _executor(tmp_path),
            tmp_path / "absent.zip",
            commande_mvt=[sys.executable, "-c", _MVT_RIEN],
        )


def test_ioc_introuvable_leve_validation(tmp_path: Path) -> None:
    bugreport = tmp_path / "bugreport.zip"
    bugreport.write_bytes(b"x")
    with pytest.raises(ValidationError):
        MVTAndroidRunner(
            _executor(tmp_path),
            bugreport,
            commande_mvt=[sys.executable, "-c", _MVT_RIEN],
            dossier_ioc=tmp_path / "iocs_absents",
        )


def _evenements(tmp_path: Path) -> list[str]:
    import json

    return [
        json.loads(ligne)["evenement"]
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
