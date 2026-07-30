"""Tests synthèse + orchestration du rapport (``guardian.report.builder``) — 8.2."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from guardian.analysis.correlator import Correlateur
from guardian.core.custody import JournalCustody, verifier_manifeste
from guardian.core.provenance import (
    CommandTrace,
    Confidence,
    Finding,
    Reproducibility,
    Severity,
    TracedExecutor,
)
from guardian.report.builder import (
    GenerateurRapport,
    convertir_html_en_pdf,
    rendre_synthese_html,
)

# Faux convertisseur HTML→PDF : crée le fichier PDF cible (dernier argument).
_FAKE_PDF = "import sys; open(sys.argv[-1], 'wb').write(b'%PDF-1.4 fake')"


def _finding(
    severity: Severity = Severity.STRONG,
    fid: str = "F-0001",
    value: str = "service d'accessibilité suspect",
) -> Finding:
    trace = CommandTrace(
        binary="adb",
        binary_version="35.0.2",
        args=("adb", "shell"),
        cwd=".",
        exit_code=0,
        duration_ms=5,
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
        reproducibility=Reproducibility.POINT_IN_TIME,
    )


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


# --- Synthèse HTML ---------------------------------------------------------
def test_synthese_html_contient_niveau_et_renvois() -> None:
    synthese = Correlateur([_finding(fid="F-0007")]).correler()
    html_txt = rendre_synthese_html(synthese, identifiant_affaire="2026-001")
    assert "FORTS" in html_txt
    assert 'href="journal_probatoire.html#F-0007"' in html_txt
    assert "[F-0007]" in html_txt
    assert "2026-001" in html_txt
    # La formulation épistémique (limites) est présente.
    assert "Limites de l'analyse" in html_txt


def test_synthese_html_aucun_ne_dit_pas_sain() -> None:
    synthese = Correlateur([_finding(severity=Severity.INFO)]).correler()
    html_txt = rendre_synthese_html(synthese)
    assert "AUCUN_OBSERVABLE" in html_txt
    assert "ne signifie PAS que l'appareil est sain" in html_txt


def test_synthese_html_echappe_le_contenu() -> None:
    synthese = Correlateur([_finding(value="<b>x</b>")]).correler()
    assert "<b>x</b>" not in rendre_synthese_html(synthese)


# --- Conversion PDF --------------------------------------------------------
def test_pdf_absent_retourne_none(tmp_path: Path) -> None:
    source = tmp_path / "s.html"
    source.write_text("<html/>", encoding="utf-8")
    resultat = convertir_html_en_pdf(
        _executor(tmp_path),
        source,
        tmp_path / "s.pdf",
        commande_pdf=["outil_pdf_inexistant_guardian_xyz"],
    )
    assert resultat is None


def test_pdf_produit_avec_outil_simule(tmp_path: Path) -> None:
    source = tmp_path / "s.html"
    source.write_text("<html/>", encoding="utf-8")
    cible = convertir_html_en_pdf(
        _executor(tmp_path),
        source,
        tmp_path / "s.pdf",
        commande_pdf=[sys.executable, "-c", _FAKE_PDF],
    )
    assert cible is not None and cible.is_file()


# --- Orchestration complète ------------------------------------------------
def test_generer_produit_tous_les_livrables(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    findings = [_finding(fid="F-0001"), _finding(fid="F-0002", severity=Severity.INFO)]
    synthese = Correlateur(findings).correler()

    dossier = GenerateurRapport(
        tmp_path,
        findings,
        synthese,
        journal=executor.journal,
        identifiant_affaire="2026-001",
    ).generer()

    for chemin in (
        dossier.journal_jsonl,
        dossier.journal_html,
        dossier.replay_manifest,
        dossier.synthese_html,
        dossier.manifest,
    ):
        assert chemin.is_file()
    assert dossier.synthese_pdf is None  # pas de conversion demandée

    # Le MANIFEST couvre le dossier et se vérifie.
    assert verifier_manifeste(tmp_path) == []

    # La génération est consignée, et le manifeste inclut la synthèse.
    contenu = (tmp_path / "custody.jsonl").read_text(encoding="utf-8")
    assert "rapport_genere" in contenu
    manifeste = dossier.manifest.read_text(encoding="utf-8")
    assert "rapport_synthese.html" in manifeste
    assert "journal_probatoire.jsonl" in manifeste


def test_generer_avec_pdf_simule(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    findings = [_finding()]
    synthese = Correlateur(findings).correler()
    dossier = GenerateurRapport(
        tmp_path,
        findings,
        synthese,
        journal=executor.journal,
        executor=executor,
        convertir_pdf=True,
        commande_pdf=[sys.executable, "-c", _FAKE_PDF],
    ).generer()
    assert dossier.synthese_pdf is not None
    assert dossier.synthese_pdf.is_file()
    # Le PDF est couvert par le manifeste.
    assert "rapport_synthese.pdf" in dossier.manifest.read_text(encoding="utf-8")


def test_journal_jsonl_relit_les_findings(tmp_path: Path) -> None:
    findings = [_finding(fid="F-0001"), _finding(fid="F-0002")]
    synthese = Correlateur(findings).correler()
    dossier = GenerateurRapport(tmp_path, findings, synthese).generer()
    lignes = dossier.journal_jsonl.read_text(encoding="utf-8").strip().splitlines()
    assert [json.loads(ligne)["finding_id"] for ligne in lignes] == ["F-0001", "F-0002"]
