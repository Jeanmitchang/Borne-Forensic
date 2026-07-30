"""Tests de l'orchestrateur d'affaire (``guardian.affaire``) — sous-lot 9.1."""

from __future__ import annotations

import sys
from pathlib import Path

from guardian.acquisition.android_logical import AndroidLogicalAcquirer
from guardian.affaire import Affaire
from guardian.analysis.correlator import NiveauIndices
from guardian.analysis.mvt_runner import MVTAndroidRunner
from guardian.core.custody import Consentement, verifier_manifeste

# adb simulé (inventaire des signaux forts).
_FAKE_ADB = """
import sys
ligne = " ".join(sys.argv)
if "enabled_accessibility_services" in ligne:
    print("com.mspy.core/.AccessSvc")
elif "enabled_notification_listeners" in ligne:
    print("com.mspy.core/.NL")
elif "device_policy" in ligne:
    print("ComponentInfo{com.mspy.core/.DevAdmin}")
elif "packages" in ligne:
    print("package:com.mspy.core")
else:
    print("null")
"""
# mvt simulé (une détection).
_FAKE_MVT = """
import os, sys
out = sys.argv[sys.argv.index("--output") + 1]
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "packages_detected.json"), "w") as f:
    f.write("[]")
"""


def _consentement() -> Consentement:
    return Consentement(
        identifiant_affaire="2026-001",
        proprietaire_support="Victime référencée V1",
        operateur="expert.forensic",
        description_support="Pixel 6, Android 14",
        portee="Acquisition logique sans root + analyse MVT",
    )


def _ouvrir(tmp_path: Path) -> Affaire:
    return Affaire.ouvrir(
        tmp_path / "affaire",
        identifiant_affaire="2026-001",
        operateur="expert.forensic",
        consentement=_consentement(),
    )


def test_ouvrir_amorce_custody_et_consentement(tmp_path: Path) -> None:
    affaire = _ouvrir(tmp_path)
    assert (affaire.dossier / "consent.json").is_file()
    contenu = (affaire.dossier / "custody.jsonl").read_text(encoding="utf-8")
    assert "affaire_ouverte" in contenu
    assert "consentement_enregistre" in contenu


def test_acquisition_puis_analyse_accumulent_les_findings(tmp_path: Path) -> None:
    affaire = _ouvrir(tmp_path)
    acquereur = AndroidLogicalAcquirer(
        affaire.executor,
        "EMU123",
        commande_adb=[sys.executable, "-c", _FAKE_ADB],
        avec_bugreport=False,
        avec_pull_sdcard=False,
        avec_apks=False,
    )
    affaire.acquerir(acquereur)
    assert len(affaire.findings) == 4  # 3 signaux forts + paquets tiers

    bugreport = affaire.dossier / "bugreport.zip"
    bugreport.write_bytes(b"FAKE")
    affaire.analyser(
        MVTAndroidRunner(
            affaire.executor, bugreport, commande_mvt=[sys.executable, "-c", _FAKE_MVT]
        )
    )
    assert len(affaire.findings) == 5  # + 1 détection MVT


def test_pipeline_complet_produit_un_dossier_verifiable(tmp_path: Path) -> None:
    affaire = _ouvrir(tmp_path)
    affaire.acquerir(
        AndroidLogicalAcquirer(
            affaire.executor,
            "EMU123",
            commande_adb=[sys.executable, "-c", _FAKE_ADB],
            avec_bugreport=False,
            avec_pull_sdcard=False,
            avec_apks=False,
        )
    )
    bugreport = affaire.dossier / "bugreport.zip"
    bugreport.write_bytes(b"FAKE")
    affaire.analyser(
        MVTAndroidRunner(
            affaire.executor, bugreport, commande_mvt=[sys.executable, "-c", _FAKE_MVT]
        )
    )

    synthese = affaire.correler()
    # Signaux forts mSpy (accessibilité, admin, MVT) → faisceau FORT.
    assert synthese.niveau is NiveauIndices.FORTS

    rapport = affaire.generer_rapport()
    assert rapport.synthese_html.is_file()
    assert rapport.manifest.is_file()
    assert verifier_manifeste(affaire.dossier) == []

    # La trame complète est consignée dans la custody.
    contenu = (affaire.dossier / "custody.jsonl").read_text(encoding="utf-8")
    for evenement in (
        "affaire_ouverte",
        "consentement_enregistre",
        "acquisition_terminee",
        "analyse_terminee",
        "synthese_correlation",
        "rapport_genere",
        "manifeste_genere",
    ):
        assert evenement in contenu


def test_generer_rapport_correle_automatiquement(tmp_path: Path) -> None:
    affaire = _ouvrir(tmp_path)
    affaire.acquerir(
        AndroidLogicalAcquirer(
            affaire.executor,
            "EMU123",
            commande_adb=[sys.executable, "-c", _FAKE_ADB],
            avec_bugreport=False,
            avec_pull_sdcard=False,
            avec_apks=False,
        )
    )
    # Pas d'appel explicite à correler() : generer_rapport doit s'en charger.
    rapport = affaire.generer_rapport()
    assert affaire.synthese is not None
    assert rapport.synthese_html.is_file()
