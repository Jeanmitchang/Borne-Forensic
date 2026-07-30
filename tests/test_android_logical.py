"""Tests de l'inventaire Android (``guardian.acquisition.android_logical``)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from guardian.acquisition.android_logical import (
    AndroidLogicalAcquirer,
    _parser_composants_admin,
    _parser_liste_composants,
    _parser_paquets,
)
from guardian.core.custody import JournalCustody
from guardian.core.provenance import Confidence, Severity, TracedExecutor

# adb simulé : sys.executable exécute un script qui inspecte ses arguments pour
# renvoyer une sortie canonique selon la commande shell demandée.
_FAKE_ADB = """
import sys
ligne = " ".join(sys.argv)
if "enabled_accessibility_services" in ligne:
    print("com.evil.spy/.Svc:com.legit.app/.Access")
elif "enabled_notification_listeners" in ligne:
    print("com.evil.spy/.NL")
elif "device_policy" in ligne:
    print("Enabled Device Admins:\\n  admin=ComponentInfo{com.evil.spy/.DevAdmin}")
elif "packages" in ligne:
    print("package:com.evil.spy\\npackage:com.android.legit")
else:
    print("null")
"""

_FAKE_ADB_VIDE = 'import sys; print("null")'
_FAKE_ADB_ECHEC = "import sys; sys.exit(2)"


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


def _acquereur(tmp_path: Path, prog: str = _FAKE_ADB) -> AndroidLogicalAcquirer:
    return AndroidLogicalAcquirer(
        _executor(tmp_path),
        "EMU123",
        commande_adb=[sys.executable, "-c", prog],
    )


# --- Parseurs purs ---------------------------------------------------------
def test_parser_liste_composants() -> None:
    assert _parser_liste_composants("null") == []
    assert _parser_liste_composants("  ") == []
    assert _parser_liste_composants("com.a/.S:com.b/.T\n") == ["com.a/.S", "com.b/.T"]


def test_parser_composants_admin_dedupe() -> None:
    sortie = (
        "Enabled Device Admins:\n"
        "  admin=ComponentInfo{com.evil/.Admin}\n"
        "  autre ComponentInfo{com.evil/.Admin}\n"
    )
    assert _parser_composants_admin(sortie) == ["com.evil/.Admin"]


def test_parser_paquets() -> None:
    sortie = "package:com.a\npackage:com.b\nbruit\n"
    assert _parser_paquets(sortie) == ["com.a", "com.b"]


# --- Relevés (adb simulé) --------------------------------------------------
def test_accessibilite_signal_fort(tmp_path: Path) -> None:
    finding = _acquereur(tmp_path).inventorier_services_accessibilite()
    assert finding.severity is Severity.STRONG
    assert finding.confidence is Confidence.HIGH
    assert "com.evil.spy/.Svc" in finding.value


def test_notifications_signal_fort(tmp_path: Path) -> None:
    finding = _acquereur(tmp_path).inventorier_ecouteurs_notifications()
    assert finding.severity is Severity.STRONG
    assert "com.evil.spy/.NL" in finding.value


def test_admins_signal_fort(tmp_path: Path) -> None:
    finding = _acquereur(tmp_path).inventorier_admins_appareil()
    assert finding.severity is Severity.STRONG
    assert "com.evil.spy/.DevAdmin" in finding.value


def test_paquets_tiers_signal_moyen(tmp_path: Path) -> None:
    finding = _acquereur(tmp_path).inventorier_paquets_tiers()
    assert finding.severity is Severity.MEDIUM
    assert "com.evil.spy" in finding.value


def test_absence_de_signal_est_info(tmp_path: Path) -> None:
    finding = _acquereur(tmp_path, _FAKE_ADB_VIDE).inventorier_services_accessibilite()
    assert finding.severity is Severity.INFO
    assert "Aucun" in finding.value


def test_releve_en_echec_est_faible_confiance(tmp_path: Path) -> None:
    finding = _acquereur(tmp_path, _FAKE_ADB_ECHEC).inventorier_services_accessibilite()
    assert finding.confidence is Confidence.LOW
    assert finding.severity is Severity.INFO
    assert "échec" in finding.value.lower()


# --- Acquisition (inventaire complet) --------------------------------------
def test_acquerir_inventaire_complet(tmp_path: Path) -> None:
    resultat = _acquereur(tmp_path).acquerir()
    assert resultat.complete is True
    assert len(resultat.findings) == 4
    assert len(resultat.artefacts) == 4
    assert all(ref.startswith("raw/") for ref in resultat.artefacts)

    evenements = [
        json.loads(ligne)["evenement"]
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert evenements[0] == "acquisition_demarree"
    assert evenements[-1] == "acquisition_terminee"
    assert evenements.count("commande_executee") == 4


def test_acquerir_incomplet_si_releve_echoue(tmp_path: Path) -> None:
    resultat = _acquereur(tmp_path, _FAKE_ADB_ECHEC).acquerir()
    assert resultat.complete is False
    assert "PARTIELLE" in resultat.resume()
