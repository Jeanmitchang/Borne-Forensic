"""Tests de la détection USB (``guardian.detection.usb_watch``)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from guardian.core.custody import JournalCustody
from guardian.core.provenance import TracedExecutor
from guardian.detection.usb_watch import (
    DetecteurUSB,
    EtatAppareil,
    TypeAppareil,
    _etat_android,
    _parser_adb_devices,
    _parser_idevice_id,
)

# Outils simulés : sys.executable joue le rôle du binaire (toujours trouvable par
# shutil.which), avec une sortie canonique injectée.
_FAKE_ADB = (
    "import sys; sys.stdout.write('List of devices attached\\n"
    "* daemon started successfully *\\n"
    "EMU123\\tdevice\\nUNAUTH9\\tunauthorized\\n"
    "OFF7\\toffline\\nNOPERM1\\tno permissions (udev)\\n')"
)
_FAKE_ADB_VIDE = "import sys; sys.stdout.write('List of devices attached\\n')"
_FAKE_IOS = "import sys; sys.stdout.write('00008030-001A2B3C4D\\nabcd1234ef567890\\n')"
_ABSENT = "binaire_inexistant_guardian_xyz"


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


# --- Parseurs purs ---------------------------------------------------------
def test_parser_idevice_id() -> None:
    sortie = "00008030-001A2B3C4D\n\nabcd1234ef567890\n"
    assert _parser_idevice_id(sortie) == ["00008030-001A2B3C4D", "abcd1234ef567890"]


def test_parser_adb_devices_ignore_entete_et_daemon() -> None:
    sortie = (
        "List of devices attached\n"
        "* daemon started successfully *\n"
        "SERIAL1\tdevice\n"
        "SERIAL2\tunauthorized\n"
        "\n"
    )
    assert _parser_adb_devices(sortie) == [
        ("SERIAL1", "device"),
        ("SERIAL2", "unauthorized"),
    ]


def test_parser_adb_devices_no_permissions_avec_complement() -> None:
    # « no permissions » comporte des espaces : la coupe doit préserver l'état complet.
    paires = _parser_adb_devices("List of devices attached\nS1\tno permissions (udev)\n")
    assert paires == [("S1", "no permissions (udev)")]


@pytest.mark.parametrize(
    ("brut", "attendu"),
    [
        ("device", EtatAppareil.PRET),
        ("unauthorized", EtatAppareil.NON_AUTORISE),
        ("offline", EtatAppareil.HORS_LIGNE),
        ("no permissions (udev)", EtatAppareil.SANS_PERMISSION),
        ("recovery", EtatAppareil.INCONNU),
    ],
)
def test_etat_android(brut: str, attendu: EtatAppareil) -> None:
    assert _etat_android(brut) == attendu


# --- Détection Android -----------------------------------------------------
def test_detecter_android_interprete_les_etats(tmp_path: Path) -> None:
    det = DetecteurUSB(
        _executor(tmp_path),
        commande_android=[sys.executable, "-c", _FAKE_ADB],
        commande_ios=[_ABSENT],
    )
    res = det.detecter_android()

    assert res.outil_disponible is True
    etats = {a.identifiant: a.etat for a in res.appareils}
    assert etats == {
        "EMU123": EtatAppareil.PRET,
        "UNAUTH9": EtatAppareil.NON_AUTORISE,
        "OFF7": EtatAppareil.HORS_LIGNE,
        "NOPERM1": EtatAppareil.SANS_PERMISSION,
    }
    # Chaque appareil porte la trace de la commande de détection.
    assert all(a.finding_id.startswith("F-") for a in res.appareils)
    # Les appareils non prêts sont diagnostiqués ; l'appareil prêt ne l'est pas.
    diag = " ".join(res.diagnostics)
    assert "UNAUTH9" in diag and "OFF7" in diag and "NOPERM1" in diag
    assert "EMU123" not in diag


def test_detecter_android_outil_absent(tmp_path: Path) -> None:
    det = DetecteurUSB(_executor(tmp_path), commande_android=[_ABSENT])
    res = det.detecter_android()
    assert res.outil_disponible is False
    assert res.appareils == ()
    assert any("indisponible" in d for d in res.diagnostics)


def test_detecter_android_aucun_appareil(tmp_path: Path) -> None:
    det = DetecteurUSB(
        _executor(tmp_path),
        commande_android=[sys.executable, "-c", _FAKE_ADB_VIDE],
    )
    res = det.detecter_android()
    assert res.outil_disponible is True
    assert res.appareils == ()
    assert any("Aucun appareil Android" in d for d in res.diagnostics)


# --- Détection iOS ---------------------------------------------------------
def test_detecter_ios_liste_les_udids(tmp_path: Path) -> None:
    det = DetecteurUSB(
        _executor(tmp_path),
        commande_ios=[sys.executable, "-c", _FAKE_IOS],
        commande_android=[_ABSENT],
    )
    res = det.detecter_ios()
    assert res.outil_disponible is True
    assert [a.identifiant for a in res.appareils] == [
        "00008030-001A2B3C4D",
        "abcd1234ef567890",
    ]
    assert all(a.etat is EtatAppareil.PRET for a in res.appareils)
    assert all(a.type is TypeAppareil.IOS for a in res.appareils)


def test_detecter_ios_outil_absent(tmp_path: Path) -> None:
    det = DetecteurUSB(_executor(tmp_path), commande_ios=[_ABSENT])
    res = det.detecter_ios()
    assert res.outil_disponible is False
    assert any("indisponible" in d for d in res.diagnostics)


# --- Détection combinée + custody ------------------------------------------
def test_detecter_combine_consigne_les_appareils(tmp_path: Path) -> None:
    det = DetecteurUSB(
        _executor(tmp_path),
        commande_ios=[sys.executable, "-c", _FAKE_IOS],
        commande_android=[sys.executable, "-c", _FAKE_ADB],
    )
    res = det.detecter()

    assert len(res.tous_les_appareils()) == 6  # 2 iOS + 4 Android
    # 2 iOS (PRET) + 1 Android PRET (EMU123) ; les 3 autres Android ne sont pas prêts.
    assert len(res.appareils_prets()) == 3

    entrees = [
        json.loads(ligne)
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    consignation = next(e for e in entrees if e["evenement"] == "appareils_detectes")
    assert len(consignation["details"]["appareils"]) == 6
    identifiants = {a["identifiant"] for a in consignation["details"]["appareils"]}
    assert "00008030-001A2B3C4D" in identifiants
    assert "EMU123" in identifiants


def test_resume_est_lisible(tmp_path: Path) -> None:
    det = DetecteurUSB(
        _executor(tmp_path),
        commande_ios=[_ABSENT],
        commande_android=[sys.executable, "-c", _FAKE_ADB_VIDE],
    )
    texte = det.detecter().resume()
    assert "Détection USB" in texte
    assert "Aucun appareil" in texte
