"""Tests de l'inventaire Android (``guardian.acquisition.android_logical``)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from guardian.acquisition.android_logical import (
    AndroidLogicalAcquirer,
    _parser_composants_admin,
    _parser_liste_composants,
    _parser_paquets,
)
from guardian.core.custody import JournalCustody
from guardian.core.exceptions import ValidationError
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

# adb simulé reproduisant l'échec MASQUÉ observé sur appareil réel (P0-C') :
# « dumpsys <service_absent> » sort en code 0, stdout vide, erreur sur stderr.
_FAKE_ADB_DUMPSYS_ABSENT = """
import sys
ligne = " ".join(sys.argv)
if "device_policy" in ligne:
    sys.stderr.write("Can't find service: device_policy")
    sys.exit(0)
else:
    print("null")
"""

# adb simulé complet : gère aussi bugreport, pull et « pm path » en créant des
# fichiers réels à la destination indiquée en argument.
_FAKE_ADB_COMPLET = """
import os
import sys

argv = sys.argv
ligne = " ".join(argv)
if "bugreport" in ligne:
    with open(argv[-1], "wb") as f:
        f.write(b"FAKE_BUGREPORT_ZIP")
elif "pull" in ligne:
    src, dest = argv[-2], argv[-1]
    os.makedirs(dest, exist_ok=True)
    base = os.path.basename(src)
    nom = "photo.jpg" if base == "sdcard" else base
    with open(os.path.join(dest, nom), "wb") as f:
        f.write(b"FAKE_CONTENU")
elif "path" in ligne:
    print("package:/data/app/com.evil.spy/base.apk")
elif "enabled_accessibility_services" in ligne:
    print("com.evil.spy/.Svc")
elif "enabled_notification_listeners" in ligne:
    print("com.evil.spy/.NL")
elif "device_policy" in ligne:
    print("ComponentInfo{com.evil.spy/.DevAdmin}")
elif "packages" in ligne:
    print("package:com.evil.spy")
else:
    print("null")
"""


# adb simulé : une app en SPLITS (base + split_config.*), comme observé sur appareil
# réel (P1-D). « pm path » liste plusieurs APK ; « pull » crée un fichier par chemin.
_FAKE_ADB_SPLITS = """
import os
import sys

argv = sys.argv
ligne = " ".join(argv)
if "path" in ligne:
    print("package:/data/app/com.evil.spy/base.apk")
    print("package:/data/app/com.evil.spy/split_config.arm64_v8a.apk")
    print("package:/data/app/com.evil.spy/split_config.fr.apk")
elif "pull" in ligne:
    src, dest = argv[-2], argv[-1]
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, os.path.basename(src)), "wb") as f:
        f.write(b"FAKE_APK")
else:
    print("null")
"""

# Variante où un split échoue au pull (exit != 0, aucun fichier créé pour lui).
_FAKE_ADB_SPLITS_PARTIEL = """
import os
import sys

argv = sys.argv
ligne = " ".join(argv)
if "path" in ligne:
    print("package:/data/app/com.evil.spy/base.apk")
    print("package:/data/app/com.evil.spy/split_config.fr.apk")
elif "pull" in ligne:
    src, dest = argv[-2], argv[-1]
    if src.endswith("split_config.fr.apk"):
        sys.exit(1)
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, os.path.basename(src)), "wb") as f:
        f.write(b"FAKE_APK")
else:
    print("null")
"""


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


def _acquereur(
    tmp_path: Path, prog: str = _FAKE_ADB, **options: object
) -> AndroidLogicalAcquirer:
    return AndroidLogicalAcquirer(
        _executor(tmp_path),
        "EMU123",
        commande_adb=[sys.executable, "-c", prog],
        **options,  # type: ignore[arg-type]
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


def test_parser_composants_admin_forme_nue_ecarte_le_bruit() -> None:
    """Format AOSP récent (composant nu) + P0-A : le bruit type LockGuard est écarté.

    Structure observée sur appareil réel : les admins sont des lignes ``composant:``
    indentées sous « Enabled Device Admins (…) ». Une ligne de statistiques contenant
    ``… max calls/s=… max dur/s=…`` NE doit PAS produire de faux « calls/s » / « dur/s »
    (faux positif d'administrateur = signal FORT erroné, cf. essais terrain P0-A).
    """
    sortie = (
        "Current Device Policy Manager state:\n"
        "  Enabled Device Admins (User 0, provisioningState: 0):\n"
        "    com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver:\n"
        "      uid=10099\n"
        "    com.microsoft.office.outlook/com.acompli.accore.receivers"
        ".OutlookDeviceAdminReceiver:\n"
        "      uid=10304\n"
        "  Locks:\n"
        "    LockGuard.guard(): count=158865, max calls/s=3828 max dur/s=52,2ms\n"
    )
    assert _parser_composants_admin(sortie) == [
        "com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver",
        "com.microsoft.office.outlook/com.acompli.accore.receivers.OutlookDeviceAdminReceiver",
    ]


def test_parser_composants_admin_repli_sans_entete() -> None:
    """Sans en-tête reconnu : repli sur les formes strictes (pas la regex globale)."""
    sortie = "ComponentInfo{com.evil/.Admin}\nbruit avec calls/s=10 dur/s=2ms\n"
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


def test_admins_echec_masque_est_non_concluant(tmp_path: Path) -> None:
    """P0-C' : dumpsys exit 0 + stderr (service absent) => non concluant, PAS une absence.

    Sans ce garde-fou, exit 0 + stdout vide serait interprété « aucun administrateur »
    (fausse absence silencieuse). On exige au contraire un résultat indéterminé
    (confiance faible), la sortie brute restant archivée.
    """
    finding = _acquereur(tmp_path, _FAKE_ADB_DUMPSYS_ABSENT).inventorier_admins_appareil()
    assert finding.confidence is Confidence.LOW
    assert "non concluante" in finding.value


def test_extraire_apk_capture_tous_les_splits(tmp_path: Path) -> None:
    """P1-D : une app en splits est capturée ENTIÈREMENT (base + split_*), pas que base."""
    finding, refs = _acquereur(tmp_path, _FAKE_ADB_SPLITS).extraire_apk("com.evil.spy")
    noms = sorted(r.rsplit("/", 1)[-1] for r in refs)
    assert noms == ["base.apk", "split_config.arm64_v8a.apk", "split_config.fr.apk"]
    assert finding.confidence is Confidence.HIGH  # tous les composants récupérés


def test_extraire_apk_split_manquant_signale_partiel(tmp_path: Path) -> None:
    """Un split non récupéré => extraction partielle signalée (confiance faible)."""
    finding, refs = _acquereur(tmp_path, _FAKE_ADB_SPLITS_PARTIEL).extraire_apk("com.evil.spy")
    noms = [r.rsplit("/", 1)[-1] for r in refs]
    assert noms == ["base.apk"]  # le split a échoué
    assert finding.confidence is Confidence.LOW
    assert "NON récupéré" in finding.value


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
    assert "non concluante" in finding.value
    assert "code 2" in finding.value


_SANS_LOURD = {"avec_bugreport": False, "avec_pull_sdcard": False, "avec_apks": False}


# --- Acquisition : inventaire seul -----------------------------------------
def test_acquerir_inventaire_seul(tmp_path: Path) -> None:
    resultat = _acquereur(tmp_path, **_SANS_LOURD).acquerir()
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
    resultat = _acquereur(tmp_path, _FAKE_ADB_ECHEC, **_SANS_LOURD).acquerir()
    assert resultat.complete is False
    assert "PARTIELLE" in resultat.resume()


# --- Captures de fichiers (adb simulé complet) -----------------------------
def test_capturer_bugreport(tmp_path: Path) -> None:
    finding, refs = _acquereur(tmp_path, _FAKE_ADB_COMPLET).capturer_bugreport()
    assert refs == ("artefacts/bugreport.zip",)
    assert (tmp_path / "artefacts" / "bugreport.zip").read_bytes() == b"FAKE_BUGREPORT_ZIP"
    assert finding.severity is Severity.INFO
    assert finding.confidence is Confidence.HIGH
    assert "sha256=" in finding.value


def test_puller_sdcard(tmp_path: Path) -> None:
    finding, refs = _acquereur(tmp_path, _FAKE_ADB_COMPLET).puller_sdcard()
    assert refs == ("artefacts/sdcard/photo.jpg",)
    assert finding.confidence is Confidence.HIGH
    assert "1 fichier" in finding.value


def test_extraire_apk(tmp_path: Path) -> None:
    finding, refs = _acquereur(tmp_path, _FAKE_ADB_COMPLET).extraire_apk("com.evil.spy")
    assert refs == ("artefacts/apk/com.evil.spy/base.apk",)
    assert finding.severity is Severity.MEDIUM
    assert "base.apk=" in finding.value


def test_extraire_apk_paquet_invalide(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        _acquereur(tmp_path, _FAKE_ADB_COMPLET).extraire_apk("paquet invalide!")


def test_acquerir_complet(tmp_path: Path) -> None:
    resultat = _acquereur(tmp_path, _FAKE_ADB_COMPLET).acquerir()
    assert resultat.complete is True
    # 4 inventaire + bugreport + pull /sdcard + 1 APK (com.evil.spy, seul suspect).
    assert len(resultat.findings) == 7
    assert "artefacts/bugreport.zip" in resultat.artefacts
    assert "artefacts/sdcard/photo.jpg" in resultat.artefacts
    assert "artefacts/apk/com.evil.spy/base.apk" in resultat.artefacts

    evenements = [
        json.loads(ligne)["evenement"]
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert evenements[0] == "acquisition_demarree"
    assert evenements[-1] == "acquisition_terminee"
