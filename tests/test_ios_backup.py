"""Tests de l'acquisition iOS (``guardian.acquisition.ios_backup``)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from guardian.acquisition.ios_backup import EtatChiffrement, IOSBackupAcquirer
from guardian.core.custody import JournalCustody
from guardian.core.exceptions import AcquisitionError
from guardian.core.provenance import Confidence, TracedExecutor

_UDID = "00008030001A2B3C4D"

# Faux ideviceinfo : répond à la requête WillEncrypt.
_INFO_ACTIF = 'print("true")'
_INFO_INACTIF = 'print("false")'
_INFO_ECHEC = "import sys; sys.exit(1)"

# Faux idevicebackup2 : consomme stdin (le mot de passe) SANS le ré-émettre,
# comme le ferait le vrai outil. Ne crée aucun fichier de sauvegarde.
_BACKUP_OK = "import sys; sys.stdin.read(); print('encryption enabled')"

# Faux idevicebackup2 complet : « encryption on » consomme stdin sans l'émettre ;
# « backup <dir> » crée un dossier de sauvegarde réaliste (manifestes + données).
_BACKUP_COMPLET = f"""
import os, sys

argv = sys.argv
ligne = " ".join(argv)
if "encryption" in ligne:
    sys.stdin.read()
    print("encryption enabled")
elif "backup" in ligne:
    dossier = os.path.join(argv[-1], "{_UDID}")
    os.makedirs(dossier, exist_ok=True)
    for nom in ("Manifest.plist", "Status.plist", "Info.plist"):
        with open(os.path.join(dossier, nom), "wb") as f:
            f.write(b"<plist>fake</plist>")
    with open(os.path.join(dossier, "aa11bb22cc"), "wb") as f:
        f.write(b"DONNEES_SAUVEGARDE")
"""

# Jeton distinctif pour traquer une éventuelle fuite du mot de passe.
_SECRET = "Sup3rSecret_backup_2026_XYZ"


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


def _acquereur(
    tmp_path: Path,
    info_prog: str = _INFO_ACTIF,
    backup_prog: str = _BACKUP_OK,
    **options: object,
) -> IOSBackupAcquirer:
    return IOSBackupAcquirer(
        _executor(tmp_path),
        _UDID,
        commande_ideviceinfo=[sys.executable, "-c", info_prog],
        commande_idevicebackup2=[sys.executable, "-c", backup_prog],
        **options,  # type: ignore[arg-type]
    )


# --- Détection d'état (lecture seule) --------------------------------------
def test_detecter_chiffrement_actif(tmp_path: Path) -> None:
    etat, finding = _acquereur(tmp_path, _INFO_ACTIF).detecter_etat_chiffrement()
    assert etat is EtatChiffrement.ACTIF
    assert finding.confidence is Confidence.HIGH
    assert "ACTIF" in finding.value


def test_detecter_chiffrement_inactif(tmp_path: Path) -> None:
    etat, finding = _acquereur(tmp_path, _INFO_INACTIF).detecter_etat_chiffrement()
    assert etat is EtatChiffrement.INACTIF
    assert "CLAIR" in finding.value


def test_detecter_chiffrement_inconnu_si_echec(tmp_path: Path) -> None:
    etat, finding = _acquereur(tmp_path, _INFO_ECHEC).detecter_etat_chiffrement()
    assert etat is EtatChiffrement.INCONNU
    assert finding.confidence is Confidence.LOW


# --- Activation du chiffrement : opt-in obligatoire ------------------------
def test_activation_refusee_sans_optin(tmp_path: Path) -> None:
    acq = _acquereur(tmp_path, fournisseur_mot_de_passe=lambda: _SECRET)
    with pytest.raises(AcquisitionError):
        acq.activer_chiffrement()


def test_activation_refusee_sans_fournisseur(tmp_path: Path) -> None:
    acq = _acquereur(tmp_path, autoriser_activation_chiffrement=True)
    with pytest.raises(AcquisitionError):
        acq.activer_chiffrement()


def test_activation_reussie_avec_optin(tmp_path: Path) -> None:
    acq = _acquereur(
        tmp_path,
        autoriser_activation_chiffrement=True,
        fournisseur_mot_de_passe=lambda: _SECRET,
    )
    finding = acq.activer_chiffrement()
    assert finding.confidence is Confidence.HIGH
    assert "activé" in finding.value.lower()


# --- LE test de sécurité : le mot de passe ne fuit nulle part ---------------
def test_le_mot_de_passe_ne_fuit_pas(tmp_path: Path) -> None:
    acq = _acquereur(
        tmp_path,
        autoriser_activation_chiffrement=True,
        fournisseur_mot_de_passe=lambda: _SECRET,
    )
    acq.activer_chiffrement()

    # Journal de custody : aucune trace du secret (ni dans les args consignés).
    custody = (tmp_path / "custody.jsonl").read_text(encoding="utf-8")
    assert _SECRET not in custody
    assert "chiffrement_sauvegarde_active" in custody

    # Sorties brutes archivées (raw/*.out et *.err) : aucune trace du secret.
    for fichier in (tmp_path / "raw").glob("*"):
        assert _SECRET not in fichier.read_text(encoding="utf-8", errors="replace")


# --- Sauvegarde ------------------------------------------------------------
def test_sauvegarder_produit_et_hache(tmp_path: Path) -> None:
    finding, refs = _acquereur(tmp_path, backup_prog=_BACKUP_COMPLET).sauvegarder()
    assert finding.confidence is Confidence.HIGH
    assert any(ref.endswith("Manifest.plist") for ref in refs)
    assert "Manifest.plist=" in finding.value  # empreinte présente


def test_sauvegarder_echec_si_aucun_fichier(tmp_path: Path) -> None:
    # _BACKUP_OK ne crée aucun fichier : la sauvegarde doit être signalée non concluante.
    finding, refs = _acquereur(tmp_path, backup_prog=_BACKUP_OK).sauvegarder()
    assert finding.confidence is Confidence.LOW
    assert refs == ()


# --- acquerir (orchestration complète) -------------------------------------
def test_acquerir_complet_chiffrement_actif(tmp_path: Path) -> None:
    resultat = _acquereur(
        tmp_path, info_prog=_INFO_ACTIF, backup_prog=_BACKUP_COMPLET
    ).acquerir()
    assert resultat.complete is True
    # détection d'état + sauvegarde (pas d'activation, déjà actif).
    assert len(resultat.findings) == 2
    assert any(ref.endswith("Manifest.plist") for ref in resultat.artefacts)


def test_acquerir_inactif_sans_optin_sauvegarde_quand_meme(tmp_path: Path) -> None:
    resultat = _acquereur(
        tmp_path, info_prog=_INFO_INACTIF, backup_prog=_BACKUP_COMPLET
    ).acquerir()
    assert resultat.complete is True
    assert len(resultat.findings) == 2  # état + sauvegarde, pas d'activation
    assert "CLAIR" in resultat.findings[0].value


def test_acquerir_inactif_avec_optin_active_le_chiffrement(tmp_path: Path) -> None:
    resultat = _acquereur(
        tmp_path,
        info_prog=_INFO_INACTIF,
        backup_prog=_BACKUP_COMPLET,
        autoriser_activation_chiffrement=True,
        fournisseur_mot_de_passe=lambda: _SECRET,
    ).acquerir()
    assert resultat.complete is True
    # état + activation + sauvegarde.
    assert len(resultat.findings) == 3

    # Même via acquerir(), le mot de passe ne fuit pas.
    custody = (tmp_path / "custody.jsonl").read_text(encoding="utf-8")
    assert _SECRET not in custody
    for fichier in (tmp_path / "raw").glob("*"):
        assert _SECRET not in fichier.read_text(encoding="utf-8", errors="replace")
