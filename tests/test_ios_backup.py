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
# comme le ferait le vrai outil.
_BACKUP_OK = "import sys; sys.stdin.read(); print('encryption enabled')"

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


# --- acquerir (sous-lot 4.1 : détection seule) -----------------------------
def test_acquerir_detection_seule_est_partielle(tmp_path: Path) -> None:
    resultat = _acquereur(tmp_path, _INFO_ACTIF).acquerir()
    assert resultat.complete is False
    assert len(resultat.findings) == 1
    assert "PARTIELLE" in resultat.resume()
