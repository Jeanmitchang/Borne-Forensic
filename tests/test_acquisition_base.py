"""Tests du contrat d'acquisition (``guardian.acquisition.base``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardian.acquisition.base import (
    Acquirer,
    ResultatAcquisition,
    valider_identifiant_appareil,
)
from guardian.core.custody import JournalCustody
from guardian.core.exceptions import ValidationError
from guardian.core.provenance import TracedExecutor
from guardian.detection.usb_watch import TypeAppareil


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


class _AcquereurFactice(Acquirer):
    """Acquéreur minimal pour tester le contrat (n'exécute rien)."""

    @property
    def plateforme(self) -> TypeAppareil:
        return TypeAppareil.ANDROID

    def acquerir(self) -> ResultatAcquisition:
        self._consigner_debut()
        resultat = ResultatAcquisition(
            plateforme=self.plateforme,
            identifiant_appareil=self.identifiant,
            findings=(),
            artefacts=("raw/F-0001.out",),
            complete=True,
        )
        self._consigner_fin(resultat)
        return resultat


# --- Validation d'identifiant ----------------------------------------------
@pytest.mark.parametrize("valide", ["EMU123", "00008030-001A2B", "a.b_c:d-e"])
def test_identifiant_valide(valide: str) -> None:
    assert valider_identifiant_appareil(valide) == valide


@pytest.mark.parametrize("invalide", ["", "avec espace", "point-virgule;rm", "é" * 2])
def test_identifiant_invalide(invalide: str) -> None:
    with pytest.raises(ValidationError):
        valider_identifiant_appareil(invalide)


# --- Contrat Acquirer ------------------------------------------------------
def test_acquirer_est_abstrait(tmp_path: Path) -> None:
    # Impossible d'instancier la classe abstraite directement.
    with pytest.raises(TypeError):
        Acquirer(_executor(tmp_path), "EMU123")  # type: ignore[abstract]


def test_constructeur_valide_l_identifiant(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        _AcquereurFactice(_executor(tmp_path), "identifiant invalide")


def test_acquisition_consigne_debut_et_fin(tmp_path: Path) -> None:
    acq = _AcquereurFactice(_executor(tmp_path), "EMU123")
    assert acq.plateforme is TypeAppareil.ANDROID
    assert acq.identifiant == "EMU123"

    resultat = acq.acquerir()
    assert resultat.complete is True
    assert "complète" in resultat.resume()

    evenements = [
        json.loads(ligne)["evenement"]
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert "acquisition_demarree" in evenements
    assert "acquisition_terminee" in evenements


def test_resume_signale_acquisition_partielle(tmp_path: Path) -> None:
    resultat = ResultatAcquisition(
        plateforme=TypeAppareil.ANDROID,
        identifiant_appareil="EMU123",
        findings=(),
        artefacts=(),
        complete=False,
    )
    assert "PARTIELLE" in resultat.resume()
