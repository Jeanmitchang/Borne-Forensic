"""Tests de la vérification d'environnement (``guardian.core.environment``)."""

from __future__ import annotations

import sys
from pathlib import Path

from guardian.core.custody import JournalCustody
from guardian.core.environment import (
    Dependance,
    Exigence,
    TypeDependance,
    VerificateurEnvironnement,
    verifier_environnement,
)
from guardian.core.provenance import RegistreVersions, TracedExecutor


def _dep_python() -> Dependance:
    return Dependance(
        nom="Python ≥ 3.11",
        type=TypeDependance.RUNTIME,
        exigence=Exigence.OBLIGATOIRE,
        role="Runtime",
        installation="apt install python3.11",
        cible="",
    )


def _dep_binaire_absent() -> Dependance:
    return Dependance(
        nom="Outil fictif",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.RECOMMANDEE,
        role="Test",
        installation="apt install outil-fictif",
        cible="binaire_inexistant_guardian_xyz",
    )


def _dep_paquet(cible: str, exigence: Exigence = Exigence.OPTIONNELLE) -> Dependance:
    return Dependance(
        nom=f"paquet {cible}",
        type=TypeDependance.PAQUET_PYTHON,
        exigence=exigence,
        role="Test",
        installation=f"pip install {cible}",
        cible=cible,
    )


def test_runtime_python_present() -> None:
    rapport = VerificateurEnvironnement((_dep_python(),)).verifier()
    (resultat,) = rapport.resultats
    assert resultat.presente is True
    assert resultat.version is not None
    assert rapport.tout_obligatoire_present()


def test_binaire_absent_est_signale_sans_crash() -> None:
    rapport = VerificateurEnvironnement((_dep_binaire_absent(),)).verifier()
    (resultat,) = rapport.resultats
    assert resultat.presente is False
    assert "introuvable" in resultat.detail.lower()


def test_obligatoire_absent_bloque() -> None:
    dep = Dependance(
        nom="Outil critique fictif",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.OBLIGATOIRE,
        role="Test",
        installation="…",
        cible="binaire_inexistant_guardian_xyz",
    )
    rapport = VerificateurEnvironnement((dep,)).verifier()
    assert not rapport.tout_obligatoire_present()
    assert rapport.manquants_obligatoires()[0].dependance.nom == "Outil critique fictif"


def test_paquet_python_present_et_absent() -> None:
    # « json » est toujours importable ; un nom bidon ne l'est jamais.
    rapport = VerificateurEnvironnement(
        (_dep_paquet("json"), _dep_paquet("paquet_bidon_guardian_xyz"))
    ).verifier()
    present, absent = rapport.resultats
    assert present.presente is True
    assert absent.presente is False


def test_capture_version_via_executor(tmp_path: Path) -> None:
    """Avec un TracedExecutor, la version d'un binaire est captée (et tracée)."""
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="op")
    registre = RegistreVersions()
    executor = TracedExecutor(tmp_path, "op", journal, registre)

    # On sonde l'interpréteur Python courant, garanti présent, via « --version ».
    dep = Dependance(
        nom="Python (sondé)",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.OPTIONNELLE,
        role="Test",
        installation="…",
        cible=sys.executable,
        commande_version=("--version",),
    )
    rapport = VerificateurEnvironnement((dep,), executor=executor).verifier()
    (resultat,) = rapport.resultats
    assert resultat.presente is True
    assert resultat.version is not None
    assert "Python" in resultat.version
    # La version a peuplé le registre et l'exécution a été consignée.
    assert registre.version_de(sys.executable) == resultat.version
    contenu = (tmp_path / "custody.jsonl").read_text(encoding="utf-8")
    assert "commande_executee" in contenu
    assert "environnement_verifie" in contenu


def test_pre_vol_sans_executor_ne_capte_pas_de_version() -> None:
    dep = Dependance(
        nom="Python (sondé)",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.OPTIONNELLE,
        role="Test",
        installation="…",
        cible=sys.executable,
    )
    rapport = VerificateurEnvironnement((dep,)).verifier()
    (resultat,) = rapport.resultats
    assert resultat.presente is True
    assert resultat.version is None
    assert "pré-vol" in resultat.detail


def test_resume_est_lisible() -> None:
    rapport = verifier_environnement()
    texte = rapport.resume()
    assert "Vérification de l'environnement guardian" in texte
    assert "Python" in texte
    # Le rappel épistémique est toujours présent.
    assert "réduit le périmètre observable" in texte
