"""Tests de la chaîne de custody (``guardian.core.custody``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardian.core.custody import (
    Consentement,
    JournalCustody,
    enregistrer_consentement,
    generer_manifeste,
    hacher_donnees,
    hacher_fichier,
    horodatage_utc,
    verifier_manifeste,
)
from guardian.core.exceptions import CustodyError, ValidationError

# Vecteurs SHA-256 de référence (connus).
_SHA_VIDE = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_SHA_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# --- Hachage ---------------------------------------------------------------
def test_hacher_donnees_vecteurs_connus() -> None:
    assert hacher_donnees(b"") == _SHA_VIDE
    assert hacher_donnees(b"abc") == _SHA_ABC


def test_hacher_fichier(tmp_path: Path) -> None:
    fichier = tmp_path / "donnee.bin"
    fichier.write_bytes(b"abc")
    assert hacher_fichier(fichier) == _SHA_ABC


def test_hacher_fichier_absent_leve_validation(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        hacher_fichier(tmp_path / "inexistant.bin")


def test_horodatage_est_utc_iso() -> None:
    horo = horodatage_utc()
    assert horo.endswith("Z")
    assert "T" in horo


# --- Journal de custody ----------------------------------------------------
def test_journal_exige_un_operateur(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        JournalCustody(tmp_path / "custody.jsonl", operateur="  ")


def test_journal_consigne_et_chaine(tmp_path: Path) -> None:
    chemin = tmp_path / "custody.jsonl"
    journal = JournalCustody(chemin, operateur="expert.forensic")
    e0 = journal.consigner("ouverture_affaire", {"affaire": "2026-001"})
    e1 = journal.consigner("acquisition_demarree")

    assert e0["index"] == 0
    assert e1["index"] == 1
    # La 2e entrée scelle la 1re.
    assert e1["hash_precedent"] == e0["hash_entree"]
    # Intégrité vérifiée sans exception.
    journal.verifier_integrite()

    lignes = chemin.read_text(encoding="utf-8").strip().splitlines()
    assert len(lignes) == 2
    assert json.loads(lignes[0])["operateur"] == "expert.forensic"


def test_journal_reprend_la_chaine_apres_reouverture(tmp_path: Path) -> None:
    chemin = tmp_path / "custody.jsonl"
    JournalCustody(chemin, operateur="op").consigner("evt_a")
    # Nouvelle instance sur le même fichier : la chaîne doit se poursuivre.
    journal2 = JournalCustody(chemin, operateur="op")
    e = journal2.consigner("evt_b")
    assert e["index"] == 1
    journal2.verifier_integrite()


def test_journal_detecte_une_alteration(tmp_path: Path) -> None:
    chemin = tmp_path / "custody.jsonl"
    journal = JournalCustody(chemin, operateur="op")
    journal.consigner("evt_a", {"valeur": "origine"})
    journal.consigner("evt_b")

    # Falsification : on modifie le contenu de la 1re entrée sans recalculer le hash.
    lignes = chemin.read_text(encoding="utf-8").splitlines()
    entree = json.loads(lignes[0])
    entree["details"] = {"valeur": "falsifiee"}
    lignes[0] = json.dumps(entree, ensure_ascii=False)
    chemin.write_text("\n".join(lignes) + "\n", encoding="utf-8")

    with pytest.raises(CustodyError):
        JournalCustody(chemin, operateur="op").verifier_integrite()


# --- Consentement ----------------------------------------------------------
def _consentement_valide() -> Consentement:
    return Consentement(
        identifiant_affaire="2026-001",
        proprietaire_support="Victime référencée V1",
        operateur="expert.forensic",
        description_support="Pixel 6, Android 14",
        portee="Acquisition logique sans root + analyse MVT",
    )


def test_consentement_champ_manquant_leve_validation() -> None:
    with pytest.raises(ValidationError):
        Consentement(
            identifiant_affaire="2026-001",
            proprietaire_support="",  # manquant
            operateur="op",
            description_support="desc",
            portee="portée",
        )


def test_enregistrer_consentement_ecrit_et_hache(tmp_path: Path) -> None:
    chemin = tmp_path / "consent.json"
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="op")
    empreinte = enregistrer_consentement(chemin, _consentement_valide(), journal)

    assert chemin.is_file()
    assert empreinte == hacher_fichier(chemin)
    donnees = json.loads(chemin.read_text(encoding="utf-8"))
    assert donnees["identifiant_affaire"] == "2026-001"
    # L'événement est consigné dans la custody, sans recopier le propriétaire.
    entrees = [
        json.loads(ligne)
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    evt = entrees[0]
    assert evt["evenement"] == "consentement_enregistre"
    assert evt["details"]["sha256"] == empreinte
    assert "proprietaire_support" not in evt["details"]


# --- Manifeste -------------------------------------------------------------
def test_generer_et_verifier_manifeste(tmp_path: Path) -> None:
    (tmp_path / "sous").mkdir()
    (tmp_path / "a.txt").write_text("alpha", encoding="utf-8")
    (tmp_path / "sous" / "b.txt").write_text("bravo", encoding="utf-8")

    manifeste = generer_manifeste(tmp_path)
    assert manifeste.name == "MANIFEST.sha256"

    contenu = manifeste.read_text(encoding="utf-8")
    # Format sha256sum : 64 hexa, deux espaces, chemin POSIX ; manifeste exclu.
    assert "  a.txt" in contenu
    assert "  sous/b.txt" in contenu
    assert "MANIFEST.sha256" not in contenu

    assert verifier_manifeste(tmp_path) == []


def test_verifier_manifeste_detecte_modification(tmp_path: Path) -> None:
    fichier = tmp_path / "a.txt"
    fichier.write_text("alpha", encoding="utf-8")
    generer_manifeste(tmp_path)

    fichier.write_text("alpha-modifié", encoding="utf-8")
    anomalies = verifier_manifeste(tmp_path)
    assert any("a.txt" in a for a in anomalies)


def test_verifier_manifeste_detecte_fichier_manquant(tmp_path: Path) -> None:
    fichier = tmp_path / "a.txt"
    fichier.write_text("alpha", encoding="utf-8")
    generer_manifeste(tmp_path)

    fichier.unlink()
    anomalies = verifier_manifeste(tmp_path)
    assert any("manquant" in a.lower() for a in anomalies)
