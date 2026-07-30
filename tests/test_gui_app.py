"""Tests de fumée de la GUI (``guardian.gui.app``) — sous-lot 9.2.

Ignorés si PyQt6 n'est pas installé (dépendance optionnelle). S'exécutent en mode
« offscreen » pour ne nécessiter aucun serveur d'affichage.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("PyQt6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from guardian.gui.app import FenetrePrincipale, Travailleur  # noqa: E402


@pytest.fixture(scope="module")
def app() -> Iterator[QApplication]:
    application = QApplication.instance() or QApplication([])
    assert isinstance(application, QApplication)
    yield application


def test_fenetre_se_construit(app: QApplication) -> None:
    fenetre = FenetrePrincipale()
    assert fenetre.windowTitle().startswith("guardian")
    # Avant ouverture d'affaire, détection/pipeline/rapport sont désactivés.
    assert fenetre._bouton_detecter.isEnabled() is False
    assert fenetre._bouton_pipeline.isEnabled() is False
    assert fenetre._bouton_rapport.isEnabled() is False


def test_ouvrir_affaire_depuis_le_formulaire(app: QApplication, tmp_path: Path) -> None:
    fenetre = FenetrePrincipale()
    fenetre._champ_dossier.setText(str(tmp_path / "affaire"))
    fenetre._champ_identifiant.setText("2026-001")
    fenetre._champ_operateur.setText("expert.forensic")
    fenetre._champ_proprietaire.setText("Victime référencée V1")
    fenetre._champ_description.setText("Pixel 6")
    fenetre._champ_portee.setText("Acquisition logique sans root")

    fenetre._ouvrir_affaire()

    assert fenetre.affaire is not None
    assert (tmp_path / "affaire" / "consent.json").is_file()
    # L'ouverture active les phases suivantes.
    assert fenetre._bouton_detecter.isEnabled() is True
    assert fenetre._bouton_pipeline.isEnabled() is True


def test_ouvrir_affaire_consentement_incomplet_est_signale(
    app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Neutraliser la boîte de dialogue modale pour le test.
    from guardian.gui import app as module_app

    monkeypatch.setattr(module_app.QMessageBox, "critical", lambda *a, **k: None)

    fenetre = FenetrePrincipale()
    fenetre._champ_dossier.setText(str(tmp_path / "aff"))
    fenetre._champ_identifiant.setText("2026-001")
    # Opérateur manquant → Consentement invalide.
    fenetre._ouvrir_affaire()
    assert fenetre.affaire is None


def test_travailleur_remonte_le_resultat(app: QApplication) -> None:
    resultats: list[object] = []
    travailleur = Travailleur(lambda log: "ok")
    travailleur.termine.connect(resultats.append)
    travailleur.run()  # exécution synchrone pour le test
    assert resultats == ["ok"]


def test_travailleur_remonte_l_erreur(app: QApplication) -> None:
    erreurs: list[str] = []

    def tache(log: object) -> object:
        raise RuntimeError("boum")

    travailleur = Travailleur(tache)
    travailleur.echoue.connect(erreurs.append)
    travailleur.run()
    assert erreurs and "boum" in erreurs[0]
