"""Tests de fumée de l'Étape 0 — Bootstrap.

Vérifient que le paquet ``guardian`` s'importe, expose une version cohérente et
démarre sans effet de bord. Aucune donnée réelle : ces tests n'ont pas de fixture
externe (cf. CONTRIBUTING §6, fixtures synthétiques uniquement).
"""

from __future__ import annotations

import re

import pytest

import guardian
from guardian.main import banniere, main


def test_version_est_une_chaine_semver() -> None:
    """La version doit exister et suivre le schéma MAJEUR.MINEUR.CORRECTIF."""
    assert isinstance(guardian.__version__, str)
    assert re.fullmatch(r"\d+\.\d+\.\d+", guardian.__version__), guardian.__version__


def test_banniere_contient_nom_et_version() -> None:
    """La bannière affiche le nom de travail et la version courante."""
    assert banniere() == f"guardian v{guardian.__version__}"
    assert banniere().startswith("guardian v")


def test_main_imprime_banniere_et_retourne_succes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """main() imprime la bannière et retourne le code de succès POSIX (0)."""
    code = main()
    sortie = capsys.readouterr().out
    assert code == 0
    assert banniere() in sortie
