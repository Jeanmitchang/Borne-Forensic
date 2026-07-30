"""guardian (nom de travail) — station d'analyse forensic 100 % hors-ligne.

Paquet racine du projet. Cette variable ``__version__`` est la **source de vérité
unique** de la version : elle est consommée à la fois par ``pyproject.toml`` (au
moment du build, via ``[tool.setuptools.dynamic]``) et par la bannière de démarrage
(``guardian.main.banniere``). Ne pas dupliquer le numéro de version ailleurs.
"""

from __future__ import annotations

__version__ = "0.0.0"
