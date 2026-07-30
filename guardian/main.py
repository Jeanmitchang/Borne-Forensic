"""Point d'entrée applicatif de guardian (nom de travail).

À ce stade (Étape 0 — Bootstrap, cf. CLAUDE.md §10), le programme se contente de
démarrer et d'afficher sa bannière de version. Les modules de détection,
d'acquisition, d'analyse et l'interface graphique sont introduits par les étapes
suivantes de la feuille de route.
"""

from __future__ import annotations

from guardian import __version__


def banniere() -> str:
    """Retourne la bannière de démarrage : nom de travail suivi de la version."""
    return f"guardian v{__version__}"


def main() -> int:
    """Point d'entrée principal.

    Retourne un code de sortie POSIX (``0`` = succès). À ce stade, se limite à
    afficher la bannière ; deviendra le point d'assemblage du pipeline aux étapes
    ultérieures.
    """
    print(banniere())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
