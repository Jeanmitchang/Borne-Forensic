"""Lanceur racine de guardian.

Délègue au point d'entrée du paquet (``guardian.main.main``) afin de permettre
« python main.py » depuis la racine du dépôt, en complément de « python -m
guardian » et de l'entrée console ``guardian``. Voir CLAUDE.md §7 (main.py comme
point d'entrée).
"""

from __future__ import annotations

from guardian.main import main

if __name__ == "__main__":
    raise SystemExit(main())
