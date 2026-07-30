"""Rend le paquet exécutable via « python -m guardian ».

Délègue au point d'entrée ``guardian.main.main``. Voir aussi le lanceur racine
``main.py`` (« python main.py ») et l'entrée console ``guardian`` déclarée dans
``pyproject.toml``.
"""

from __future__ import annotations

from guardian.main import main

if __name__ == "__main__":
    raise SystemExit(main())
