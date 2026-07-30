"""Socle du projet (Étape 1 — priorité absolue).

Regroupera : hiérarchie d'exceptions métier (``exceptions``), logging structuré
(``logging_conf``), chaîne de custody et hachage (``custody``), provenance et
porte unique d'exécution ``TracedExecutor`` (``provenance``), et vérification de
l'environnement (``environment``). Aucun module externe n'exécute de commande
hors de ``TracedExecutor`` (cf. CLAUDE.md §6).
"""
