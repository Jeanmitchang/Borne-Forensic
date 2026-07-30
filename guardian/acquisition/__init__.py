"""Acquisition des supports (Étapes 3-4).

Acquisition logique Android sans root (``adb bugreport`` + ``dumpsys`` + pull
ciblé + APK suspects) et sauvegarde iOS chiffrée (``idevicebackup2``). Règle
absolue : lecture seule sur le support source, tout passe par ``TracedExecutor``.
"""
