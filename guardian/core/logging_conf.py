"""Configuration du logging structuré de guardian.

Produit des journaux **applicatifs** au format JSONL (une ligne = un objet JSON),
horodatés en UTC, avec rotation de fichier. Ces journaux tracent le *comportement
du logiciel* ; ils sont distincts du **journal de custody** append-only
(``core.custody``), qui trace la chaîne probatoire et obéit à des règles propres.

Garde-fous appliqués (CLAUDE.md §2, SECURITY.md §3.2) :

- **Aucun secret en clair.** ``FiltreRedaction`` masque la valeur des champs
  ``extra`` au nom sensible (défense en profondeur). Cela ne dispense PAS
  l'appelant : ne jamais passer de secret (mot de passe de sauvegarde, etc.) au
  logger, ni dans le message, ni dans les champs.
- **100 % hors-ligne.** Aucun handler réseau n'est configuré, jamais.
- **Zéro ``print`` en production** : tout passe par un logger obtenu ici.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Final

# Attributs standard d'un ``LogRecord``. Tout attribut hors de cet ensemble est
# considéré comme un champ « extra » métier et sérialisé dans la ligne JSON.
_ATTRS_STANDARD: Final[frozenset[str]] = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
    }
)

# Sous-chaînes (insensibles à la casse) marquant un champ ``extra`` comme sensible.
MOTS_SENSIBLES: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "motdepasse",
    "mot_de_passe",
    "mdp",
    "passphrase",
    "secret",
    "token",
    "credential",
)

_MASQUE: Final[str] = "***RÉDIGÉ***"


class FiltreRedaction(logging.Filter):
    """Masque la valeur des champs ``extra`` dont le nom paraît sensible.

    Défense en profondeur : réduit le risque qu'un secret passé par mégarde dans
    un champ ``extra`` n'atterrisse en clair dans le journal. Ne masque pas un
    secret noyé dans le texte libre du message — l'appelant reste responsable.
    """

    def __init__(self, mots_sensibles: tuple[str, ...] = MOTS_SENSIBLES) -> None:
        super().__init__()
        self._mots: tuple[str, ...] = tuple(m.lower() for m in mots_sensibles)

    def _est_sensible(self, cle: str) -> bool:
        cle_min = cle.lower()
        return any(mot in cle_min for mot in self._mots)

    def filter(self, record: logging.LogRecord) -> bool:
        for cle in list(record.__dict__.keys()):
            if cle not in _ATTRS_STANDARD and self._est_sensible(cle):
                setattr(record, cle, _MASQUE)
        return True


class FormateurJSONL(logging.Formatter):
    """Formate chaque enregistrement en une ligne JSON (JSONL), horodatée UTC."""

    def format(self, record: logging.LogRecord) -> str:
        horodatage = (
            datetime.fromtimestamp(record.created, tz=UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        charge: dict[str, Any] = {
            "horodatage_utc": horodatage,
            "niveau": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "fonction": record.funcName,
            "ligne": record.lineno,
        }
        # Champs métier supplémentaires (extra), hors attributs standard.
        for cle, valeur in record.__dict__.items():
            if cle not in _ATTRS_STANDARD and cle not in charge:
                charge[cle] = valeur
        if record.exc_info:
            charge["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            charge["pile"] = self.formatStack(record.stack_info)
        # default=str : ne jamais faire échouer la journalisation sur un type non
        # sérialisable ; ensure_ascii=False : préserver les accents français.
        return json.dumps(charge, ensure_ascii=False, default=str)


def configurer_logging(
    *,
    nom: str = "guardian",
    niveau: int = logging.INFO,
    fichier: Path | str | None = None,
    console: bool = True,
    taille_max_octets: int = 5 * 1024 * 1024,
    nb_sauvegardes: int = 5,
    rediger_secrets: bool = True,
) -> logging.Logger:
    """Configure et retourne le logger nommé ``nom``.

    Idempotent : un appel répété repart de handlers propres (pas d'accumulation
    ni de doublons de lignes). Le logger ne propage pas vers la racine afin de
    garantir que **seuls** les handlers configurés ici reçoivent les messages.

    :param nom: nom du logger (par convention, ``guardian`` ou ``guardian.<...>``).
    :param niveau: niveau minimal journalisé (``logging.INFO`` par défaut).
    :param fichier: chemin du journal JSONL ; ``None`` = pas de fichier. Le
        dossier parent est créé au besoin.
    :param console: si vrai, ajoute un handler vers ``stderr`` (stdout reste libre
        pour la sortie applicative).
    :param taille_max_octets: seuil de rotation du fichier.
    :param nb_sauvegardes: nombre de fichiers de rotation conservés.
    :param rediger_secrets: active ``FiltreRedaction`` sur tous les handlers.
    """
    logger = logging.getLogger(nom)
    logger.setLevel(niveau)
    logger.propagate = False

    # Idempotence : fermer et retirer les handlers existants avant reconfiguration.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formateur = FormateurJSONL()
    filtre = FiltreRedaction() if rediger_secrets else None

    if console:
        handler_console: logging.Handler = logging.StreamHandler()
        handler_console.setFormatter(formateur)
        if filtre is not None:
            handler_console.addFilter(filtre)
        logger.addHandler(handler_console)

    if fichier is not None:
        chemin = Path(fichier)
        chemin.parent.mkdir(parents=True, exist_ok=True)
        handler_fichier = RotatingFileHandler(
            chemin,
            maxBytes=taille_max_octets,
            backupCount=nb_sauvegardes,
            encoding="utf-8",
        )
        handler_fichier.setFormatter(formateur)
        if filtre is not None:
            handler_fichier.addFilter(filtre)
        logger.addHandler(handler_fichier)

    return logger


def obtenir_logger(nom: str) -> logging.Logger:
    """Retourne un logger rattaché à l'espace de noms applicatif ``guardian``.

    ``obtenir_logger("core.custody")`` → logger ``guardian.core.custody``. Un nom
    déjà préfixé par ``guardian`` est renvoyé tel quel.
    """
    if nom == "guardian" or nom.startswith("guardian."):
        return logging.getLogger(nom)
    return logging.getLogger(f"guardian.{nom}")
