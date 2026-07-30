"""Tests du logging structuré JSONL (``guardian.core.logging_conf``)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from guardian.core.logging_conf import (
    FormateurJSONL,
    configurer_logging,
    obtenir_logger,
)


def _vider(logger: logging.Logger) -> None:
    """Force l'écriture des handlers vers le disque avant lecture."""
    for handler in logger.handlers:
        handler.flush()


def _lire_lignes(fichier: Path) -> list[str]:
    return fichier.read_text(encoding="utf-8").strip().splitlines()


def test_formateur_produit_json_avec_champs_attendus() -> None:
    """Le formateur émet un JSON valide horodaté UTC (suffixe Z)."""
    formateur = FormateurJSONL()
    record = logging.LogRecord(
        name="guardian.test",
        level=logging.INFO,
        pathname="custody.py",
        lineno=42,
        msg="bonjour %s",
        args=("monde",),
        exc_info=None,
        func="ma_fonction",
    )
    obj = json.loads(formateur.format(record))
    assert obj["message"] == "bonjour monde"
    assert obj["niveau"] == "INFO"
    assert obj["logger"] == "guardian.test"
    assert obj["ligne"] == 42
    assert obj["fonction"] == "ma_fonction"
    assert obj["horodatage_utc"].endswith("Z")


def test_logger_ecrit_jsonl_avec_extra(tmp_path: Path) -> None:
    """Un champ ``extra`` métier est sérialisé dans la ligne JSON."""
    fichier = tmp_path / "app.jsonl"
    logger = configurer_logging(nom="guardian.test_fichier", fichier=fichier, console=False)
    logger.info("démarrage", extra={"affaire": "2026-001"})
    _vider(logger)

    lignes = _lire_lignes(fichier)
    assert len(lignes) == 1
    obj = json.loads(lignes[0])
    assert obj["message"] == "démarrage"
    assert obj["affaire"] == "2026-001"
    assert obj["niveau"] == "INFO"
    assert obj["horodatage_utc"].endswith("Z")


def test_filtre_redige_les_champs_sensibles(tmp_path: Path) -> None:
    """Un champ ``extra`` au nom sensible est masqué ; le secret n'apparaît pas."""
    fichier = tmp_path / "app.jsonl"
    logger = configurer_logging(nom="guardian.test_redaction", fichier=fichier, console=False)
    logger.info(
        "sauvegarde iOS",
        extra={"backup_password": "hunter2", "device_id": "ABC123"},
    )
    _vider(logger)

    contenu = fichier.read_text(encoding="utf-8")
    obj = json.loads(contenu.strip())
    assert obj["backup_password"] == "***RÉDIGÉ***"
    assert obj["device_id"] == "ABC123"
    assert "hunter2" not in contenu


def test_niveau_filtre_les_messages(tmp_path: Path) -> None:
    """Un message sous le niveau configuré n'est pas journalisé."""
    fichier = tmp_path / "app.jsonl"
    logger = configurer_logging(
        nom="guardian.test_niveau",
        fichier=fichier,
        console=False,
        niveau=logging.WARNING,
    )
    logger.info("ignoré")
    logger.warning("gardé")
    _vider(logger)

    lignes = _lire_lignes(fichier)
    assert len(lignes) == 1
    assert json.loads(lignes[0])["message"] == "gardé"


def test_exception_est_capturee(tmp_path: Path) -> None:
    """``logger.exception`` inclut le type et la trace de l'exception."""
    fichier = tmp_path / "app.jsonl"
    logger = configurer_logging(nom="guardian.test_exc", fichier=fichier, console=False)
    try:
        raise ValueError("boum")
    except ValueError:
        logger.exception("échec du traitement")
    _vider(logger)

    obj = json.loads(_lire_lignes(fichier)[0])
    assert "exception" in obj
    assert "ValueError" in obj["exception"]


def test_configuration_est_idempotente(tmp_path: Path) -> None:
    """Reconfigurer le même logger ne cumule pas les handlers."""
    fichier = tmp_path / "app.jsonl"
    logger = configurer_logging(nom="guardian.test_idem", fichier=fichier, console=False)
    nb_handlers = len(logger.handlers)
    logger = configurer_logging(nom="guardian.test_idem", fichier=fichier, console=False)
    assert len(logger.handlers) == nb_handlers

    logger.info("unique")
    _vider(logger)
    assert len(_lire_lignes(fichier)) == 1


def test_obtenir_logger_prefixe_l_espace_de_noms() -> None:
    """Les loggers sont rattachés à l'espace de noms ``guardian``."""
    assert obtenir_logger("core.custody").name == "guardian.core.custody"
    assert obtenir_logger("guardian.deja_prefixe").name == "guardian.deja_prefixe"
    assert obtenir_logger("guardian").name == "guardian"
