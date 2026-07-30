"""Tests de la hiérarchie d'exceptions métier (``guardian.core.exceptions``)."""

from __future__ import annotations

import pytest

from guardian.core.exceptions import (
    AcquisitionError,
    AnalysisError,
    CustodyError,
    EnvironmentCheckError,
    GuardianError,
    ProvenanceError,
    ValidationError,
)

_SOUS_CLASSES = (
    EnvironmentCheckError,
    CustodyError,
    ProvenanceError,
    ValidationError,
    AcquisitionError,
    AnalysisError,
)


def test_racine_derive_d_exception() -> None:
    """La racine métier reste une Exception standard."""
    assert issubclass(GuardianError, Exception)


@pytest.mark.parametrize("exc", _SOUS_CLASSES)
def test_sous_classes_derivent_de_la_racine(exc: type[GuardianError]) -> None:
    """Toutes les erreurs métier se rattrapent via ``GuardianError``."""
    assert issubclass(exc, GuardianError)


@pytest.mark.parametrize("exc", _SOUS_CLASSES)
def test_capture_par_la_racine(exc: type[GuardianError]) -> None:
    """Une sous-classe levée est bien capturée par ``GuardianError``."""
    with pytest.raises(GuardianError):
        raise exc("erreur de test")


def test_message_preserve() -> None:
    """Le message passé au constructeur est conservé."""
    err = AcquisitionError("échec de l'acquisition adb")
    assert str(err) == "échec de l'acquisition adb"


def test_environmentcheckerror_ne_masque_pas_le_builtin() -> None:
    """Décision de conception : distinct du builtin ``EnvironmentError`` (OSError)."""
    assert not issubclass(EnvironmentCheckError, OSError)
