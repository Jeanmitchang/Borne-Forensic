"""Interface commune des acquéreurs (Android logique, sauvegarde iOS).

Un *acquéreur* extrait des données d'un appareil vers le dossier d'affaire, **en
lecture seule sur le support source** (garde-fou non négociable, CLAUDE.md §2). Il
ne réalise aucune écriture, installation ni modification de réglage sur le téléphone
analysé. Toute commande passe par le :class:`~guardian.core.provenance.TracedExecutor`.

Ce module ne fait qu'établir le **contrat** (classe abstraite :class:`Acquirer` et
type de résultat :class:`ResultatAcquisition`) ; les implémentations concrètes
(``android_logical``, ``ios_backup``) suivent aux étapes 3 et 4.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from guardian.core.exceptions import ValidationError
from guardian.core.logging_conf import obtenir_logger
from guardian.core.provenance import (
    Confidence,
    ExecutionTracee,
    Finding,
    Reproducibility,
    Severity,
    TracedExecutor,
)
from guardian.detection.usb_watch import TypeAppareil

# Un identifiant d'appareil (série adb / UDID iOS) est composé de caractères sûrs.
# On le valide avant tout emploi : ne jamais faire confiance aveuglément à une entrée.
_MOTIF_IDENTIFIANT = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def valider_identifiant_appareil(identifiant: str) -> str:
    """Valide et retourne un identifiant d'appareil (série/UDID).

    :raises ValidationError: si l'identifiant est vide ou contient des caractères
        inattendus (défense contre une entrée non maîtrisée).
    """
    if not _MOTIF_IDENTIFIANT.match(identifiant):
        raise ValidationError(
            f"Identifiant d'appareil invalide : {identifiant!r} "
            "(attendu : lettres, chiffres, « . _ : - », 1 à 128 caractères)."
        )
    return identifiant


@dataclass(frozen=True)
class ResultatAcquisition:
    """Résultat d'une acquisition : findings tracés + artefacts produits.

    ``complete`` distingue une acquisition menée à son terme d'une acquisition
    interrompue ou partielle (échouer bruyamment plutôt que dégrader en silence).
    """

    plateforme: TypeAppareil
    identifiant_appareil: str
    findings: tuple[Finding, ...]
    artefacts: tuple[str, ...]
    complete: bool

    def resume(self) -> str:
        """Synthèse lisible par l'opérateur."""
        etat = "complète" if self.complete else "PARTIELLE"
        return (
            f"Acquisition {etat} — {self.plateforme.value} {self.identifiant_appareil} : "
            f"{len(self.findings)} finding(s), {len(self.artefacts)} artefact(s)."
        )


class Acquirer(ABC):
    """Contrat commun d'un acquéreur, **en lecture seule sur le support source**.

    Les sous-classes implémentent :meth:`acquerir`. Elles doivent :
    - n'exécuter **aucune** écriture sur l'appareil ;
    - faire passer **toute** commande externe par ``self._executor`` ;
    - encadrer leur travail par :meth:`_consigner_debut` / :meth:`_consigner_fin`.
    """

    def __init__(self, executor: TracedExecutor, identifiant_appareil: str) -> None:
        self._executor = executor
        self._identifiant = valider_identifiant_appareil(identifiant_appareil)
        self._logger = obtenir_logger("acquisition")

    @property
    @abstractmethod
    def plateforme(self) -> TypeAppareil:
        """Plateforme prise en charge par cet acquéreur."""

    @property
    def identifiant(self) -> str:
        """Identifiant (série/UDID) de l'appareil ciblé."""
        return self._identifiant

    @abstractmethod
    def acquerir(self) -> ResultatAcquisition:
        """Réalise l'acquisition et retourne son résultat tracé."""

    def _consigner_debut(self) -> None:
        """Consigne le début d'acquisition dans la custody."""
        self._executor.journal.consigner(
            "acquisition_demarree",
            {"plateforme": self.plateforme.value, "identifiant": self._identifiant},
        )
        self._logger.info(
            "acquisition démarrée",
            extra={"plateforme": self.plateforme.value, "identifiant": self._identifiant},
        )

    def _consigner_fin(self, resultat: ResultatAcquisition) -> None:
        """Consigne la fin d'acquisition (état + décomptes) dans la custody."""
        self._executor.journal.consigner(
            "acquisition_terminee",
            {
                "plateforme": self.plateforme.value,
                "identifiant": self._identifiant,
                "complete": resultat.complete,
                "nb_findings": len(resultat.findings),
                "nb_artefacts": len(resultat.artefacts),
            },
        )
        self._logger.info(
            "acquisition terminée",
            extra={"complete": resultat.complete, "nb_findings": len(resultat.findings)},
        )

    # --- Helpers communs aux acquéreurs ------------------------------------
    def _rel(self, chemin: Path) -> str:
        """Chemin relatif POSIX d'un artefact, à la racine du dossier d'affaire."""
        return chemin.relative_to(self._executor.dossier).as_posix()

    def _finding_echec(self, tracee: ExecutionTracee, releve: str) -> Finding:
        """Finding pour une opération en échec : confiance faible, sortie brute conservée.

        On documente l'échec (jamais masqué, §5) plutôt que d'abandonner : la sortie
        brute reste archivée pour analyse.
        """
        return tracee.en_finding(
            value=(
                f"Opération « {releve} » en échec (code {tracee.trace.exit_code}) — "
                "voir la sortie brute ; résultat non concluant."
            ),
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
