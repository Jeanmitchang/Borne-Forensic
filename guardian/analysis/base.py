"""Interface commune des analyseurs (MVT, LEAPP, Autopsy).

Un *analyseur* examine une acquisition (bugreport, sauvegarde…) et produit des
:class:`~guardian.core.provenance.Finding`. Comme pour l'acquisition, **toute
commande passe par le** :class:`~guardian.core.provenance.TracedExecutor`.

Ce module établit le contrat (:class:`Analyzer`, :class:`ResultatAnalyse`). Les
implémentations concrètes (``mvt_runner``, ``leapp_runner``, ``autopsy_runner``)
suivent aux étapes 5 à 7 et 10.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from guardian.core.logging_conf import obtenir_logger
from guardian.core.provenance import (
    Confidence,
    ExecutionTracee,
    Finding,
    Reproducibility,
    Severity,
    TracedExecutor,
)


@dataclass(frozen=True)
class ResultatAnalyse:
    """Résultat d'une analyse : findings tracés + artefacts produits.

    ``complete`` distingue une analyse menée à son terme d'une analyse interrompue
    ou non concluante (échouer bruyamment plutôt que dégrader en silence).
    """

    outil: str
    findings: tuple[Finding, ...]
    artefacts: tuple[str, ...]
    complete: bool

    def resume(self) -> str:
        """Synthèse lisible par l'opérateur."""
        etat = "complète" if self.complete else "NON CONCLUANTE"
        return (
            f"Analyse {etat} — {self.outil} : {len(self.findings)} finding(s), "
            f"{len(self.artefacts)} artefact(s)."
        )


class Analyzer(ABC):
    """Contrat commun d'un analyseur. Toute commande passe par ``self._executor``."""

    def __init__(self, executor: TracedExecutor) -> None:
        self._executor = executor
        self._logger = obtenir_logger("analysis")

    @property
    @abstractmethod
    def outil(self) -> str:
        """Nom de l'outil d'analyse (ex. ``"mvt-android"``)."""

    @abstractmethod
    def analyser(self) -> ResultatAnalyse:
        """Réalise l'analyse et retourne son résultat tracé."""

    # --- Bornage custody ---------------------------------------------------
    def _consigner_debut(self) -> None:
        self._executor.journal.consigner("analyse_demarree", {"outil": self.outil})
        self._logger.info("analyse démarrée", extra={"outil": self.outil})

    def _consigner_fin(self, resultat: ResultatAnalyse) -> None:
        self._executor.journal.consigner(
            "analyse_terminee",
            {
                "outil": self.outil,
                "complete": resultat.complete,
                "nb_findings": len(resultat.findings),
                "nb_artefacts": len(resultat.artefacts),
            },
        )
        self._logger.info(
            "analyse terminée",
            extra={"outil": self.outil, "complete": resultat.complete},
        )

    # --- Helpers communs ---------------------------------------------------
    def _rel(self, chemin: Path) -> str:
        """Chemin relatif POSIX d'un artefact, à la racine du dossier d'affaire."""
        return chemin.relative_to(self._executor.dossier).as_posix()

    def _finding_echec(self, tracee: ExecutionTracee, operation: str) -> Finding:
        """Finding pour une opération en échec : confiance faible, sortie brute conservée."""
        return tracee.en_finding(
            value=(
                f"Opération « {operation} » en échec (code {tracee.trace.exit_code}) — "
                "voir la sortie brute ; résultat non concluant."
            ),
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
