"""Analyse LEAPP — iLEAPP (iOS) / ALEAPP (Android) (CLAUDE.md §5, §10).

LEAPP **extrait et met en forme des artefacts** (historiques, comptes, usages…) à
partir d'une acquisition. Contrairement à MVT, il ne « détecte » pas de compromission :
il produit un rapport de **corroboration** (§5, signaux faibles). Les Findings sont
donc de gravité ``INFO`` — le rapport généré est la pièce ; son interprétation revient
à l'opérateur et au corrélateur (Étape 7).

Comme MVT, la logique est partagée entre les deux outils (:class:`_LEAPPRunnerBase`)
et paramétrée par de fines sous-classes (:class:`ILEAPPRunner`, :class:`ALEAPPRunner`).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from guardian.analysis.base import Analyzer, ResultatAnalyse
from guardian.core.exceptions import ValidationError
from guardian.core.provenance import (
    Confidence,
    Reproducibility,
    Severity,
    TracedExecutor,
)

# Types d'entrée acceptés par iLEAPP/ALEAPP (option -t).
_TYPES_ENTREE = frozenset({"fs", "tar", "zip", "gz"})


def _trouver_rapport(dossier: Path) -> Path | None:
    """Retourne le premier ``index.html`` produit par LEAPP, s'il existe."""
    if not dossier.is_dir():
        return None
    candidats = sorted(
        p for p in dossier.rglob("*") if p.is_file() and p.name.lower() == "index.html"
    )
    return candidats[0] if candidats else None


class _LEAPPRunnerBase(Analyzer):
    """Logique commune iLEAPP/ALEAPP ; paramétrée par les attributs de classe."""

    _OUTIL: ClassVar[str]
    _SOUS_DOSSIER: ClassVar[str]

    def __init__(
        self,
        executor: TracedExecutor,
        cible: Path | str,
        *,
        commande_leapp: Sequence[str],
        type_entree: str = "fs",
        dossier_sortie: Path | str | None = None,
        timeout: float = 1800.0,
    ) -> None:
        super().__init__(executor)
        self._cible = Path(cible)
        if not self._cible.exists():
            raise ValidationError(f"Cible d'analyse introuvable : {self._cible}")
        if type_entree not in _TYPES_ENTREE:
            raise ValidationError(
                f"Type d'entrée LEAPP invalide : {type_entree!r} "
                f"(attendu : {', '.join(sorted(_TYPES_ENTREE))})."
            )
        self._commande_leapp = tuple(commande_leapp)
        self._type_entree = type_entree
        self._dossier_sortie = (
            Path(dossier_sortie)
            if dossier_sortie is not None
            else executor.dossier / "analyse" / self._SOUS_DOSSIER
        )
        self._timeout = timeout

    @property
    def outil(self) -> str:
        return self._OUTIL

    def analyser(self) -> ResultatAnalyse:
        self._consigner_debut()
        self._dossier_sortie.mkdir(parents=True, exist_ok=True)
        args = [
            *self._commande_leapp,
            "-t",
            self._type_entree,
            "-i",
            str(self._cible),
            "-o",
            str(self._dossier_sortie),
        ]
        tracee = self._executor.executer(args, timeout=self._timeout)

        fichiers = [p for p in self._dossier_sortie.rglob("*") if p.is_file()]
        if tracee.trace.exit_code != 0 or not fichiers:
            finding = self._finding_echec(tracee, f"{self.outil} (-t {self._type_entree})")
            resultat = ResultatAnalyse(self.outil, (finding,), (), complete=False)
            self._consigner_fin(resultat)
            return resultat

        rapport = _trouver_rapport(self._dossier_sortie)
        ref_rapport = self._rel(rapport) if rapport is not None else None
        artefacts = (ref_rapport,) if ref_rapport is not None else ()
        emplacement = ref_rapport if ref_rapport is not None else "sans index.html"
        finding = tracee.en_finding(
            value=(
                f"{self.outil} : rapport d'artefacts généré ({emplacement}), "
                f"{len(fichiers)} fichier(s) — corroboration, à interpréter."
            ),
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
        resultat = ResultatAnalyse(self.outil, (finding,), artefacts, complete=True)
        self._consigner_fin(resultat)
        return resultat


class ALEAPPRunner(_LEAPPRunnerBase):
    """Analyse ALEAPP d'une acquisition Android (répertoire ``/sdcard``, archive…)."""

    _OUTIL = "aleapp"
    _SOUS_DOSSIER = "aleapp_android"

    def __init__(
        self,
        executor: TracedExecutor,
        cible: Path | str,
        *,
        commande_leapp: Sequence[str] = ("aleapp",),
        type_entree: str = "fs",
        dossier_sortie: Path | str | None = None,
        timeout: float = 1800.0,
    ) -> None:
        super().__init__(
            executor,
            cible,
            commande_leapp=commande_leapp,
            type_entree=type_entree,
            dossier_sortie=dossier_sortie,
            timeout=timeout,
        )


class ILEAPPRunner(_LEAPPRunnerBase):
    """Analyse iLEAPP d'une acquisition iOS (dossier de sauvegarde, archive…)."""

    _OUTIL = "ileapp"
    _SOUS_DOSSIER = "ileapp_ios"

    def __init__(
        self,
        executor: TracedExecutor,
        cible: Path | str,
        *,
        commande_leapp: Sequence[str] = ("ileapp",),
        type_entree: str = "fs",
        dossier_sortie: Path | str | None = None,
        timeout: float = 1800.0,
    ) -> None:
        super().__init__(
            executor,
            cible,
            commande_leapp=commande_leapp,
            type_entree=type_entree,
            dossier_sortie=dossier_sortie,
            timeout=timeout,
        )
