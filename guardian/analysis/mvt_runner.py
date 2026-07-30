"""Analyse MVT (Mobile Verification Toolkit) — iOS et Android (CLAUDE.md §5, §10).

MVT compare une acquisition à des indicateurs de compromission (IOC) et à ses
détections intégrées, et signale les correspondances (stalkerware connu, etc.).

Base IOC — **« prévoir les deux »** (100 % hors-ligne, §2) :

- Si l'opérateur fournit un chemin d'IOC (``dossier_ioc``), il est passé à MVT via
  ``--iocs`` et son **empreinte** (version) est consignée dans la custody. Aucune
  récupération réseau : la base est fournie en amont, hors de l'outil.
- Sinon, MVT tourne avec ses **détections intégrées** (dont la version est celle de
  MVT, captée dans la provenance) — couverture moindre, signalée honnêtement.

La version de la base employée est donc toujours consignée (empreinte IOC fournie,
ou version de MVT via la trace de commande).
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

from guardian.analysis.base import Analyzer, ResultatAnalyse
from guardian.core.custody import hacher_donnees, hacher_fichier
from guardian.core.exceptions import ValidationError
from guardian.core.provenance import (
    Confidence,
    Reproducibility,
    Severity,
    TracedExecutor,
)

# MVT nomme les fichiers de détection « <module>_detected.json ».
_SUFFIXE_DETECTION = "_detected.json"


# ---------------------------------------------------------------------------
#  Helpers purs
# ---------------------------------------------------------------------------
def _fichiers_detection(dossier: Path) -> list[Path]:
    """Retourne les fichiers de détection MVT (« *_detected.json ») du dossier."""
    if not dossier.is_dir():
        return []
    return sorted(
        p for p in dossier.rglob("*") if p.is_file() and p.name.endswith(_SUFFIXE_DETECTION)
    )


def _empreinte_base_ioc(chemin: Path) -> str:
    """Empreinte (version) stable d'une base IOC : fichier haché, ou dossier agrégé.

    Pour un dossier : SHA-256 de la liste triée « chemin_relatif:sha256 » de chaque
    fichier — déterministe, indépendante de l'ordre de parcours.
    """
    if chemin.is_file():
        return hacher_fichier(chemin)
    lignes = [
        f"{f.relative_to(chemin).as_posix()}:{hacher_fichier(f)}"
        for f in sorted(p for p in chemin.rglob("*") if p.is_file())
    ]
    return hacher_donnees("\n".join(lignes).encode("utf-8"))


# ---------------------------------------------------------------------------
#  Base MVT (logique partagée iOS/Android)
# ---------------------------------------------------------------------------
class _MVTRunnerBase(Analyzer):
    """Logique commune d'un runner MVT ; paramétrée par les attributs de classe."""

    _OUTIL: ClassVar[str]
    _SOUS_COMMANDE: ClassVar[str]
    _SOUS_DOSSIER: ClassVar[str]

    def __init__(
        self,
        executor: TracedExecutor,
        cible: Path | str,
        *,
        commande_mvt: Sequence[str],
        dossier_ioc: Path | str | None = None,
        dossier_sortie: Path | str | None = None,
        timeout: float = 900.0,
    ) -> None:
        super().__init__(executor)
        self._cible = Path(cible)
        if not self._cible.exists():
            raise ValidationError(f"Cible d'analyse introuvable : {self._cible}")
        self._commande_mvt = tuple(commande_mvt)
        self._dossier_ioc: Path | None = None
        if dossier_ioc is not None:
            self._dossier_ioc = Path(dossier_ioc)
            if not self._dossier_ioc.exists():
                raise ValidationError(f"Base IOC introuvable : {self._dossier_ioc}")
        self._dossier_sortie = (
            Path(dossier_sortie)
            if dossier_sortie is not None
            else executor.dossier / "analyse" / self._SOUS_DOSSIER
        )
        self._timeout = timeout

    @property
    def outil(self) -> str:
        return self._OUTIL

    def _consigner_base_ioc(self) -> str:
        """Consigne l'empreinte (version) de la base IOC fournie et la retourne."""
        assert self._dossier_ioc is not None
        empreinte = _empreinte_base_ioc(self._dossier_ioc)
        self._executor.journal.consigner(
            "base_ioc",
            {"chemin": str(self._dossier_ioc), "empreinte_sha256": empreinte},
        )
        return empreinte

    def analyser(self) -> ResultatAnalyse:
        self._consigner_debut()
        self._dossier_sortie.mkdir(parents=True, exist_ok=True)

        args = [
            *self._commande_mvt,
            self._SOUS_COMMANDE,
            "--output",
            str(self._dossier_sortie),
        ]
        empreinte_ioc: str | None = None
        if self._dossier_ioc is not None:
            empreinte_ioc = self._consigner_base_ioc()
            args += ["--iocs", str(self._dossier_ioc)]
        args.append(str(self._cible))

        tracee = self._executor.executer(args, timeout=self._timeout)
        if tracee.trace.exit_code != 0:
            finding = self._finding_echec(tracee, f"{self.outil} {self._SOUS_COMMANDE}")
            resultat = ResultatAnalyse(self.outil, (finding,), (), complete=False)
            self._consigner_fin(resultat)
            return resultat

        fichiers = _fichiers_detection(self._dossier_sortie)
        modules = [f.name[: -len(_SUFFIXE_DETECTION)] for f in fichiers]
        artefacts = tuple(self._rel(f) for f in fichiers)
        contexte = (
            f"base IOC {empreinte_ioc[:16]}…"
            if empreinte_ioc is not None
            else "détections MVT intégrées"
        )
        if modules:
            value = (
                f"{self.outil} : {len(modules)} détection(s) IOC "
                f"({', '.join(modules)}) — {contexte}."
            )
            severity = Severity.STRONG
        else:
            value = f"{self.outil} : aucun IOC détecté parmi la base employée ({contexte})."
            severity = Severity.INFO
        finding = tracee.en_finding(
            value=value,
            severity=severity,
            confidence=Confidence.HIGH,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
        resultat = ResultatAnalyse(self.outil, (finding,), artefacts, complete=True)
        self._consigner_fin(resultat)
        return resultat


# ---------------------------------------------------------------------------
#  Runner Android
# ---------------------------------------------------------------------------
class MVTAndroidRunner(_MVTRunnerBase):
    """Analyse MVT d'un bugreport Android (``mvt-android check-bugreport``)."""

    _OUTIL = "mvt-android"
    _SOUS_COMMANDE = "check-bugreport"
    _SOUS_DOSSIER = "mvt_android"

    def __init__(
        self,
        executor: TracedExecutor,
        cible_bugreport: Path | str,
        *,
        commande_mvt: Sequence[str] = ("mvt-android",),
        dossier_ioc: Path | str | None = None,
        dossier_sortie: Path | str | None = None,
        timeout: float = 900.0,
    ) -> None:
        super().__init__(
            executor,
            cible_bugreport,
            commande_mvt=commande_mvt,
            dossier_ioc=dossier_ioc,
            dossier_sortie=dossier_sortie,
            timeout=timeout,
        )


# ---------------------------------------------------------------------------
#  Runner iOS
# ---------------------------------------------------------------------------
class MVTIOSRunner(_MVTRunnerBase):
    """Analyse MVT d'une sauvegarde iOS (``mvt-ios check-backup``).

    La cible est le dossier de sauvegarde produit par ``idevicebackup2`` (Étape 4).
    """

    _OUTIL = "mvt-ios"
    _SOUS_COMMANDE = "check-backup"
    _SOUS_DOSSIER = "mvt_ios"

    def __init__(
        self,
        executor: TracedExecutor,
        cible_backup: Path | str,
        *,
        commande_mvt: Sequence[str] = ("mvt-ios",),
        dossier_ioc: Path | str | None = None,
        dossier_sortie: Path | str | None = None,
        timeout: float = 900.0,
    ) -> None:
        super().__init__(
            executor,
            cible_backup,
            commande_mvt=commande_mvt,
            dossier_ioc=dossier_ioc,
            dossier_sortie=dossier_sortie,
            timeout=timeout,
        )
