"""Corrélateur : agrège les Findings en une synthèse orientée (CLAUDE.md §7, §11).

Ce module transforme une collection d'observations en une **synthèse**. C'est le
point où la rigueur épistémique est la plus critique (§11) :

- Un **score** interne pondère chaque Finding par ``Severity × Confidence``, mais il
  n'est **pas** restitué comme un « pourcentage de culpabilité » : le niveau rendu à
  l'opérateur est **qualitatif** (:class:`NiveauIndices`).
- Le niveau est piloté par la **gravité** des indices (présence d'un vecteur direct
  de surveillance), pas par un seuil arbitraire sur le score.
- L'absence d'indice est **toujours** formulée « aucun indicateur détecté **parmi
  ceux observables** par les méthodes employées (sans root) » — **jamais** « appareil
  sain ».
- La section **Limites** accompagne systématiquement la synthèse.
- La synthèse **oriente** (dépôt de plainte, saisie officielle) ; elle ne conclut
  pas à la culpabilité de quiconque.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from guardian.core.custody import JournalCustody
from guardian.core.logging_conf import obtenir_logger
from guardian.core.provenance import Confidence, Finding, Severity

_logger = obtenir_logger("analysis.correlator")

# Pondérations internes (score non restitué tel quel à l'opérateur).
_POIDS_SEVERITE: Final[dict[Severity, float]] = {
    Severity.STRONG: 10.0,
    Severity.MEDIUM: 4.0,
    Severity.WEAK: 1.0,
    Severity.INFO: 0.0,  # neutre : ne contribue pas au faisceau de suspicion
}
_POIDS_CONFIANCE: Final[dict[Confidence, float]] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.6,
    Confidence.LOW: 0.3,
}
_ORDRE_GRAVITE: Final[dict[Severity, int]] = {
    Severity.STRONG: 0,
    Severity.MEDIUM: 1,
    Severity.WEAK: 2,
    Severity.INFO: 3,
}

# Limites de l'analyse — TOUJOURS restituées (§5, §11).
LIMITES: Final[tuple[str, ...]] = (
    "Analyse par acquisition logique SANS root : certaines zones du système restent "
    "inaccessibles.",
    "Les contenus supprimés, l'espace non alloué et les bases SQLite système protégées "
    "ne sont pas observés.",
    "Les données chiffrées propres aux applications ne sont pas déchiffrées.",
    "Aucune garantie d'exhaustivité : un logiciel malveillant disposant de privilèges "
    "root pourrait masquer sa présence.",
    "Une absence de détection signifie « aucun indicateur PARMI CEUX OBSERVABLES par "
    "les méthodes employées », jamais « appareil sain ».",
)


class NiveauIndices(StrEnum):
    """Niveau qualitatif du faisceau d'indices (restitué à l'opérateur)."""

    FORTS = "FORTS"
    MODERES = "MODERES"
    FAIBLES = "FAIBLES"
    AUCUN_OBSERVABLE = "AUCUN_OBSERVABLE"


def _score(findings: tuple[Finding, ...]) -> float:
    """Score interne pondéré Severity × Confidence (usage interne, non restitué brut)."""
    return sum(_POIDS_SEVERITE[f.severity] * _POIDS_CONFIANCE[f.confidence] for f in findings)


def _niveau(findings: tuple[Finding, ...]) -> NiveauIndices:
    """Détermine le niveau qualitatif, piloté par la gravité (pas par un seuil).

    - FORTS : au moins un signal FORT de confiance non faible (vecteur direct).
    - MODÉRÉS : un signal fort peu fiable, ou un signal moyen de confiance non faible.
    - FAIBLES : uniquement des signaux de corroboration.
    - AUCUN_OBSERVABLE : aucun signal contributif (que de l'INFO neutre / rien).
    """
    contributifs = [f for f in findings if _POIDS_SEVERITE[f.severity] > 0]
    if not contributifs:
        return NiveauIndices.AUCUN_OBSERVABLE
    if any(
        f.severity is Severity.STRONG and f.confidence is not Confidence.LOW
        for f in contributifs
    ):
        return NiveauIndices.FORTS
    if any(
        f.severity is Severity.STRONG
        or (f.severity is Severity.MEDIUM and f.confidence is not Confidence.LOW)
        for f in contributifs
    ):
        return NiveauIndices.MODERES
    return NiveauIndices.FAIBLES


_ENTETE_NIVEAU: Final[dict[NiveauIndices, str]] = {
    NiveauIndices.FORTS: (
        "Des indicateurs FORTS ont été relevés (vecteurs directs de surveillance). "
        "Ce faisceau justifie d'orienter vers un dépôt de plainte et une saisie "
        "officielle par un expert judiciaire."
    ),
    NiveauIndices.MODERES: (
        "Des indicateurs MODÉRÉS ont été relevés (contexte, persistance). Ils "
        "appellent une corroboration par une expertise plus approfondie."
    ),
    NiveauIndices.FAIBLES: (
        "Seuls des indicateurs FAIBLES (corroboration) ont été relevés. Ils ne "
        "suffisent pas à eux seuls et demandent une mise en contexte."
    ),
    NiveauIndices.AUCUN_OBSERVABLE: (
        "Aucun indicateur détecté PARMI CEUX OBSERVABLES par les méthodes employées "
        "(acquisition logique sans root). Cela ne signifie PAS que l'appareil est "
        "sain : seules les zones accessibles ont pu être examinées."
    ),
}

_RAPPEL_FINAL: Final[str] = (
    "Cette synthèse ORIENTE ; elle ne conclut pas à la culpabilité de quiconque et ne "
    "se substitue pas à une expertise judiciaire."
)


@dataclass(frozen=True)
class SyntheseCorrelation:
    """Synthèse agrégée : niveau qualitatif, score interne, findings et limites."""

    niveau: NiveauIndices
    score: float
    findings: tuple[Finding, ...]  # triés par gravité décroissante
    limites: tuple[str, ...]

    def comptes(self) -> dict[str, int]:
        """Nombre de findings par gravité."""
        comptes: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            comptes[f.severity.value] += 1
        return comptes

    def findings_de(self, severity: Severity) -> tuple[Finding, ...]:
        """Findings d'une gravité donnée."""
        return tuple(f for f in self.findings if f.severity is severity)

    def formulation(self) -> str:
        """Texte de synthèse, épistémiquement prudent, limites incluses."""
        comptes = self.comptes()
        lignes = [
            _ENTETE_NIVEAU[self.niveau],
            "",
            "Décompte des indices : "
            + ", ".join(f"{s.value}={comptes[s.value]}" for s in Severity),
            "",
            "Limites de l'analyse :",
        ]
        lignes.extend(f" - {limite}" for limite in self.limites)
        lignes.extend(["", _RAPPEL_FINAL])
        return "\n".join(lignes)

    def vers_dict(self) -> dict[str, Any]:
        """Représentation JSON-sérialisable (journal probatoire)."""
        return {
            "niveau": self.niveau.value,
            "score_interne": round(self.score, 3),
            "comptes": self.comptes(),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "value": f.value,
                }
                for f in self.findings
            ],
            "limites": list(self.limites),
        }


class Correlateur:
    """Agrège des Findings en une :class:`SyntheseCorrelation`."""

    def __init__(
        self,
        findings: Iterable[Finding],
        *,
        journal: JournalCustody | None = None,
    ) -> None:
        self._findings = tuple(findings)
        self._journal = journal

    def correler(self) -> SyntheseCorrelation:
        """Calcule la synthèse et, si un journal est fourni, la consigne."""
        tries = tuple(sorted(self._findings, key=lambda f: _ORDRE_GRAVITE[f.severity]))
        synthese = SyntheseCorrelation(
            niveau=_niveau(tries),
            score=_score(tries),
            findings=tries,
            limites=LIMITES,
        )
        if self._journal is not None:
            self._journal.consigner(
                "synthese_correlation",
                {
                    "niveau": synthese.niveau.value,
                    "score_interne": round(synthese.score, 3),
                    "comptes": synthese.comptes(),
                },
            )
        _logger.info(
            "corrélation effectuée",
            extra={"niveau": synthese.niveau.value, "nb_findings": len(tries)},
        )
        return synthese
