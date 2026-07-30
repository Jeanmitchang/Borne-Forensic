"""Analyse Autopsy — corroboration **optionnelle** (CLAUDE.md §3, §10, Étape 10).

Autopsy (plateforme Java, Sleuth Kit) sert de **corroboration** post-acquisition
(timeline, recherche par mots-clés). Comme LEAPP, il **produit des artefacts** à
interpréter, il ne « détecte » pas : le Finding est de gravité ``INFO`` et le
rapport généré est la pièce.

**Honnêteté sur l'outil** : l'invocation en ligne de commande d'Autopsy varie
fortement selon les versions et les plateformes. Plutôt que de figer un contrat CLI
potentiellement faux, ce runner rend l'invocation **configurable** :

- ``commande_autopsy`` : commande de base (défaut ``("autopsy",)``) ;
- ``flag_entree`` / ``flag_sortie`` : noms des options (défaut ``--input`` / ``--output``) ;
- ``args_supplementaires`` : options propres à la version/configuration de l'opérateur.

Autopsy requiert **Java** (vérifié par ``core.environment``). Ce module reste
optionnel : il n'est utilisé que si l'opérateur le sollicite explicitement.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from guardian.analysis.base import Analyzer, ResultatAnalyse
from guardian.core.exceptions import ValidationError
from guardian.core.provenance import (
    Confidence,
    Reproducibility,
    Severity,
    TracedExecutor,
)

_NOMS_RAPPORT = ("report.html", "index.html")


def _trouver_rapport(dossier: Path) -> Path | None:
    """Retourne le premier rapport HTML produit par Autopsy, s'il existe."""
    if not dossier.is_dir():
        return None
    candidats = sorted(
        p for p in dossier.rglob("*") if p.is_file() and p.name.lower() in _NOMS_RAPPORT
    )
    return candidats[0] if candidats else None


class AutopsyRunner(Analyzer):
    """Corroboration Autopsy d'une source de données (invocation configurable)."""

    def __init__(
        self,
        executor: TracedExecutor,
        cible: Path | str,
        *,
        commande_autopsy: Sequence[str] = ("autopsy",),
        flag_entree: str = "--input",
        flag_sortie: str = "--output",
        args_supplementaires: Sequence[str] = (),
        dossier_sortie: Path | str | None = None,
        timeout: float = 3600.0,
    ) -> None:
        super().__init__(executor)
        self._cible = Path(cible)
        if not self._cible.exists():
            raise ValidationError(f"Source de données introuvable : {self._cible}")
        self._commande_autopsy = tuple(commande_autopsy)
        self._flag_entree = flag_entree
        self._flag_sortie = flag_sortie
        self._args_supp = tuple(args_supplementaires)
        self._dossier_sortie = (
            Path(dossier_sortie)
            if dossier_sortie is not None
            else executor.dossier / "analyse" / "autopsy"
        )
        self._timeout = timeout

    @property
    def outil(self) -> str:
        return "autopsy"

    def analyser(self) -> ResultatAnalyse:
        self._consigner_debut()
        self._dossier_sortie.mkdir(parents=True, exist_ok=True)
        args = [
            *self._commande_autopsy,
            *self._args_supp,
            self._flag_entree,
            str(self._cible),
            self._flag_sortie,
            str(self._dossier_sortie),
        ]
        tracee = self._executor.executer(args, timeout=self._timeout)

        fichiers = [p for p in self._dossier_sortie.rglob("*") if p.is_file()]
        if tracee.trace.exit_code != 0 or not fichiers:
            finding = self._finding_echec(tracee, "autopsy")
            resultat = ResultatAnalyse(self.outil, (finding,), (), complete=False)
            self._consigner_fin(resultat)
            return resultat

        rapport = _trouver_rapport(self._dossier_sortie)
        ref_rapport = self._rel(rapport) if rapport is not None else None
        artefacts = (ref_rapport,) if ref_rapport is not None else ()
        emplacement = ref_rapport if ref_rapport is not None else "sans rapport HTML"
        finding = tracee.en_finding(
            value=(
                f"autopsy : corroboration générée ({emplacement}), "
                f"{len(fichiers)} fichier(s) — à interpréter."
            ),
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
        resultat = ResultatAnalyse(self.outil, (finding,), artefacts, complete=True)
        self._consigner_fin(resultat)
        return resultat
