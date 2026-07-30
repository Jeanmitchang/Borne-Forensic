"""Orchestration d'une affaire : le fil qui relie tout le pipeline (Étape 9.1).

Ce module **ne dépend pas de PyQt** : il contient toute la logique d'enchaînement
(ouverture d'affaire → détection → acquisition → analyse → corrélation → rapport),
afin qu'elle soit testable indépendamment de l'interface. La GUI (sous-lot 9.2) n'en
sera qu'une fine couche d'appel.

Une :class:`Affaire` porte le **contexte** partagé — dossier, ``TracedExecutor``,
journal de custody, registre de versions — et **accumule** les Findings au fil des
phases. Les acquéreurs/analyseurs concrets sont construits par l'appelant avec
``affaire.executor`` (injection des commandes possible → testabilité).
"""

from __future__ import annotations

from pathlib import Path

from guardian.acquisition.base import Acquirer, ResultatAcquisition
from guardian.analysis.base import Analyzer, ResultatAnalyse
from guardian.analysis.correlator import Correlateur, SyntheseCorrelation
from guardian.core.custody import (
    Consentement,
    JournalCustody,
    enregistrer_consentement,
)
from guardian.core.environment import RapportEnvironnement, verifier_environnement
from guardian.core.logging_conf import obtenir_logger
from guardian.core.provenance import Finding, RegistreVersions, TracedExecutor
from guardian.detection.usb_watch import DetecteurUSB, ResultatDetection
from guardian.report.builder import DossierRapport, GenerateurRapport

_logger = obtenir_logger("affaire")


class Affaire:
    """Contexte d'une affaire ouverte et orchestration de son pipeline.

    À construire via :meth:`ouvrir` (qui écrit le consentement et amorce la custody),
    puis piloter phase par phase. Chaque acquisition/analyse **accumule** ses Findings,
    consommés ensuite par :meth:`correler` et :meth:`generer_rapport`.
    """

    def __init__(
        self,
        *,
        dossier: Path,
        identifiant_affaire: str,
        operateur: str,
        executor: TracedExecutor,
        journal: JournalCustody,
        registre: RegistreVersions,
    ) -> None:
        self.dossier = dossier
        self.identifiant_affaire = identifiant_affaire
        self.operateur = operateur
        self.executor = executor
        self.journal = journal
        self.registre = registre
        self._findings: list[Finding] = []
        self._synthese: SyntheseCorrelation | None = None

    # --- Cycle de vie ------------------------------------------------------
    @classmethod
    def ouvrir(
        cls,
        dossier: Path | str,
        *,
        identifiant_affaire: str,
        operateur: str,
        consentement: Consentement,
    ) -> Affaire:
        """Ouvre une affaire : crée le dossier, amorce la custody, consigne le consentement.

        Le consentement est **obligatoire** : analyser un support sans autorisation
        explicite est hors du cadre légal (README, CLAUDE.md §1).
        """
        dossier = Path(dossier)
        dossier.mkdir(parents=True, exist_ok=True)
        journal = JournalCustody(dossier / "custody.jsonl", operateur=operateur)
        journal.consigner("affaire_ouverte", {"identifiant_affaire": identifiant_affaire})
        enregistrer_consentement(dossier / "consent.json", consentement, journal)
        registre = RegistreVersions()
        executor = TracedExecutor(dossier, operateur, journal, registre)
        _logger.info("affaire ouverte", extra={"identifiant_affaire": identifiant_affaire})
        return cls(
            dossier=dossier,
            identifiant_affaire=identifiant_affaire,
            operateur=operateur,
            executor=executor,
            journal=journal,
            registre=registre,
        )

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Findings accumulés depuis l'ouverture de l'affaire."""
        return tuple(self._findings)

    @property
    def synthese(self) -> SyntheseCorrelation | None:
        """Dernière synthèse calculée, le cas échéant."""
        return self._synthese

    # --- Phases ------------------------------------------------------------
    def verifier_environnement(self) -> RapportEnvironnement:
        """Vérifie les dépendances et capte leurs versions (tracées) dans le registre."""
        return verifier_environnement(executor=self.executor, registre=self.registre)

    def detecter(self, detecteur: DetecteurUSB | None = None) -> ResultatDetection:
        """Détecte les appareils branchés (détecteur injectable pour les tests)."""
        det = detecteur if detecteur is not None else DetecteurUSB(self.executor)
        return det.detecter()

    def acquerir(self, acquereur: Acquirer) -> ResultatAcquisition:
        """Exécute un acquéreur (construit avec ``self.executor``) et accumule ses Findings."""
        resultat = acquereur.acquerir()
        self._findings.extend(resultat.findings)
        self._synthese = None  # la synthèse existante est invalidée
        return resultat

    def analyser(self, analyzer: Analyzer) -> ResultatAnalyse:
        """Exécute un analyseur (construit avec ``self.executor``) et accumule ses Findings."""
        resultat = analyzer.analyser()
        self._findings.extend(resultat.findings)
        self._synthese = None
        return resultat

    def correler(self) -> SyntheseCorrelation:
        """Agrège les Findings accumulés en une synthèse (consignée en custody)."""
        self._synthese = Correlateur(self._findings, journal=self.journal).correler()
        return self._synthese

    def generer_rapport(
        self,
        *,
        convertir_pdf: bool = False,
        commande_pdf: tuple[str, ...] = ("wkhtmltopdf",),
    ) -> DossierRapport:
        """Génère le dossier livrable. Corrèle d'abord si ce n'est pas déjà fait."""
        if self._synthese is None:
            self.correler()
        assert self._synthese is not None  # garanti par correler()
        return GenerateurRapport(
            self.dossier,
            self._findings,
            self._synthese,
            journal=self.journal,
            executor=self.executor,
            identifiant_affaire=self.identifiant_affaire,
            convertir_pdf=convertir_pdf,
            commande_pdf=commande_pdf,
        ).generer()
