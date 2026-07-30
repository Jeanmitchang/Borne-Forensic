"""Vérification de l'environnement : présence des dépendances et capture de version.

Au démarrage (et via ``python -m guardian.core.environment``), guardian contrôle la
présence de ses dépendances système (CLAUDE.md §8) **sans jamais planter** : les
manquantes sont listées clairement, avec leur rôle et leur commande d'installation.

Deux niveaux, pour respecter la porte unique du §6 :

- **Présence** : détectée par ``shutil.which`` (binaires) ou ``importlib`` (paquets
  Python). Aucune commande n'est exécutée → sûr et déterministe, utilisable en
  pré-vol avant même l'ouverture d'une affaire.
- **Version** (métadonnée de provenance) : capturée en **exécutant** l'outil, donc
  uniquement lorsqu'un :class:`TracedExecutor` est fourni (contexte d'affaire). Ces
  sondes de version sont alors tracées et hachées comme toute autre commande.

Le diagnostic autonome fait une vérification *présence seule* (executor absent) :
il répond « adb est-il installé ? » sans rien exécuter.
"""

from __future__ import annotations

import contextlib
import importlib.metadata
import importlib.util
import platform
import shutil
import sys
from dataclasses import dataclass
from enum import StrEnum

from guardian.core.exceptions import ProvenanceError
from guardian.core.logging_conf import obtenir_logger
from guardian.core.provenance import RegistreVersions, TracedExecutor

_logger = obtenir_logger("core.environment")

_PYTHON_MIN: tuple[int, int] = (3, 11)


class Exigence(StrEnum):
    """Degré d'exigence d'une dépendance."""

    OBLIGATOIRE = "OBLIGATOIRE"  # sans elle, guardian ne peut pas fonctionner
    RECOMMANDEE = "RECOMMANDEE"  # nécessaire à une plateforme/fonction majeure
    OPTIONNELLE = "OPTIONNELLE"  # confort ou corroboration


class TypeDependance(StrEnum):
    """Nature de la dépendance (détermine la méthode de détection)."""

    RUNTIME = "RUNTIME"  # l'interpréteur Python lui-même
    BINAIRE = "BINAIRE"  # exécutable dans le PATH
    PAQUET_PYTHON = "PAQUET_PYTHON"  # module importable


@dataclass(frozen=True)
class Dependance:
    """Description déclarative d'une dépendance à vérifier."""

    nom: str
    type: TypeDependance
    exigence: Exigence
    role: str
    installation: str
    cible: str  # binaire à sonder, module à importer, ou "" pour le runtime
    commande_version: tuple[str, ...] = ("--version",)


@dataclass(frozen=True)
class ResultatDependance:
    """Résultat de la vérification d'une dépendance."""

    dependance: Dependance
    presente: bool
    version: str | None
    detail: str


@dataclass(frozen=True)
class RapportEnvironnement:
    """Synthèse de la vérification de l'ensemble des dépendances."""

    resultats: tuple[ResultatDependance, ...]

    def manquants_obligatoires(self) -> list[ResultatDependance]:
        return [
            r
            for r in self.resultats
            if not r.presente and r.dependance.exigence is Exigence.OBLIGATOIRE
        ]

    def tout_obligatoire_present(self) -> bool:
        return not self.manquants_obligatoires()

    def versions(self) -> dict[str, str | None]:
        """Versions captées, indexées par cible (binaire/module)."""
        return {
            r.dependance.cible: r.version
            for r in self.resultats
            if r.presente and r.dependance.cible
        }

    def resume(self) -> str:
        """Rapport lisible par l'opérateur (multi-lignes)."""
        lignes = ["Vérification de l'environnement guardian", "=" * 42]
        for r in self.resultats:
            marque = "✔" if r.presente else "✗"
            version = f" ({r.version})" if r.version else ""
            lignes.append(
                f" {marque} [{r.dependance.exigence.value:<11}] {r.dependance.nom}{version}"
            )
            lignes.append(f"      {r.detail}")
        manquants = self.manquants_obligatoires()
        lignes.append("-" * 42)
        if manquants:
            noms = ", ".join(r.dependance.nom for r in manquants)
            lignes.append(f"BLOQUANT : dépendance(s) obligatoire(s) absente(s) : {noms}")
        else:
            lignes.append("Toutes les dépendances obligatoires sont présentes.")
        lignes.append(
            "Note : une dépendance absente réduit le périmètre observable ; "
            "elle n'invalide pas les résultats obtenus par les méthodes disponibles."
        )
        return "\n".join(lignes)


# Dépendances par défaut (CLAUDE.md §8). Seul Python est strictement obligatoire :
# un opérateur peut n'analyser qu'une plateforme. Les outils de plateforme sont donc
# « recommandés », listés s'ils manquent, sans empêcher le démarrage.
DEPENDANCES: tuple[Dependance, ...] = (
    Dependance(
        nom="Python ≥ 3.11",
        type=TypeDependance.RUNTIME,
        exigence=Exigence.OBLIGATOIRE,
        role="Runtime de guardian",
        installation="apt install python3.11",
        cible="",
    ),
    Dependance(
        nom="android-tools-adb (adb)",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.RECOMMANDEE,
        role="Acquisition logique Android",
        installation="apt install android-tools-adb",
        cible="adb",
        commande_version=("--version",),
    ),
    Dependance(
        nom="libimobiledevice (idevice_id)",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.RECOMMANDEE,
        role="Détection d'appareils iOS",
        installation="apt install libimobiledevice-utils",
        cible="idevice_id",
        commande_version=("-v",),
    ),
    Dependance(
        nom="libimobiledevice (idevicebackup2)",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.RECOMMANDEE,
        role="Sauvegarde iOS chiffrée",
        installation="apt install libimobiledevice-utils",
        cible="idevicebackup2",
    ),
    Dependance(
        nom="MVT iOS (mvt-ios)",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.RECOMMANDEE,
        role="Analyse IOC/blocklist iOS",
        installation="pip install mvt",
        cible="mvt-ios",
    ),
    Dependance(
        nom="MVT Android (mvt-android)",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.RECOMMANDEE,
        role="Analyse IOC/blocklist Android",
        installation="pip install mvt",
        cible="mvt-android",
    ),
    Dependance(
        nom="PyQt6",
        type=TypeDependance.PAQUET_PYTHON,
        exigence=Exigence.RECOMMANDEE,
        role="Interface graphique cockpit",
        installation="pip install PyQt6",
        cible="PyQt6",
    ),
    Dependance(
        nom="Java (Autopsy)",
        type=TypeDependance.BINAIRE,
        exigence=Exigence.OPTIONNELLE,
        role="Corroboration Autopsy (optionnel)",
        installation="apt install default-jre",
        cible="java",
        commande_version=("-version",),
    ),
)


class VerificateurEnvironnement:
    """Vérifie les dépendances et, si un contexte tracé est fourni, capte les versions."""

    def __init__(
        self,
        dependances: tuple[Dependance, ...] = DEPENDANCES,
        executor: TracedExecutor | None = None,
        registre: RegistreVersions | None = None,
    ) -> None:
        self._dependances = dependances
        self._executor = executor
        # Le registre à peupler : celui fourni, sinon celui de l'executor le cas échéant.
        if registre is not None:
            self._registre: RegistreVersions | None = registre
        elif executor is not None:
            self._registre = executor.registre
        else:
            self._registre = None

    def verifier(self) -> RapportEnvironnement:
        """Vérifie toutes les dépendances et retourne un rapport. Ne lève jamais."""
        resultats = tuple(self._verifier_une(dep) for dep in self._dependances)
        rapport = RapportEnvironnement(resultats)

        if self._registre is not None:
            for r in resultats:
                if r.presente and r.dependance.cible:
                    self._registre.enregistrer(r.dependance.cible, r.version)
        if self._executor is not None:
            self._executor.journal.consigner(
                "environnement_verifie", {"versions": rapport.versions()}
            )
        _logger.info(
            "environnement vérifié",
            extra={"obligatoires_ok": rapport.tout_obligatoire_present()},
        )
        return rapport

    def _verifier_une(self, dep: Dependance) -> ResultatDependance:
        if dep.type is TypeDependance.RUNTIME:
            return self._verifier_runtime(dep)
        if dep.type is TypeDependance.PAQUET_PYTHON:
            return self._verifier_paquet(dep)
        return self._verifier_binaire(dep)

    def _verifier_runtime(self, dep: Dependance) -> ResultatDependance:
        version = platform.python_version()
        present = sys.version_info[:2] >= _PYTHON_MIN
        if present:
            detail = f"Python {version} détecté (minimum {_PYTHON_MIN[0]}.{_PYTHON_MIN[1]})."
        else:
            detail = (
                f"Python {version} trop ancien : "
                f"{_PYTHON_MIN[0]}.{_PYTHON_MIN[1]}+ requis. {dep.installation}"
            )
        return ResultatDependance(dep, present, version, detail)

    def _verifier_paquet(self, dep: Dependance) -> ResultatDependance:
        try:
            spec = importlib.util.find_spec(dep.cible)
        except ModuleNotFoundError:
            spec = None
        if spec is None:
            return ResultatDependance(
                dep, False, None, f"Module Python absent. Installation : {dep.installation}"
            )
        try:
            version = importlib.metadata.version(dep.cible)
        except importlib.metadata.PackageNotFoundError:
            version = None
        return ResultatDependance(dep, True, version, "Module Python présent.")

    def _verifier_binaire(self, dep: Dependance) -> ResultatDependance:
        chemin = shutil.which(dep.cible)
        if chemin is None:
            return ResultatDependance(
                dep,
                False,
                None,
                f"Binaire « {dep.cible} » introuvable dans le PATH. "
                f"Installation : {dep.installation}",
            )
        version = self._capturer_version(dep, chemin)
        if version is not None:
            detail = f"Présent : {chemin}"
        elif self._executor is None:
            detail = f"Présent : {chemin} (version non capturée — pré-vol sans contexte tracé)"
        else:
            detail = f"Présent : {chemin} (version illisible)"
        return ResultatDependance(dep, True, version, detail)

    def _capturer_version(self, dep: Dependance, chemin: str) -> str | None:
        """Capte la version via le TracedExecutor. ``None`` si indisponible."""
        if self._executor is None:
            return None
        try:
            resultat = self._executor.executer([chemin, *dep.commande_version], timeout=10)
        except ProvenanceError:
            return None
        # Certains outils écrivent leur version sur stderr (ex. « java -version »).
        brut = resultat.texte_stdout() + "\n" + resultat.stderr.decode("utf-8", "replace")
        for ligne in brut.splitlines():
            ligne = ligne.strip()
            if ligne:
                return ligne[:200]
        return None


def verifier_environnement(
    executor: TracedExecutor | None = None,
    registre: RegistreVersions | None = None,
    dependances: tuple[Dependance, ...] = DEPENDANCES,
) -> RapportEnvironnement:
    """Raccourci : vérifie l'environnement avec les dépendances par défaut."""
    return VerificateurEnvironnement(dependances, executor, registre).verifier()


def _principal() -> int:
    """Diagnostic autonome (présence seule) : ``python -m guardian.core.environment``."""
    # Cible = Linux (UTF-8). Sur une console Windows héritée (cp1252), on force UTF-8
    # pour ne pas planter sur les marqueurs du rapport ; sinon on continue tel quel.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        # Flux non reconfigurable (redirigé, capturé…) : le rapport reste lisible.
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8")
    rapport = verifier_environnement()
    print(rapport.resume())
    return 0 if rapport.tout_obligatoire_present() else 1


if __name__ == "__main__":
    raise SystemExit(_principal())
