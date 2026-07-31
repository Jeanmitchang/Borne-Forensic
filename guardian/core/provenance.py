"""Provenance : la porte unique d'exécution et l'objet de résultat auto-traçant.

Cœur du projet (CLAUDE.md §6). **Aucun module d'acquisition ou d'analyse n'exécute
de commande externe directement** : tout passe par :class:`TracedExecutor`, qui
capture stdout/stderr/code de sortie, archive et hache la sortie brute dans
``raw/<id>.out``, horodate en UTC, journalise l'exécution dans la custody
append-only, et fournit une :class:`ExecutionTracee` convertible en :class:`Finding`.

Séparation des responsabilités :

- ``TracedExecutor`` garantit la **trace** (le « comment » : binaire, version, args,
  cwd, code de sortie, sortie brute hachée). C'est la seule porte vers ``subprocess``.
- Le module appelant (runner d'analyse) attache l'**interprétation forensic** (le
  « sens » : ``value``, ``severity``, ``confidence``, ``reproducibility``) via
  :meth:`ExecutionTracee.en_finding`.

Rappel (CLAUDE.md §6) : ne jamais marquer ``DETERMINISTIC`` un résultat qui ne
l'est pas — c'est un faux pas juridique exploitable par un contradicteur.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from guardian.core.custody import JournalCustody, hacher_donnees, horodatage_utc
from guardian.core.exceptions import ProvenanceError, ValidationError
from guardian.core.logging_conf import obtenir_logger

_logger = obtenir_logger("core.provenance")


# ---------------------------------------------------------------------------
#  Vocabulaire contrôlé (enums)
# ---------------------------------------------------------------------------
class Severity(StrEnum):
    """Gravité d'un signal (cf. CLAUDE.md §5)."""

    STRONG = "STRONG"  # vecteur direct de surveillance
    MEDIUM = "MEDIUM"  # contexte & persistance
    WEAK = "WEAK"  # corroboration
    INFO = "INFO"  # information neutre, sans valeur d'indice en soi


class Confidence(StrEnum):
    """Niveau de confiance explicite dans l'interprétation d'un résultat."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Reproducibility(StrEnum):
    """Nature de la reproductibilité d'un résultat (cf. CLAUDE.md §6).

    - ``DETERMINISTIC`` : rejeu → résultat identique (hash de fichier, version).
    - ``POINT_IN_TIME`` : capture d'un instant T (méthode rejouable, pas le résultat).
    - ``ENVIRONMENT_DEPENDENT`` : dépend d'un état externe.
    """

    DETERMINISTIC = "DETERMINISTIC"
    POINT_IN_TIME = "POINT_IN_TIME"
    ENVIRONMENT_DEPENDENT = "ENVIRONMENT_DEPENDENT"


# ---------------------------------------------------------------------------
#  Trace de commande & résultat (Finding)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CommandTrace:
    """Trace d'invocation et d'exécution d'une commande externe.

    ``binary_version`` peut être ``None`` si la version n'a pas pu être capturée au
    démarrage (le signaler honnêtement plutôt que d'inventer). ``stderr_ref`` /
    ``stderr_sha256`` sont ``None`` si la commande n'a rien écrit sur stderr.
    """

    binary: str
    binary_version: str | None
    args: tuple[str, ...]
    cwd: str
    exit_code: int
    duration_ms: int
    stderr_ref: str | None
    stderr_sha256: str | None

    def vers_dict(self) -> dict[str, Any]:
        return {
            "binary": self.binary,
            "binary_version": self.binary_version,
            "args": list(self.args),
            "cwd": self.cwd,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "stderr_ref": self.stderr_ref,
            "stderr_sha256": self.stderr_sha256,
        }


@dataclass(frozen=True)
class Finding:
    """Résultat forensic auto-traçant (cf. CLAUDE.md §6).

    Un ``Finding`` associe une **interprétation** (``value`` + ``severity`` +
    ``confidence``) à sa **provenance** complète (``trace`` + sortie brute hachée),
    de sorte qu'un tiers puisse relier chaque affirmation de synthèse à la commande
    exacte qui l'a produite.
    """

    finding_id: str
    value: str
    severity: Severity
    confidence: Confidence
    trace: CommandTrace
    raw_output_ref: str
    raw_output_sha256: str
    timestamp_utc: str
    operator: str
    reproducibility: Reproducibility

    def vers_dict(self) -> dict[str, Any]:
        """Représentation JSON-sérialisable (pour le journal probatoire)."""
        return {
            "finding_id": self.finding_id,
            "value": self.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "reproducibility": self.reproducibility.value,
            "timestamp_utc": self.timestamp_utc,
            "operator": self.operator,
            "raw_output_ref": self.raw_output_ref,
            "raw_output_sha256": self.raw_output_sha256,
            "trace": self.trace.vers_dict(),
        }


# ---------------------------------------------------------------------------
#  Registre des versions d'outils
# ---------------------------------------------------------------------------
class RegistreVersions:
    """Mémorise la version des outils externes, captée au démarrage.

    Rempli par ``core.environment`` (sous-lot suivant) puis consulté par le
    ``TracedExecutor`` pour renseigner ``CommandTrace.binary_version``. Une version
    inconnue est ``None`` — jamais inventée.
    """

    def __init__(self) -> None:
        self._versions: dict[str, str | None] = {}

    def enregistrer(self, binaire: str, version: str | None) -> None:
        self._versions[binaire] = version

    def version_de(self, binaire: str) -> str | None:
        return self._versions.get(binaire)

    def vers_dict(self) -> dict[str, str | None]:
        return dict(self._versions)


# ---------------------------------------------------------------------------
#  Exécution tracée
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ExecutionTracee:
    """Enveloppe tracée d'une exécution, avant interprétation forensic.

    Produite par :meth:`TracedExecutor.executer`. Le runner appelant lit la sortie
    (``texte_stdout``), l'interprète, puis matérialise un :class:`Finding` via
    :meth:`en_finding`.
    """

    finding_id: str
    trace: CommandTrace
    raw_output_ref: str
    raw_output_sha256: str
    stdout: bytes
    stderr: bytes
    timestamp_utc: str
    operator: str

    def texte_stdout(self, encodage: str = "utf-8", erreurs: str = "replace") -> str:
        """Décode stdout en texte (``replace`` par défaut : ne jamais planter dessus)."""
        return self.stdout.decode(encodage, erreurs)

    def texte_stderr(self, encodage: str = "utf-8", erreurs: str = "replace") -> str:
        """Décode stderr en texte (``replace`` par défaut : ne jamais planter dessus)."""
        return self.stderr.decode(encodage, erreurs)

    def en_finding(
        self,
        *,
        value: str,
        severity: Severity,
        confidence: Confidence,
        reproducibility: Reproducibility,
    ) -> Finding:
        """Attache l'interprétation forensic à la trace et retourne un ``Finding``."""
        return Finding(
            finding_id=self.finding_id,
            value=value,
            severity=severity,
            confidence=confidence,
            trace=self.trace,
            raw_output_ref=self.raw_output_ref,
            raw_output_sha256=self.raw_output_sha256,
            timestamp_utc=self.timestamp_utc,
            operator=self.operator,
            reproducibility=reproducibility,
        )


class TracedExecutor:
    """Porte **unique** d'exécution de commandes externes.

    Toute commande d'acquisition ou d'analyse passe par ici. Chaque exécution :
    archive stdout dans ``raw/<id>.out`` (et stderr dans ``raw/<id>.err`` s'il y en
    a), hache ces sorties (SHA-256), horodate en UTC, et journalise l'événement dans
    la custody append-only. ``subprocess`` n'est jamais invoqué avec ``shell=True`` ;
    les arguments sont toujours passés en liste.
    """

    def __init__(
        self,
        dossier_affaire: Path | str,
        operateur: str,
        journal: JournalCustody,
        registre: RegistreVersions | None = None,
    ) -> None:
        if not operateur or not operateur.strip():
            raise ValidationError("L'identité de l'opérateur est obligatoire.")
        self.dossier = Path(dossier_affaire)
        self.dossier_raw = self.dossier / "raw"
        self.dossier_raw.mkdir(parents=True, exist_ok=True)
        self.operateur = operateur
        self.journal = journal
        self.registre = registre if registre is not None else RegistreVersions()
        self._compteur = 0

    def _prochain_id(self) -> str:
        self._compteur += 1
        return f"F-{self._compteur:04d}"

    def _archiver(self, finding_id: str, extension: str, donnees: bytes) -> tuple[str, str]:
        """Écrit une sortie brute dans ``raw/`` et retourne (ref POSIX, sha256)."""
        nom = f"{finding_id}.{extension}"
        chemin = self.dossier_raw / nom
        try:
            chemin.write_bytes(donnees)
        except OSError as exc:
            raise ProvenanceError(
                f"Archivage de la sortie brute impossible : {chemin}"
            ) from exc
        return f"raw/{nom}", hacher_donnees(donnees)

    def executer(
        self,
        args: Sequence[str],
        *,
        cwd: Path | str | None = None,
        timeout: float | None = None,
        entree: bytes | None = None,
        env: Mapping[str, str] | None = None,
    ) -> ExecutionTracee:
        """Exécute ``args`` (liste, jamais shell) et retourne l'exécution tracée.

        :param args: commande sous forme de liste d'arguments non vide.
        :param cwd: répertoire de travail ; par défaut le dossier d'affaire.
        :param timeout: délai maximal en secondes ; dépassement = ``ProvenanceError``.
        :param entree: données à passer sur stdin, le cas échéant.
        :param env: variables d'environnement **surchargeant** celles du processus
            (fusion avec ``os.environ``, les clés fournies l'emportent). Voie réservée
            aux **secrets** qui ne doivent jamais transiter par ``args`` (ex. mot de
            passe de sauvegarde iOS pour MVT) : comme ``entree`` (stdin), ``env``
            n'est **ni archivé dans** ``raw/`` **ni journalisé** dans la custody. Ne
            jamais y placer une valeur destinée à être tracée.
        :raises ValidationError: si ``args`` est invalide.
        :raises ProvenanceError: si le binaire est introuvable, en délai dépassé, ou
            si l'archivage de la sortie échoue.
        """
        if isinstance(args, str):
            raise ValidationError(
                "La commande doit être une liste d'arguments, pas une chaîne."
            )
        args = list(args)
        if not args:
            raise ValidationError("La commande à exécuter ne peut être vide.")
        if not all(isinstance(a, str) for a in args):
            raise ValidationError(
                "Tous les arguments de la commande doivent être des chaînes."
            )

        binaire = args[0]
        repertoire = Path(cwd) if cwd is not None else self.dossier
        # Fusion avec l'environnement courant : passer ``env=`` seul à subprocess le
        # remplacerait entièrement (PATH, HOME… perdus). ``None`` => héritage complet.
        environnement = {**os.environ, **env} if env is not None else None
        finding_id = self._prochain_id()
        horodatage = horodatage_utc()
        debut = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 — args en liste, jamais shell=True
                args,
                capture_output=True,
                cwd=repertoire,
                timeout=timeout,
                input=entree,
                env=environnement,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ProvenanceError(f"Binaire introuvable : {binaire}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ProvenanceError(f"Délai dépassé pour {binaire} ({timeout} s)") from exc
        except OSError as exc:
            raise ProvenanceError(f"Échec d'exécution de {binaire}") from exc
        duree_ms = int((time.monotonic() - debut) * 1000)

        stdout: bytes = proc.stdout if proc.stdout is not None else b""
        stderr: bytes = proc.stderr if proc.stderr is not None else b""
        ref_out, sha_out = self._archiver(finding_id, "out", stdout)
        ref_err: str | None = None
        sha_err: str | None = None
        if stderr:
            ref_err, sha_err = self._archiver(finding_id, "err", stderr)

        trace = CommandTrace(
            binary=binaire,
            binary_version=self.registre.version_de(binaire),
            args=tuple(args),
            cwd=str(repertoire),
            exit_code=proc.returncode,
            duration_ms=duree_ms,
            stderr_ref=ref_err,
            stderr_sha256=sha_err,
        )
        self.journal.consigner(
            "commande_executee",
            {
                "finding_id": finding_id,
                "binary": binaire,
                "args": list(args),
                "exit_code": proc.returncode,
                "raw_output_ref": ref_out,
                "raw_output_sha256": sha_out,
            },
        )
        _logger.info(
            "commande tracée",
            extra={"finding_id": finding_id, "binary": binaire, "exit_code": proc.returncode},
        )
        return ExecutionTracee(
            finding_id=finding_id,
            trace=trace,
            raw_output_ref=ref_out,
            raw_output_sha256=sha_out,
            stdout=stdout,
            stderr=stderr,
            timestamp_utc=horodatage,
            operator=self.operateur,
        )
