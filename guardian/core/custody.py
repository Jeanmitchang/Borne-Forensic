"""Chaîne de custody : hachage, journal append-only, consentement, manifeste.

Ce module matérialise l'exigence d'**intégrité probatoire** (CLAUDE.md §6,
SECURITY.md §3.3). Il fournit :

- ``hacher_fichier`` / ``hacher_donnees`` : empreintes SHA-256.
- :class:`JournalCustody` : journal **append-only** horodaté UTC et **chaîné par
  hachage** (chaque entrée scelle la précédente). Toute altération a posteriori
  d'une entrée est détectable par ``verifier_integrite``.
- :class:`Consentement` + ``enregistrer_consentement`` : consignation du
  consentement du propriétaire à l'ouverture de l'affaire (``consent.json``).
- ``generer_manifeste`` / ``verifier_manifeste`` : ``MANIFEST.sha256`` au format
  ``sha256sum`` (vérifiable par un tiers avec ``sha256sum -c``).

Distinction importante : ce journal de **custody** trace la chaîne probatoire ;
il est différent des journaux **applicatifs** de ``core.logging_conf`` qui tracent
le comportement du logiciel.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from guardian.core.exceptions import CustodyError, ValidationError
from guardian.core.logging_conf import obtenir_logger

_TAILLE_BLOC: Final[int] = 1024 * 1024  # 1 Mio : hachage en flux pour gros fichiers.
_HASH_GENESE: Final[str] = "0" * 64  # Ancre de départ de la chaîne de custody.
_NOM_MANIFESTE: Final[str] = "MANIFEST.sha256"

_logger = obtenir_logger("core.custody")


# ---------------------------------------------------------------------------
#  Horodatage & hachage
# ---------------------------------------------------------------------------
def horodatage_utc() -> str:
    """Retourne l'instant courant en ISO-8601 UTC, précision milliseconde (…Z)."""
    return datetime.now(tz=UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def hacher_donnees(donnees: bytes) -> str:
    """Retourne le SHA-256 hexadécimal de ``donnees``."""
    return hashlib.sha256(donnees).hexdigest()


def hacher_fichier(chemin: Path | str) -> str:
    """Retourne le SHA-256 hexadécimal du fichier ``chemin`` (lecture en flux).

    :raises ValidationError: si le chemin ne désigne pas un fichier existant.
    :raises CustodyError: si la lecture échoue (droits, E/S).
    """
    chemin = Path(chemin)
    if not chemin.is_file():
        raise ValidationError(f"Fichier introuvable pour hachage : {chemin}")
    empreinte = hashlib.sha256()
    try:
        with chemin.open("rb") as flux:
            for bloc in iter(lambda: flux.read(_TAILLE_BLOC), b""):
                empreinte.update(bloc)
    except OSError as exc:
        raise CustodyError(f"Lecture impossible pour hachage : {chemin}") from exc
    return empreinte.hexdigest()


def _serialiser_canonique(obj: Mapping[str, Any]) -> bytes:
    """Sérialise de façon déterministe (clés triées, compact) pour le hachage."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


# ---------------------------------------------------------------------------
#  Journal de custody append-only, chaîné par hachage
# ---------------------------------------------------------------------------
class JournalCustody:
    """Journal probatoire append-only, horodaté UTC et chaîné par hachage.

    Chaque entrée contient l'empreinte de l'entrée précédente (``hash_precedent``)
    et sa propre empreinte (``hash_entree``), calculée sur son contenu canonique.
    La rupture de la séquence d'index ou de la chaîne de hachage est détectée par
    :meth:`verifier_integrite`. Le fichier n'est **jamais réécrit**, seulement
    complété (mode append), et chaque écriture est suivie d'un ``fsync``.
    """

    def __init__(self, chemin: Path | str, operateur: str) -> None:
        if not operateur or not operateur.strip():
            raise ValidationError(
                "L'identité de l'opérateur est obligatoire pour le journal de custody."
            )
        self.chemin = Path(chemin)
        self.operateur = operateur
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        self._index_courant, self._dernier_hash = self._charger_etat()

    def _charger_etat(self) -> tuple[int, str]:
        """Reprend l'état (dernier index, dernier hash) sans réécrire le fichier."""
        if not self.chemin.exists():
            return (-1, _HASH_GENESE)
        derniere: dict[str, Any] | None = None
        try:
            with self.chemin.open("r", encoding="utf-8") as flux:
                for numero, ligne in enumerate(flux, start=1):
                    ligne = ligne.strip()
                    if not ligne:
                        continue
                    try:
                        derniere = json.loads(ligne)
                    except json.JSONDecodeError as exc:
                        raise CustodyError(
                            f"Journal de custody corrompu (ligne {numero} illisible) : "
                            f"{self.chemin}"
                        ) from exc
        except OSError as exc:
            raise CustodyError(
                f"Lecture du journal de custody impossible : {self.chemin}"
            ) from exc
        if derniere is None:
            return (-1, _HASH_GENESE)
        return (int(derniere["index"]), str(derniere["hash_entree"]))

    def consigner(
        self, evenement: str, details: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Ajoute une entrée scellée au journal et la retourne.

        :param evenement: type d'événement (ex. ``"consentement_enregistre"``).
        :param details: contexte JSON-sérialisable (jamais de secret en clair).
        :raises ValidationError: si ``evenement`` est vide.
        :raises CustodyError: si l'écriture échoue.
        """
        if not evenement or not evenement.strip():
            raise ValidationError("Le type d'événement de custody ne peut être vide.")
        index = self._index_courant + 1
        entree: dict[str, Any] = {
            "index": index,
            "horodatage_utc": horodatage_utc(),
            "operateur": self.operateur,
            "evenement": evenement,
            "details": dict(details) if details else {},
            "hash_precedent": self._dernier_hash,
        }
        entree["hash_entree"] = hacher_donnees(_serialiser_canonique(entree))
        ligne = json.dumps(entree, ensure_ascii=False) + "\n"
        try:
            with self.chemin.open("a", encoding="utf-8") as flux:
                flux.write(ligne)
                flux.flush()
                os.fsync(flux.fileno())
        except OSError as exc:
            raise CustodyError(
                f"Écriture impossible dans le journal de custody : {self.chemin}"
            ) from exc
        self._index_courant = index
        self._dernier_hash = entree["hash_entree"]
        _logger.info(
            "événement de custody consigné",
            extra={"evenement": evenement, "index": index},
        )
        return entree

    def verifier_integrite(self) -> None:
        """Revérifie séquence d'index et chaîne de hachage de bout en bout.

        :raises CustodyError: à la première anomalie (séquence, chaînage, ou
            entrée altérée). Ne retourne rien si le journal est intègre.
        """
        if not self.chemin.exists():
            return
        hash_precedent_attendu = _HASH_GENESE
        index_attendu = 0
        try:
            flux = self.chemin.open("r", encoding="utf-8")
        except OSError as exc:
            raise CustodyError(
                f"Lecture du journal de custody impossible : {self.chemin}"
            ) from exc
        with flux:
            for numero, ligne in enumerate(flux, start=1):
                ligne = ligne.strip()
                if not ligne:
                    continue
                try:
                    entree = json.loads(ligne)
                except json.JSONDecodeError as exc:
                    raise CustodyError(
                        f"Ligne {numero} du journal de custody illisible (JSON)."
                    ) from exc
                if entree.get("index") != index_attendu:
                    raise CustodyError(
                        f"Rupture de séquence à la ligne {numero} : index "
                        f"{entree.get('index')!r}, attendu {index_attendu}."
                    )
                if entree.get("hash_precedent") != hash_precedent_attendu:
                    raise CustodyError(f"Rupture de chaînage de custody à la ligne {numero}.")
                hash_enregistre = entree.get("hash_entree")
                sans_hash = {c: v for c, v in entree.items() if c != "hash_entree"}
                hash_recalcule = hacher_donnees(_serialiser_canonique(sans_hash))
                if hash_enregistre != hash_recalcule:
                    raise CustodyError(
                        f"Entrée de custody altérée à la ligne {numero} "
                        f"(hash recalculé différent)."
                    )
                hash_precedent_attendu = str(hash_enregistre)
                index_attendu += 1


# ---------------------------------------------------------------------------
#  Consentement
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Consentement:
    """Consentement du propriétaire du support, consigné à l'ouverture d'affaire.

    Tous les champs listés dans ``__post_init__`` sont obligatoires : l'analyse
    d'un support sans autorisation explicite est hors du cadre légal (README,
    CLAUDE.md §1).
    """

    identifiant_affaire: str
    proprietaire_support: str
    operateur: str
    description_support: str
    portee: str
    date_consentement_utc: str = field(default_factory=horodatage_utc)
    mentions: str = ""

    def __post_init__(self) -> None:
        obligatoires = {
            "identifiant_affaire": self.identifiant_affaire,
            "proprietaire_support": self.proprietaire_support,
            "operateur": self.operateur,
            "description_support": self.description_support,
            "portee": self.portee,
        }
        manquants = [nom for nom, val in obligatoires.items() if not val or not val.strip()]
        if manquants:
            raise ValidationError(
                "Champs de consentement obligatoires manquants : " + ", ".join(manquants)
            )

    def vers_dict(self) -> dict[str, Any]:
        """Retourne une représentation sérialisable du consentement."""
        return asdict(self)


def enregistrer_consentement(
    chemin: Path | str,
    consentement: Consentement,
    journal: JournalCustody | None = None,
) -> str:
    """Écrit ``consent.json`` et retourne son SHA-256.

    Si un ``journal`` est fourni, consigne l'événement (identifiant d'affaire et
    empreinte du fichier uniquement — pas de recopie de données personnelles).

    :raises CustodyError: si l'écriture échoue.
    """
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    contenu = json.dumps(
        consentement.vers_dict(), ensure_ascii=False, indent=2, sort_keys=True
    )
    try:
        chemin.write_text(contenu + "\n", encoding="utf-8")
    except OSError as exc:
        raise CustodyError(f"Écriture du consentement impossible : {chemin}") from exc
    empreinte = hacher_fichier(chemin)
    if journal is not None:
        journal.consigner(
            "consentement_enregistre",
            {
                "fichier": chemin.name,
                "sha256": empreinte,
                "identifiant_affaire": consentement.identifiant_affaire,
            },
        )
    return empreinte


# ---------------------------------------------------------------------------
#  Manifeste SHA-256 du dossier d'affaire
# ---------------------------------------------------------------------------
def _resoudre_manifeste(dossier: Path, chemin_manifeste: Path | str | None) -> Path:
    """Chemin du manifeste : celui fourni, sinon ``MANIFEST.sha256`` dans le dossier."""
    if chemin_manifeste is not None:
        return Path(chemin_manifeste)
    return dossier / _NOM_MANIFESTE


def generer_manifeste(
    dossier: Path | str,
    *,
    chemin_manifeste: Path | str | None = None,
    journal: JournalCustody | None = None,
) -> Path:
    """Génère ``MANIFEST.sha256`` (format ``sha256sum``) pour tout le dossier.

    Le manifeste liste, triés par chemin relatif POSIX, les SHA-256 de tous les
    fichiers du dossier — sauf le manifeste lui-même. Le format (``<hash>␠␠<chemin>``)
    est vérifiable par un tiers avec ``sha256sum -c MANIFEST.sha256``.

    Si un ``journal`` est fourni, l'événement est consigné **avant** le calcul des
    empreintes, afin que l'état final du journal soit bien reflété dans le manifeste.

    :raises ValidationError: si ``dossier`` n'est pas un répertoire.
    :raises CustodyError: si l'écriture du manifeste échoue.
    """
    dossier = Path(dossier)
    if not dossier.is_dir():
        raise ValidationError(f"Dossier d'affaire introuvable : {dossier}")
    cible = _resoudre_manifeste(dossier, chemin_manifeste)

    if journal is not None:
        journal.consigner("manifeste_genere", {"fichier": cible.name})

    cible_resolue = cible.resolve()
    fichiers = sorted(
        p for p in dossier.rglob("*") if p.is_file() and p.resolve() != cible_resolue
    )
    lignes = [f"{hacher_fichier(f)}  {f.relative_to(dossier).as_posix()}" for f in fichiers]
    contenu = "\n".join(lignes) + ("\n" if lignes else "")
    try:
        cible.write_text(contenu, encoding="utf-8")
    except OSError as exc:
        raise CustodyError(f"Écriture du manifeste impossible : {cible}") from exc
    _logger.info("manifeste généré", extra={"nb_fichiers": len(fichiers)})
    return cible


def verifier_manifeste(
    dossier: Path | str, chemin_manifeste: Path | str | None = None
) -> list[str]:
    """Vérifie le dossier contre son manifeste. Liste vide = intègre.

    Retourne une liste de descriptions d'anomalies (fichier manquant, empreinte
    divergente). Ne lève pas sur divergence — c'est un résultat, pas une erreur —
    mais lève si le manifeste est absent ou illisible.

    :raises ValidationError: si le manifeste est introuvable.
    :raises CustodyError: si le manifeste est illisible.
    """
    dossier = Path(dossier)
    cible = _resoudre_manifeste(dossier, chemin_manifeste)
    if not cible.is_file():
        raise ValidationError(f"Manifeste introuvable : {cible}")
    try:
        lignes = cible.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CustodyError(f"Lecture du manifeste impossible : {cible}") from exc

    anomalies: list[str] = []
    for numero, ligne in enumerate(lignes, start=1):
        if not ligne.strip():
            continue
        empreinte_attendue, separateur, rel = ligne.partition("  ")
        if not separateur:
            anomalies.append(f"Ligne {numero} du manifeste mal formée.")
            continue
        fichier = dossier / rel
        if not fichier.is_file():
            anomalies.append(f"Fichier manquant : {rel}")
            continue
        if hacher_fichier(fichier) != empreinte_attendue:
            anomalies.append(f"Empreinte divergente : {rel}")
    return anomalies
