"""Détection USB des appareils iOS et Android + diagnostic des prérequis Android.

Premier module « métier » consommant le socle : toute commande de détection passe
par le :class:`~guardian.core.provenance.TracedExecutor` (porte unique, §6). En
effet, l'**identité de l'appareil** et l'**instant de connexion** sont pertinents
pour la chaîne de custody : la détection est donc tracée, horodatée et consignée.

Deux niveaux, comme pour ``core.environment`` :

- **Disponibilité de l'outil** : ``shutil.which`` (sans exécution). Si ``adb`` ou
  ``idevice_id`` manque, la plateforme concernée est signalée indisponible, sans
  planter — l'autre plateforme reste détectable.
- **Détection effective** : exécution tracée de ``adb devices`` / ``idevice_id -l``.

Les parseurs (``_parser_adb_devices``, ``_parser_idevice_id``) sont des fonctions
pures, testées indépendamment de tout sous-processus.
"""

from __future__ import annotations

import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from guardian.core.logging_conf import obtenir_logger
from guardian.core.provenance import ExecutionTracee, TracedExecutor

_logger = obtenir_logger("detection.usb")

_COMMANDE_IOS: tuple[str, ...] = ("idevice_id", "-l")
_COMMANDE_ANDROID: tuple[str, ...] = ("adb", "devices")
_ENTETE_ADB = "list of devices attached"


class TypeAppareil(StrEnum):
    """Plateforme d'un appareil détecté."""

    IOS = "IOS"
    ANDROID = "ANDROID"


class EtatAppareil(StrEnum):
    """État d'exploitabilité d'un appareil détecté."""

    PRET = "PRET"  # détecté et exploitable
    NON_AUTORISE = "NON_AUTORISE"  # Android : clé RSA de débogage non acceptée
    HORS_LIGNE = "HORS_LIGNE"  # Android : « offline »
    SANS_PERMISSION = "SANS_PERMISSION"  # Android : « no permissions » (udev/plugdev)
    INCONNU = "INCONNU"  # état rapporté mais non reconnu


@dataclass(frozen=True)
class AppareilDetecte:
    """Un appareil vu sur le bus USB, avec son état et la trace de sa détection."""

    type: TypeAppareil
    identifiant: str  # UDID (iOS) ou numéro de série (Android)
    etat: EtatAppareil
    detail: str
    finding_id: str  # identifiant de la commande tracée ayant produit la détection


@dataclass(frozen=True)
class DetectionPlateforme:
    """Résultat de détection pour une plateforme donnée."""

    plateforme: TypeAppareil
    outil_disponible: bool
    appareils: tuple[AppareilDetecte, ...]
    diagnostics: tuple[str, ...]


@dataclass(frozen=True)
class ResultatDetection:
    """Résultat combiné iOS + Android d'une passe de détection."""

    ios: DetectionPlateforme
    android: DetectionPlateforme

    def tous_les_appareils(self) -> tuple[AppareilDetecte, ...]:
        return self.ios.appareils + self.android.appareils

    def appareils_prets(self) -> tuple[AppareilDetecte, ...]:
        return tuple(a for a in self.tous_les_appareils() if a.etat is EtatAppareil.PRET)

    def tous_les_diagnostics(self) -> tuple[str, ...]:
        return self.ios.diagnostics + self.android.diagnostics

    def resume(self) -> str:
        """Synthèse lisible par l'opérateur."""
        lignes = ["Détection USB", "-" * 32]
        appareils = self.tous_les_appareils()
        if not appareils:
            lignes.append("Aucun appareil détecté.")
        for a in appareils:
            lignes.append(f" • [{a.type.value}] {a.identifiant} — {a.etat.value}")
        diagnostics = self.tous_les_diagnostics()
        if diagnostics:
            lignes.append("Diagnostic :")
            lignes.extend(f"   - {d}" for d in diagnostics)
        return "\n".join(lignes)


# ---------------------------------------------------------------------------
#  Parseurs purs (testables sans sous-processus)
# ---------------------------------------------------------------------------
def _parser_idevice_id(sortie: str) -> list[str]:
    """Extrait les UDID de la sortie de ``idevice_id -l`` (un UDID par ligne)."""
    return [ligne.strip() for ligne in sortie.splitlines() if ligne.strip()]


def _parser_adb_devices(sortie: str) -> list[tuple[str, str]]:
    """Extrait les paires (série, état brut) de la sortie de ``adb devices``.

    Ignore l'en-tête « List of devices attached » et les lignes de service du démon
    (préfixées par « * »).
    """
    paires: list[tuple[str, str]] = []
    for ligne in sortie.splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("*"):
            continue
        if ligne.lower() == _ENTETE_ADB:
            continue
        # « série <TAB|espaces> état [complément] » → on coupe au premier blanc.
        morceaux = ligne.split(None, 1)
        if len(morceaux) != 2:
            continue
        serie, etat_brut = morceaux
        paires.append((serie, etat_brut.strip()))
    return paires


def _etat_android(etat_brut: str) -> EtatAppareil:
    """Traduit l'état textuel d'``adb devices`` en :class:`EtatAppareil`."""
    brut = etat_brut.lower()
    if brut == "device":
        return EtatAppareil.PRET
    if brut == "unauthorized":
        return EtatAppareil.NON_AUTORISE
    if brut == "offline":
        return EtatAppareil.HORS_LIGNE
    if "no permission" in brut:
        return EtatAppareil.SANS_PERMISSION
    return EtatAppareil.INCONNU


_DETAIL_ANDROID: dict[EtatAppareil, str] = {
    EtatAppareil.PRET: "Appareil autorisé et prêt pour l'acquisition.",
    EtatAppareil.NON_AUTORISE: (
        "Détecté mais non autorisé : accepter « Autoriser le débogage USB » sur le "
        "téléphone (cocher « Toujours autoriser depuis cet ordinateur »)."
    ),
    EtatAppareil.HORS_LIGNE: (
        "Appareil hors-ligne : rebrancher le câble, déverrouiller l'écran, puis relancer."
    ),
    EtatAppareil.SANS_PERMISSION: (
        "Permissions USB insuffisantes côté hôte (règles udev / appartenance au "
        "groupe plugdev sous Linux)."
    ),
    EtatAppareil.INCONNU: "État non reconnu — inspecter la sortie brute d'adb.",
}


# ---------------------------------------------------------------------------
#  Détecteur
# ---------------------------------------------------------------------------
class DetecteurUSB:
    """Détecte les appareils iOS/Android via le ``TracedExecutor`` (porte unique).

    Les commandes sont injectables pour faciliter les tests (outils simulés). Le
    ``timeout`` borne chaque exécution afin qu'un outil bloqué ne fige pas la veille.
    """

    def __init__(
        self,
        executor: TracedExecutor,
        *,
        commande_ios: Sequence[str] = _COMMANDE_IOS,
        commande_android: Sequence[str] = _COMMANDE_ANDROID,
        timeout: float = 15.0,
    ) -> None:
        self._executor = executor
        self._commande_ios = tuple(commande_ios)
        self._commande_android = tuple(commande_android)
        self._timeout = timeout

    def _executer(self, commande: tuple[str, ...]) -> ExecutionTracee:
        return self._executor.executer(list(commande), timeout=self._timeout)

    def detecter_ios(self) -> DetectionPlateforme:
        """Liste les appareils iOS via ``idevice_id -l`` (si l'outil est présent)."""
        binaire = self._commande_ios[0]
        if shutil.which(binaire) is None:
            return DetectionPlateforme(
                TypeAppareil.IOS,
                False,
                (),
                (f"« {binaire} » indisponible : installer libimobiledevice-utils.",),
            )
        tracee = self._executer(self._commande_ios)
        udids = _parser_idevice_id(tracee.texte_stdout())
        appareils = tuple(
            AppareilDetecte(
                type=TypeAppareil.IOS,
                identifiant=udid,
                etat=EtatAppareil.PRET,
                detail=(
                    "Appareil iOS détecté. L'appairage/confiance (« Faire confiance à "
                    "cet ordinateur ») sera vérifié à l'acquisition."
                ),
                finding_id=tracee.finding_id,
            )
            for udid in udids
        )
        diagnostics: tuple[str, ...] = ()
        if not appareils:
            diagnostics = (
                "Aucun appareil iOS. Vérifier : câble data, écran déverrouillé, et "
                "invite « Faire confiance à cet ordinateur » acceptée sur le téléphone.",
            )
        return DetectionPlateforme(TypeAppareil.IOS, True, appareils, diagnostics)

    def detecter_android(self) -> DetectionPlateforme:
        """Liste les appareils Android via ``adb devices`` et diagnostique l'état."""
        binaire = self._commande_android[0]
        if shutil.which(binaire) is None:
            return DetectionPlateforme(
                TypeAppareil.ANDROID,
                False,
                (),
                (f"« {binaire} » indisponible : installer android-tools-adb.",),
            )
        tracee = self._executer(self._commande_android)
        appareils = tuple(
            AppareilDetecte(
                type=TypeAppareil.ANDROID,
                identifiant=serie,
                etat=(etat := _etat_android(etat_brut)),
                detail=_DETAIL_ANDROID[etat],
                finding_id=tracee.finding_id,
            )
            for serie, etat_brut in _parser_adb_devices(tracee.texte_stdout())
        )
        return DetectionPlateforme(
            TypeAppareil.ANDROID, True, appareils, _diagnostics_android(appareils)
        )

    def detecter(self) -> ResultatDetection:
        """Passe complète iOS + Android. Consigne les appareils vus dans la custody."""
        resultat = ResultatDetection(self.detecter_ios(), self.detecter_android())
        self._executor.journal.consigner(
            "appareils_detectes",
            {
                "appareils": [
                    {
                        "type": a.type.value,
                        "identifiant": a.identifiant,
                        "etat": a.etat.value,
                    }
                    for a in resultat.tous_les_appareils()
                ]
            },
        )
        _logger.info(
            "détection USB effectuée",
            extra={"nb_appareils": len(resultat.tous_les_appareils())},
        )
        return resultat


def _diagnostics_android(appareils: tuple[AppareilDetecte, ...]) -> tuple[str, ...]:
    """Construit les conseils opérateur à partir de l'état des appareils Android."""
    if not appareils:
        return (
            "Aucun appareil Android détecté. Vérifier : câble USB de données (pas "
            "seulement de charge), débogage USB activé (Options développeur), écran "
            "déverrouillé.",
        )
    messages: list[str] = []
    for a in appareils:
        if a.etat is not EtatAppareil.PRET:
            messages.append(f"{a.identifiant} : {a.detail}")
    return tuple(messages)
