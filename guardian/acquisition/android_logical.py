"""Acquisition logique Android sans root — point clé du projet (CLAUDE.md §3, §10).

**Lecture seule sur le support source.** Toute commande passe par le
``TracedExecutor`` : chaque relevé est horodaté, sa sortie brute archivée et hachée,
et un :class:`~guardian.core.provenance.Finding` produit.

Ce module est construit en deux temps :

- **Sous-lot 2 (ce fichier)** : inventaire ``dumpsys``/``settings`` des **signaux
  forts** (§5) — services d'accessibilité, écouteurs de notifications,
  administrateurs d'appareil — plus l'inventaire des paquets tiers (signal moyen).
- **Sous-lot 3 (à venir)** : ``adb bugreport``, pull ``/sdcard``, extraction des APK
  suspects, et assemblage complet de :meth:`AndroidLogicalAcquirer.acquerir`.

Honnêteté épistémique (§5) : sans root, ces relevés ne voient que ce que l'appareil
expose. Une absence de signal signifie « rien d'observable par cette méthode », pas
« appareil sain ». Les échecs de relevé sont consignés (confiance faible), jamais
masqués.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from guardian.acquisition.base import Acquirer, ResultatAcquisition
from guardian.core.provenance import (
    Confidence,
    ExecutionTracee,
    Finding,
    Reproducibility,
    Severity,
    TracedExecutor,
)
from guardian.detection.usb_watch import TypeAppareil

# Un composant Android a la forme « paquet/classe ».
_MOTIF_COMPOSANT = re.compile(r"[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+")
_PREFIXE_PAQUET = "package:"


# ---------------------------------------------------------------------------
#  Parseurs purs
# ---------------------------------------------------------------------------
def _parser_liste_composants(sortie: str) -> list[str]:
    """Parse une valeur ``settings`` : liste de composants séparés par « : ».

    ``settings get`` renvoie ``null`` (ou vide) quand rien n'est configuré.
    """
    valeur = sortie.strip()
    if not valeur or valeur.lower() == "null":
        return []
    return [c.strip() for c in valeur.split(":") if c.strip()]


def _parser_composants_admin(sortie: str) -> list[str]:
    """Extrait les composants candidats d'administrateur depuis ``dumpsys device_policy``.

    Heuristique (dédupliquée, ordre préservé) : la sortie de ``dumpsys device_policy``
    n'a pas de format stable ; on relève les composants ``paquet/classe``. La sortie
    brute reste archivée pour analyse experte.
    """
    vus: dict[str, None] = {}
    for composant in _MOTIF_COMPOSANT.findall(sortie):
        vus.setdefault(composant, None)
    return list(vus)


def _parser_paquets(sortie: str) -> list[str]:
    """Extrait les noms de paquets d'une sortie ``pm list packages`` (« package:… »)."""
    paquets: list[str] = []
    for ligne in sortie.splitlines():
        ligne = ligne.strip()
        if ligne.startswith(_PREFIXE_PAQUET):
            nom = ligne[len(_PREFIXE_PAQUET) :].strip()
            if nom:
                paquets.append(nom)
    return paquets


# ---------------------------------------------------------------------------
#  Acquéreur Android
# ---------------------------------------------------------------------------
class AndroidLogicalAcquirer(Acquirer):
    """Acquéreur logique Android (sans root), en lecture seule sur l'appareil.

    ``commande_adb`` est injectable pour les tests (adb simulé). Le ``timeout``
    borne chaque commande ``adb shell``.
    """

    def __init__(
        self,
        executor: TracedExecutor,
        identifiant_appareil: str,
        *,
        commande_adb: Sequence[str] = ("adb",),
        timeout: float = 120.0,
    ) -> None:
        super().__init__(executor, identifiant_appareil)
        self._commande_adb = tuple(commande_adb)
        self._timeout = timeout

    @property
    def plateforme(self) -> TypeAppareil:
        return TypeAppareil.ANDROID

    def _adb_shell(self, commande: Sequence[str]) -> ExecutionTracee:
        """Exécute ``adb -s <série> shell <commande>`` via la porte unique."""
        arguments = [
            *self._commande_adb,
            "-s",
            self._identifiant,
            "shell",
            *commande,
        ]
        return self._executor.executer(arguments, timeout=self._timeout)

    def _finding_echec(self, tracee: ExecutionTracee, releve: str) -> Finding:
        """Finding pour un relevé en échec : confiance faible, sortie brute conservée."""
        return tracee.en_finding(
            value=(
                f"Relevé « {releve} » en échec (code {tracee.trace.exit_code}) — "
                "voir la sortie brute ; résultat non concluant."
            ),
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )

    def _finding_liste_forte(
        self, tracee: ExecutionTracee, composants: list[str], libelle: str
    ) -> Finding:
        """Construit un Finding pour un signal fort fondé sur une liste de composants."""
        if composants:
            value = f"{len(composants)} {libelle} activé(s) : " + ", ".join(composants)
            severity = Severity.STRONG
        else:
            value = f"Aucun {libelle} activé (parmi ceux observables sans root)."
            severity = Severity.INFO
        return tracee.en_finding(
            value=value,
            severity=severity,
            confidence=Confidence.HIGH,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )

    def inventorier_services_accessibilite(self) -> Finding:
        """Signal FORT : services d'accessibilité activés (vecteur de surveillance)."""
        tracee = self._adb_shell(
            ["settings", "get", "secure", "enabled_accessibility_services"]
        )
        if tracee.trace.exit_code != 0:
            return self._finding_echec(tracee, "services d'accessibilité")
        composants = _parser_liste_composants(tracee.texte_stdout())
        return self._finding_liste_forte(tracee, composants, "service(s) d'accessibilité")

    def inventorier_ecouteurs_notifications(self) -> Finding:
        """Signal FORT : écouteurs de notifications activés."""
        tracee = self._adb_shell(
            ["settings", "get", "secure", "enabled_notification_listeners"]
        )
        if tracee.trace.exit_code != 0:
            return self._finding_echec(tracee, "écouteurs de notifications")
        composants = _parser_liste_composants(tracee.texte_stdout())
        return self._finding_liste_forte(tracee, composants, "écouteur(s) de notifications")

    def inventorier_admins_appareil(self) -> Finding:
        """Signal FORT : administrateurs d'appareil (dumpsys device_policy)."""
        tracee = self._adb_shell(["dumpsys", "device_policy"])
        if tracee.trace.exit_code != 0:
            return self._finding_echec(tracee, "administrateurs d'appareil")
        composants = _parser_composants_admin(tracee.texte_stdout())
        return self._finding_liste_forte(
            tracee, composants, "composant(s) administrateur(s) d'appareil"
        )

    def inventorier_paquets_tiers(self) -> Finding:
        """Signal MOYEN : inventaire des paquets tiers installés (pm list packages -3)."""
        tracee = self._adb_shell(["pm", "list", "packages", "-3"])
        if tracee.trace.exit_code != 0:
            return self._finding_echec(tracee, "paquets tiers")
        paquets = _parser_paquets(tracee.texte_stdout())
        value = f"{len(paquets)} paquet(s) tiers installé(s) : " + ", ".join(paquets)
        return tracee.en_finding(
            value=value,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )

    def inventorier_signaux(self) -> list[Finding]:
        """Exécute l'ensemble des relevés d'inventaire et retourne leurs Findings."""
        return [
            self.inventorier_services_accessibilite(),
            self.inventorier_ecouteurs_notifications(),
            self.inventorier_admins_appareil(),
            self.inventorier_paquets_tiers(),
        ]

    def acquerir(self) -> ResultatAcquisition:
        """Acquisition (sous-lot 2 : inventaire des signaux).

        ``complete`` vaut vrai si aucun relevé n'a échoué (confiance faible). Le
        sous-lot 3 étendra cette méthode (bugreport, pull /sdcard, APK suspects).
        """
        self._consigner_debut()
        findings = self.inventorier_signaux()
        artefacts = tuple(f.raw_output_ref for f in findings)
        complete = all(f.confidence is not Confidence.LOW for f in findings)
        resultat = ResultatAcquisition(
            plateforme=self.plateforme,
            identifiant_appareil=self.identifiant,
            findings=tuple(findings),
            artefacts=artefacts,
            complete=complete,
        )
        self._consigner_fin(resultat)
        return resultat
