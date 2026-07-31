"""Acquisition logique Android sans root — point clé du projet (CLAUDE.md §3, §10).

**Lecture seule sur le support source.** Toute commande passe par le
``TracedExecutor`` : chaque relevé est horodaté, sa sortie brute archivée et hachée,
et un :class:`~guardian.core.provenance.Finding` produit.

Contenu :

- Inventaire ``dumpsys``/``settings`` des **signaux forts** (§5) — services
  d'accessibilité, écouteurs de notifications, administrateurs d'appareil — plus
  l'inventaire des paquets tiers (signal moyen).
- Capture ``adb bugreport``, pull ``/sdcard``, et extraction ciblée des **APK des
  paquets impliqués dans les signaux forts** (les plus intéressants à figer).
- Assemblage complet dans :meth:`AndroidLogicalAcquirer.acquerir` (étapes lourdes
  activables/désactivables).

Honnêteté épistémique (§5) : sans root, ces relevés ne voient que ce que l'appareil
expose. Une absence de signal signifie « rien d'observable par cette méthode », pas
« appareil sain ». Les échecs de relevé sont consignés (confiance faible), jamais
masqués.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from guardian.acquisition.base import Acquirer, ResultatAcquisition
from guardian.core.custody import hacher_fichier
from guardian.core.exceptions import ValidationError
from guardian.core.provenance import (
    Confidence,
    ExecutionTracee,
    Finding,
    Reproducibility,
    Severity,
    TracedExecutor,
)
from guardian.detection.usb_watch import TypeAppareil

# Un composant Android a la forme « paquet/classe » ; un paquet est « a.b.c ».
_MOTIF_COMPOSANT = re.compile(r"[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+")
_MOTIF_PAQUET = re.compile(r"^[A-Za-z0-9_.]+$")
_PREFIXE_PAQUET = "package:"
# Un administrateur listé par « dumpsys device_policy » apparaît, selon la version
# d'Android, sous deux formes : soit un composant SEUL suivi de « : » (AOSP récent,
# p. ex. « com.pkg/.Cls: »), soit enveloppé dans « ComponentInfo{com.pkg/.Cls} ».
# Les deux sont ancrées sous l'en-tête de la section des admins actifs.
_MOTIF_LIGNE_ADMIN = re.compile(r"^([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+):$")
_MOTIF_COMPONENTINFO = re.compile(r"ComponentInfo\{([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)\}")
_MOTIF_ENTETE_ADMINS = re.compile(r"Device Admins.*:$")


def _admin_de_ligne(contenu: str) -> str | None:
    """Composant admin d'une ligne : forme nue ``composant:`` ou ``ComponentInfo{…}``.

    Retourne ``None`` pour toute autre ligne — ce qui écarte le bruit de la sortie
    (p. ex. ``… max calls/s=… max dur/s=…`` : ``calls/s`` matche « paquet/classe » mais
    n'est ni un composant isolé, ni enveloppé dans ``ComponentInfo{…}``).
    """
    nue = _MOTIF_LIGNE_ADMIN.match(contenu)
    if nue:
        return nue.group(1)
    enveloppe = _MOTIF_COMPONENTINFO.search(contenu)
    if enveloppe:
        return enveloppe.group(1)
    return None


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
    """Extrait les administrateurs d'appareil depuis ``dumpsys device_policy``.

    **Ancrage sur la section « Enabled Device Admins »** (format AOSP) : chaque admin y
    est une ligne indentée ``composant:`` (un composant seul). On n'accepte que cette
    forme stricte, ce qui écarte le **bruit** de la sortie — p. ex. une ligne de
    statistiques ``… max calls/s=… max dur/s=…`` dont ``calls/s`` et ``dur/s`` matchent
    par accident le motif ``paquet/classe`` (faux positifs observés sur appareil réel).

    Si **aucun en-tête** de section n'est reconnu (format OEM inhabituel), on se rabat
    sur la même forme stricte appliquée à toute la sortie — nettement plus sûr qu'une
    recherche globale du motif ``paquet/classe``. Dédupliqué, ordre préservé ; la sortie
    brute reste archivée pour analyse experte.
    """
    vus: dict[str, None] = {}
    dans_section = False
    entete_vue = False
    indent_entete = -1
    for ligne in sortie.splitlines():
        if not ligne.strip():
            continue
        contenu = ligne.strip()
        indent = len(ligne) - len(ligne.lstrip())
        if _MOTIF_ENTETE_ADMINS.search(contenu):
            dans_section = True
            entete_vue = True
            indent_entete = indent
            continue
        if dans_section:
            if indent <= indent_entete:  # retour au niveau de l'en-tête = fin de section
                dans_section = False
            else:
                composant = _admin_de_ligne(contenu)
                if composant is not None:
                    vus.setdefault(composant, None)
                continue
    if not entete_vue:
        # Repli : aucune section reconnue → mêmes formes strictes sur toute la sortie.
        for ligne in sortie.splitlines():
            composant = _admin_de_ligne(ligne.strip())
            if composant is not None:
                vus.setdefault(composant, None)
    return list(vus)


def _parser_paquets(sortie: str) -> list[str]:
    """Extrait les noms/chemins d'une sortie « package:… » (pm list / pm path)."""
    valeurs: list[str] = []
    for ligne in sortie.splitlines():
        ligne = ligne.strip()
        if ligne.startswith(_PREFIXE_PAQUET):
            valeur = ligne[len(_PREFIXE_PAQUET) :].strip()
            if valeur:
                valeurs.append(valeur)
    return valeurs


def _paquet_du_composant(composant: str) -> str:
    """« com.x/.Svc » → « com.x »."""
    return composant.split("/", 1)[0]


@dataclass(frozen=True)
class ReleveSignal:
    """Résultat interne d'un relevé : le Finding produit + composants impliqués."""

    finding: Finding
    composants: tuple[str, ...]


# ---------------------------------------------------------------------------
#  Acquéreur Android
# ---------------------------------------------------------------------------
class AndroidLogicalAcquirer(Acquirer):
    """Acquéreur logique Android (sans root), en lecture seule sur l'appareil.

    ``commande_adb`` est injectable pour les tests (adb simulé). ``timeout`` borne les
    commandes ``adb shell`` ; ``timeout_lourd`` les opérations longues (bugreport,
    pull). Les étapes lourdes sont activables/désactivables (utile pour des
    acquisitions ciblées ou des tests).
    """

    def __init__(
        self,
        executor: TracedExecutor,
        identifiant_appareil: str,
        *,
        commande_adb: Sequence[str] = ("adb",),
        timeout: float = 120.0,
        timeout_lourd: float = 600.0,
        dossier_artefacts: Path | str | None = None,
        avec_bugreport: bool = True,
        avec_pull_sdcard: bool = True,
        avec_apks: bool = True,
    ) -> None:
        super().__init__(executor, identifiant_appareil)
        self._commande_adb = tuple(commande_adb)
        self._timeout = timeout
        self._timeout_lourd = timeout_lourd
        self._dossier_artefacts = (
            Path(dossier_artefacts)
            if dossier_artefacts is not None
            else executor.dossier / "artefacts"
        )
        self._avec_bugreport = avec_bugreport
        self._avec_pull_sdcard = avec_pull_sdcard
        self._avec_apks = avec_apks

    @property
    def plateforme(self) -> TypeAppareil:
        return TypeAppareil.ANDROID

    # --- Primitives d'exécution --------------------------------------------
    def _adb(self, args: Sequence[str], timeout: float | None = None) -> ExecutionTracee:
        """Exécute ``adb -s <série> <args>`` (commande adb non-shell)."""
        arguments = [*self._commande_adb, "-s", self._identifiant, *args]
        return self._executor.executer(arguments, timeout=timeout or self._timeout)

    def _adb_shell(self, commande: Sequence[str]) -> ExecutionTracee:
        """Exécute ``adb -s <série> shell <commande>``."""
        return self._adb(["shell", *commande])

    # --- Constructeurs de Finding ------------------------------------------
    def _finding_liste_forte(
        self, tracee: ExecutionTracee, composants: list[str], libelle: str
    ) -> Finding:
        """Finding pour un signal fort fondé sur une liste de composants."""
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

    # --- Relevés internes (Finding + composants) ---------------------------
    def _relever_composants(
        self,
        commande: Sequence[str],
        libelle: str,
        releve: str,
        parseur: Callable[[str], list[str]],
    ) -> ReleveSignal:
        tracee = self._adb_shell(commande)
        if self._releve_non_concluant(tracee):
            return ReleveSignal(self._finding_echec(tracee, releve), ())
        composants = parseur(tracee.texte_stdout())
        finding = self._finding_liste_forte(tracee, composants, libelle)
        return ReleveSignal(finding, tuple(composants))

    def _relever_accessibilite(self) -> ReleveSignal:
        return self._relever_composants(
            ["settings", "get", "secure", "enabled_accessibility_services"],
            "service(s) d'accessibilité",
            "services d'accessibilité",
            _parser_liste_composants,
        )

    def _relever_notifications(self) -> ReleveSignal:
        return self._relever_composants(
            ["settings", "get", "secure", "enabled_notification_listeners"],
            "écouteur(s) de notifications",
            "écouteurs de notifications",
            _parser_liste_composants,
        )

    def _relever_admins(self) -> ReleveSignal:
        return self._relever_composants(
            ["dumpsys", "device_policy"],
            "composant(s) administrateur(s) d'appareil",
            "administrateurs d'appareil",
            _parser_composants_admin,
        )

    def _relever_paquets_tiers(self) -> ReleveSignal:
        tracee = self._adb_shell(["pm", "list", "packages", "-3"])
        if self._releve_non_concluant(tracee):
            return ReleveSignal(self._finding_echec(tracee, "paquets tiers"), ())
        paquets = _parser_paquets(tracee.texte_stdout())
        value = f"{len(paquets)} paquet(s) tiers installé(s) : " + ", ".join(paquets)
        finding = tracee.en_finding(
            value=value,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
        return ReleveSignal(finding, tuple(paquets))

    # --- Relevés publics (Finding seul) ------------------------------------
    def inventorier_services_accessibilite(self) -> Finding:
        """Signal FORT : services d'accessibilité activés (vecteur de surveillance)."""
        return self._relever_accessibilite().finding

    def inventorier_ecouteurs_notifications(self) -> Finding:
        """Signal FORT : écouteurs de notifications activés."""
        return self._relever_notifications().finding

    def inventorier_admins_appareil(self) -> Finding:
        """Signal FORT : administrateurs d'appareil (dumpsys device_policy)."""
        return self._relever_admins().finding

    def inventorier_paquets_tiers(self) -> Finding:
        """Signal MOYEN : inventaire des paquets tiers (pm list packages -3)."""
        return self._relever_paquets_tiers().finding

    def inventorier_signaux(self) -> list[Finding]:
        """Exécute l'ensemble des relevés d'inventaire et retourne leurs Findings."""
        return [
            self._relever_accessibilite().finding,
            self._relever_notifications().finding,
            self._relever_admins().finding,
            self._relever_paquets_tiers().finding,
        ]

    # --- Captures de fichiers ----------------------------------------------
    def capturer_bugreport(self) -> tuple[Finding, tuple[str, ...]]:
        """Capture ``adb bugreport`` dans le dossier d'artefacts, et le hache."""
        self._dossier_artefacts.mkdir(parents=True, exist_ok=True)
        cible = self._dossier_artefacts / "bugreport.zip"
        tracee = self._adb(["bugreport", str(cible)], timeout=self._timeout_lourd)
        if tracee.trace.exit_code != 0 or not cible.is_file():
            return self._finding_echec(tracee, "bugreport"), ()
        empreinte = hacher_fichier(cible)
        ref = self._rel(cible)
        finding = tracee.en_finding(
            value=f"Bugreport capturé : {ref} (sha256={empreinte[:16]}…).",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
        return finding, (ref,)

    def puller_sdcard(self) -> tuple[Finding, tuple[str, ...]]:
        """Copie ``/sdcard`` (stockage utilisateur) vers le dossier d'artefacts."""
        cible = self._dossier_artefacts / "sdcard"
        cible.mkdir(parents=True, exist_ok=True)
        tracee = self._adb(["pull", "/sdcard", str(cible)], timeout=self._timeout_lourd)
        fichiers = [p for p in cible.rglob("*") if p.is_file()]
        if tracee.trace.exit_code != 0 and not fichiers:
            return self._finding_echec(tracee, "pull /sdcard"), ()
        refs = tuple(self._rel(p) for p in fichiers)
        rel_cible = self._rel(cible)
        finding = tracee.en_finding(
            value=f"Pull /sdcard : {len(fichiers)} fichier(s) copié(s) sous {rel_cible}.",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
        return finding, refs

    def extraire_apk(self, paquet: str) -> tuple[Finding, tuple[str, ...]]:
        """Extrait l'APK d'un paquet (``pm path`` puis ``adb pull``), et le hache.

        :raises ValidationError: si le nom de paquet est mal formé.
        """
        if not _MOTIF_PAQUET.match(paquet):
            raise ValidationError(f"Nom de paquet invalide : {paquet!r}")
        tracee_path = self._adb_shell(["pm", "path", paquet])
        chemins = _parser_paquets(tracee_path.texte_stdout())
        if tracee_path.trace.exit_code != 0 or not chemins:
            return (
                tracee_path.en_finding(
                    value=f"APK du paquet {paquet} introuvable sur l'appareil.",
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    reproducibility=Reproducibility.POINT_IN_TIME,
                ),
                (),
            )
        destination = self._dossier_artefacts / "apk" / paquet
        destination.mkdir(parents=True, exist_ok=True)
        # Puller TOUS les composants (base + splits). Une application distribuée en
        # « app bundle » est répartie sur plusieurs APK : ne prendre que le premier
        # figerait une capture INCOMPLÈTE — or les splits « config.* » portent le code
        # natif (.so), souvent l'essentiel d'un malware (essais terrain P1-D). Chaque
        # pull est tracé individuellement par le TracedExecutor.
        nb_echecs = 0
        tracee_pull: ExecutionTracee | None = None
        for chemin in chemins:
            tracee_pull = self._adb(
                ["pull", chemin, str(destination)], timeout=self._timeout_lourd
            )
            if tracee_pull.trace.exit_code != 0:
                nb_echecs += 1
        fichiers = [p for p in destination.rglob("*") if p.is_file()]
        if tracee_pull is None or not fichiers:
            return self._finding_echec(tracee_pull or tracee_path, f"pull APK {paquet}"), ()
        refs = tuple(self._rel(p) for p in fichiers)
        empreintes = ", ".join(f"{p.name}={hacher_fichier(p)[:16]}…" for p in fichiers)
        complet = nb_echecs == 0
        if complet:
            detail = f"{len(fichiers)} APK ({empreintes})"
        else:
            detail = (
                f"{len(fichiers)} APK récupéré(s) sur {len(chemins)} — "
                f"{nb_echecs} composant(s) NON récupéré(s) ({empreintes})"
            )
        finding = tracee_pull.en_finding(
            value=f"APK de {paquet} extrait : {detail}.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH if complet else Confidence.LOW,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
        return finding, refs

    # --- Orchestration -----------------------------------------------------
    def acquerir(self) -> ResultatAcquisition:
        """Acquisition complète : inventaire, bugreport, pull /sdcard, APK suspects.

        Les APK extraits sont ceux des paquets **impliqués dans les signaux forts**
        (accessibilité, notifications, administrateurs). ``complete`` vaut vrai si
        aucun relevé/capture n'a échoué (aucun Finding en confiance faible).
        """
        self._consigner_debut()

        r_acces = self._relever_accessibilite()
        r_notif = self._relever_notifications()
        r_admin = self._relever_admins()
        r_tiers = self._relever_paquets_tiers()
        forts = (r_acces, r_notif, r_admin)

        findings: list[Finding] = [r.finding for r in (*forts, r_tiers)]
        artefacts: list[str] = [f.raw_output_ref for f in findings]

        suspects = sorted({_paquet_du_composant(c) for r in forts for c in r.composants})

        if self._avec_bugreport:
            finding, refs = self.capturer_bugreport()
            findings.append(finding)
            artefacts.extend(refs)
        if self._avec_pull_sdcard:
            finding, refs = self.puller_sdcard()
            findings.append(finding)
            artefacts.extend(refs)
        if self._avec_apks:
            for paquet in suspects:
                finding, refs = self.extraire_apk(paquet)
                findings.append(finding)
                artefacts.extend(refs)

        complete = all(f.confidence is not Confidence.LOW for f in findings)
        resultat = ResultatAcquisition(
            plateforme=self.plateforme,
            identifiant_appareil=self.identifiant,
            findings=tuple(findings),
            artefacts=tuple(artefacts),
            complete=complete,
        )
        self._consigner_fin(resultat)
        return resultat
