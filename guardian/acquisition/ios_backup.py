"""Acquisition iOS : sauvegarde chiffrée via idevicebackup2 (CLAUDE.md §10, Étape 4).

**Point sensible — le mot de passe de sauvegarde.** Il ne doit JAMAIS apparaître en
clair (logs, custody, rapports, **ni arguments de commande**). Il est :

- fourni à la demande par un *callback* (:data:`FournisseurMotDePasse`) — jamais
  stocké sur l'objet ni dans un attribut persistant ;
- transmis à ``idevicebackup2`` via **stdin** (``entree``), donc **jamais** placé
  dans ``args`` : le ``TracedExecutor`` n'archive ni ne journalise stdin ;
- consommé puis oublié (aucune conservation).

**Garde-fou lecture seule (§2).** Par défaut, AUCUNE modification de l'appareil.
*Activer* le chiffrement de sauvegarde écrit un réglage sur le téléphone (et peut
alerter un agresseur — SECURITY.md §3.1) : c'est donc un **opt-in explicite**
(``autoriser_activation_chiffrement=True``), jamais silencieux. Sinon, on se contente
de **détecter** l'état du chiffrement (lecture seule) et de sauvegarder tel quel.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from enum import StrEnum

from guardian.acquisition.base import Acquirer, ResultatAcquisition
from guardian.core.exceptions import AcquisitionError
from guardian.core.provenance import (
    Confidence,
    ExecutionTracee,
    Finding,
    Reproducibility,
    Severity,
    TracedExecutor,
)
from guardian.detection.usb_watch import TypeAppareil

# Un callback qui retourne le mot de passe de sauvegarde au moment voulu.
# Il n'est appelé que si nécessaire (activation du chiffrement) et son résultat
# n'est jamais conservé ni journalisé.
FournisseurMotDePasse = Callable[[], str]


class EtatChiffrement(StrEnum):
    """État du chiffrement de sauvegarde de l'appareil (lecture seule)."""

    ACTIF = "ACTIF"  # les sauvegardes seront chiffrées (mot de passe déjà défini)
    INACTIF = "INACTIF"  # les sauvegardes seront en clair
    INCONNU = "INCONNU"  # état non déterminable (outil en échec, réponse inattendue)


class IOSBackupAcquirer(Acquirer):
    """Acquéreur de sauvegarde iOS, en lecture seule par défaut sur l'appareil.

    ``commande_idevicebackup2`` / ``commande_ideviceinfo`` sont injectables (outils
    simulés en test). ``fournisseur_mot_de_passe`` n'est requis que pour activer le
    chiffrement (opt-in).
    """

    def __init__(
        self,
        executor: TracedExecutor,
        udid: str,
        *,
        commande_idevicebackup2: Sequence[str] = ("idevicebackup2",),
        commande_ideviceinfo: Sequence[str] = ("ideviceinfo",),
        fournisseur_mot_de_passe: FournisseurMotDePasse | None = None,
        timeout: float = 60.0,
        timeout_lourd: float = 1800.0,
        autoriser_activation_chiffrement: bool = False,
    ) -> None:
        super().__init__(executor, udid)
        self._cmd_backup = tuple(commande_idevicebackup2)
        self._cmd_info = tuple(commande_ideviceinfo)
        self._fournisseur_mdp = fournisseur_mot_de_passe
        self._timeout = timeout
        self._timeout_lourd = timeout_lourd
        self._autoriser_activation = autoriser_activation_chiffrement

    @property
    def plateforme(self) -> TypeAppareil:
        return TypeAppareil.IOS

    # --- Primitives d'exécution --------------------------------------------
    def _idevicebackup2(
        self,
        args: Sequence[str],
        *,
        entree: bytes | None = None,
        timeout: float | None = None,
    ) -> ExecutionTracee:
        """Exécute ``idevicebackup2 -u <udid> <args>``.

        ``entree`` (stdin) sert au passage du mot de passe : elle n'est ni archivée
        ni journalisée par le ``TracedExecutor``, contrairement aux ``args``.
        """
        commande = [*self._cmd_backup, "-u", self._identifiant, *args]
        return self._executor.executer(
            commande, entree=entree, timeout=timeout or self._timeout
        )

    # --- Détection d'état (lecture seule) ----------------------------------
    def detecter_etat_chiffrement(self) -> tuple[EtatChiffrement, Finding]:
        """Détecte si les sauvegardes seront chiffrées, **sans modifier l'appareil**.

        Interroge ``ideviceinfo -q com.apple.mobile.backup -k WillEncrypt``.
        """
        tracee = self._executor.executer(
            [
                *self._cmd_info,
                "-u",
                self._identifiant,
                "-q",
                "com.apple.mobile.backup",
                "-k",
                "WillEncrypt",
            ],
            timeout=self._timeout,
        )
        if tracee.trace.exit_code != 0:
            etat = EtatChiffrement.INCONNU
        else:
            reponse = tracee.texte_stdout().strip().lower()
            if reponse in ("true", "yes", "1"):
                etat = EtatChiffrement.ACTIF
            elif reponse in ("false", "no", "0"):
                etat = EtatChiffrement.INACTIF
            else:
                etat = EtatChiffrement.INCONNU

        libelles = {
            EtatChiffrement.ACTIF: (
                "Chiffrement de sauvegarde ACTIF : la sauvegarde sera chiffrée."
            ),
            EtatChiffrement.INACTIF: (
                "Chiffrement de sauvegarde INACTIF : la sauvegarde serait EN CLAIR et "
                "capturerait moins de données (trousseau, santé…)."
            ),
            EtatChiffrement.INCONNU: "État du chiffrement de sauvegarde indéterminé.",
        }
        confiance = Confidence.LOW if etat is EtatChiffrement.INCONNU else Confidence.HIGH
        finding = tracee.en_finding(
            value=libelles[etat],
            severity=Severity.INFO,
            confidence=confiance,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )
        return etat, finding

    # --- Activation du chiffrement (opt-in, écrit sur l'appareil) -----------
    def activer_chiffrement(self) -> Finding:
        """Active le chiffrement de sauvegarde. **Modifie l'appareil** — opt-in requis.

        Le mot de passe est obtenu du fournisseur et transmis via stdin (jamais en
        argument, jamais journalisé). La custody consigne l'activation **sans** le
        mot de passe.

        :raises AcquisitionError: si l'opt-in n'a pas été donné ou si aucun
            fournisseur de mot de passe n'est configuré.
        """
        if not self._autoriser_activation:
            raise AcquisitionError(
                "Activation du chiffrement refusée : elle modifie l'appareil "
                "(garde-fou lecture seule §2). Opt-in explicite requis "
                "(autoriser_activation_chiffrement=True) après consentement éclairé."
            )
        if self._fournisseur_mdp is None:
            raise AcquisitionError(
                "Aucun fournisseur de mot de passe configuré pour activer le chiffrement."
            )
        mot_de_passe = self._fournisseur_mdp()
        # idevicebackup2 « encryption on » demande deux fois le nouveau mot de passe.
        entree = f"{mot_de_passe}\n{mot_de_passe}\n".encode()
        # Le mot de passe local est effacé de la portée dès l'appel construit.
        del mot_de_passe
        tracee = self._idevicebackup2(
            ["encryption", "on"], entree=entree, timeout=self._timeout
        )
        self._executor.journal.consigner(
            "chiffrement_sauvegarde_active",
            {"methode": "idevicebackup2 encryption on", "mot_de_passe_journalise": False},
        )
        reussi = tracee.trace.exit_code == 0
        return tracee.en_finding(
            value=(
                "Chiffrement de sauvegarde activé (réglage modifié sur l'appareil, "
                "avec consentement)."
                if reussi
                else f"Échec de l'activation du chiffrement (code {tracee.trace.exit_code})."
            ),
            severity=Severity.INFO,
            confidence=Confidence.HIGH if reussi else Confidence.LOW,
            reproducibility=Reproducibility.POINT_IN_TIME,
        )

    # --- Orchestration (complétée au sous-lot 4.2) -------------------------
    def acquerir(self) -> ResultatAcquisition:
        """Acquisition iOS (sous-lot 4.1 : détection d'état seule).

        Détecte l'état du chiffrement sans modifier l'appareil. La sauvegarde
        proprement dite (``idevicebackup2 backup``) est ajoutée au sous-lot 4.2 ;
        ``complete`` vaut donc faux à ce stade.
        """
        self._consigner_debut()
        _, finding_etat = self.detecter_etat_chiffrement()
        resultat = ResultatAcquisition(
            plateforme=self.plateforme,
            identifiant_appareil=self.identifiant,
            findings=(finding_etat,),
            artefacts=(finding_etat.raw_output_ref,),
            complete=False,
        )
        self._consigner_fin(resultat)
        return resultat
