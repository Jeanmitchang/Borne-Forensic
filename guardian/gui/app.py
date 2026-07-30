"""Interface graphique cockpit (Étape 9.2) — fine couche PyQt6 sur l'orchestrateur.

**Aucune logique métier ici** : tout passe par :class:`guardian.affaire.Affaire`
(déjà testée hors UI). Cette couche se limite à saisir le contexte d'affaire,
déclencher les phases, et afficher la progression et la synthèse.

100 % hors-ligne, style dense pour un opérateur expert (CLAUDE.md §3). Les phases
longues (acquisition, analyse) s'exécutent dans un :class:`Travailleur` (QThread)
pour ne pas figer l'interface.

PyQt6 est une dépendance **optionnelle** (extra ``[gui]``) : ce module n'est importé
que lorsqu'on lance réellement l'interface.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from guardian.acquisition.android_logical import AndroidLogicalAcquirer
from guardian.acquisition.ios_backup import IOSBackupAcquirer
from guardian.affaire import Affaire
from guardian.analysis.correlator import SyntheseCorrelation
from guardian.analysis.mvt_runner import MVTAndroidRunner, MVTIOSRunner
from guardian.core.custody import Consentement
from guardian.core.exceptions import GuardianError
from guardian.detection.usb_watch import TypeAppareil


class Travailleur(QThread):
    """Exécute une fonction longue en arrière-plan et remonte progrès/résultat/erreur.

    La fonction reçoit un callback ``log(str)`` pour tracer sa progression.
    """

    progres = pyqtSignal(str)
    termine = pyqtSignal(object)
    echoue = pyqtSignal(str)

    def __init__(self, fonction: Callable[[Callable[[str], None]], object]) -> None:
        super().__init__()
        self._fonction = fonction

    def run(self) -> None:
        try:
            resultat = self._fonction(self.progres.emit)
        except Exception as exc:  # remonté à l'UI (échouer bruyamment, pas planter)
            self.echoue.emit(str(exc))
            return
        self.termine.emit(resultat)


class FenetrePrincipale(QMainWindow):
    """Fenêtre cockpit : ouverture d'affaire, détection, pipeline, rapport."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("guardian — station d'analyse forensic (hors-ligne)")
        self.affaire: Affaire | None = None
        self._travailleur: Travailleur | None = None

        self._champ_dossier = QLineEdit()
        self._champ_identifiant = QLineEdit()
        self._champ_operateur = QLineEdit()
        self._champ_proprietaire = QLineEdit()
        self._champ_description = QLineEdit()
        self._champ_portee = QLineEdit()

        self._combo_type = QComboBox()
        self._combo_type.addItems([TypeAppareil.ANDROID.value, TypeAppareil.IOS.value])
        self._champ_appareil = QLineEdit()
        self._champ_appareil.setPlaceholderText("série adb / UDID iOS")

        self._bouton_ouvrir = QPushButton("Ouvrir l'affaire")
        self._bouton_detecter = QPushButton("Détecter les appareils")
        self._bouton_pipeline = QPushButton("Acquisition + analyse")
        self._bouton_rapport = QPushButton("Générer le rapport")
        self._bouton_detecter.setEnabled(False)
        self._bouton_pipeline.setEnabled(False)
        self._bouton_rapport.setEnabled(False)

        self._etiquette_niveau = QLabel("Niveau : —")
        self._journal = QPlainTextEdit()
        self._journal.setReadOnly(True)

        self._bouton_ouvrir.clicked.connect(self._ouvrir_affaire)
        self._bouton_detecter.clicked.connect(self._detecter)
        self._bouton_pipeline.clicked.connect(self._lancer_pipeline)
        self._bouton_rapport.clicked.connect(self._generer_rapport)

        self.setCentralWidget(self._construire_ui())

    # --- Construction de l'UI ----------------------------------------------
    def _construire_ui(self) -> QWidget:
        formulaire = QFormLayout()
        formulaire.addRow("Dossier d'affaire", self._champ_dossier)
        formulaire.addRow("Identifiant d'affaire", self._champ_identifiant)
        formulaire.addRow("Opérateur", self._champ_operateur)
        formulaire.addRow("Propriétaire du support", self._champ_proprietaire)
        formulaire.addRow("Description du support", self._champ_description)
        formulaire.addRow("Portée / consentement", self._champ_portee)

        ligne_appareil = QHBoxLayout()
        ligne_appareil.addWidget(self._combo_type)
        ligne_appareil.addWidget(self._champ_appareil)

        boutons = QHBoxLayout()
        for bouton in (
            self._bouton_ouvrir,
            self._bouton_detecter,
            self._bouton_pipeline,
            self._bouton_rapport,
        ):
            boutons.addWidget(bouton)

        disposition = QVBoxLayout()
        disposition.addLayout(formulaire)
        disposition.addLayout(ligne_appareil)
        disposition.addLayout(boutons)
        disposition.addWidget(self._etiquette_niveau)
        disposition.addWidget(self._journal, stretch=1)

        central = QWidget()
        central.setLayout(disposition)
        return central

    # --- Utilitaires -------------------------------------------------------
    def _journaliser(self, texte: str) -> None:
        self._journal.appendPlainText(texte)

    def _erreur(self, message: str) -> None:
        self._journaliser(f"ERREUR : {message}")
        QMessageBox.critical(self, "Erreur", message)

    def _pipeline_en_cours(self, en_cours: bool) -> None:
        self._bouton_pipeline.setEnabled(not en_cours and self.affaire is not None)
        self._bouton_detecter.setEnabled(not en_cours and self.affaire is not None)

    # --- Handlers ----------------------------------------------------------
    def _ouvrir_affaire(self) -> None:
        try:
            consentement = Consentement(
                identifiant_affaire=self._champ_identifiant.text().strip(),
                proprietaire_support=self._champ_proprietaire.text().strip(),
                operateur=self._champ_operateur.text().strip(),
                description_support=self._champ_description.text().strip(),
                portee=self._champ_portee.text().strip(),
            )
            self.affaire = Affaire.ouvrir(
                self._champ_dossier.text().strip(),
                identifiant_affaire=consentement.identifiant_affaire,
                operateur=consentement.operateur,
                consentement=consentement,
            )
        except (GuardianError, OSError) as exc:
            self._erreur(f"Ouverture d'affaire impossible : {exc}")
            return
        self._journaliser(
            f"Affaire {self.affaire.identifiant_affaire} ouverte dans {self.affaire.dossier}."
        )
        self._bouton_detecter.setEnabled(True)
        self._bouton_pipeline.setEnabled(True)

    def _detecter(self) -> None:
        if self.affaire is None:
            return
        try:
            resultat = self.affaire.detecter()
        except GuardianError as exc:
            self._erreur(f"Détection impossible : {exc}")
            return
        self._journaliser(resultat.resume())
        prets = resultat.appareils_prets()
        if prets:
            self._combo_type.setCurrentText(prets[0].type.value)
            self._champ_appareil.setText(prets[0].identifiant)

    def _lancer_pipeline(self) -> None:
        if self.affaire is None:
            return
        affaire = self.affaire
        type_appareil = self._combo_type.currentText()
        identifiant = self._champ_appareil.text().strip()
        if not identifiant:
            self._erreur("Renseigner l'identifiant de l'appareil.")
            return

        def tache(log: Callable[[str], None]) -> object:
            log("Acquisition en cours…")
            if type_appareil == TypeAppareil.ANDROID.value:
                acq = AndroidLogicalAcquirer(affaire.executor, identifiant)
                log(affaire.acquerir(acq).resume())
                bugreport = affaire.dossier / "artefacts" / "bugreport.zip"
                if bugreport.is_file():
                    log("Analyse MVT Android…")
                    runner = MVTAndroidRunner(affaire.executor, bugreport)
                    log(affaire.analyser(runner).resume())
            else:
                acq_ios = IOSBackupAcquirer(affaire.executor, identifiant)
                log(affaire.acquerir(acq_ios).resume())
                backup = affaire.dossier / "backup_ios"
                if backup.is_dir():
                    log("Analyse MVT iOS…")
                    runner_ios = MVTIOSRunner(affaire.executor, backup)
                    log(affaire.analyser(runner_ios).resume())
            return affaire.correler()

        self._pipeline_en_cours(True)
        self._journaliser("— Lancement du pipeline —")
        self._travailleur = Travailleur(tache)
        self._travailleur.progres.connect(self._journaliser)
        self._travailleur.termine.connect(self._pipeline_termine)
        self._travailleur.echoue.connect(self._pipeline_echoue)
        self._travailleur.start()

    def _pipeline_termine(self, synthese: SyntheseCorrelation) -> None:
        self._pipeline_en_cours(False)
        self._etiquette_niveau.setText(f"Niveau : {synthese.niveau.value}")
        self._journaliser(synthese.formulation())
        self._bouton_rapport.setEnabled(True)

    def _pipeline_echoue(self, message: str) -> None:
        self._pipeline_en_cours(False)
        self._erreur(message)

    def _generer_rapport(self) -> None:
        if self.affaire is None:
            return
        try:
            dossier = self.affaire.generer_rapport()
        except (GuardianError, OSError) as exc:
            self._erreur(f"Génération du rapport impossible : {exc}")
            return
        self._journaliser(f"Rapport généré : {dossier.synthese_html}")
        self._journaliser(f"Manifeste : {dossier.manifest}")


def lancer(argv: list[str] | None = None) -> int:
    """Lance l'interface graphique. Retourne le code de sortie de l'application."""
    application = QApplication(argv if argv is not None else sys.argv)
    fenetre = FenetrePrincipale()
    fenetre.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(lancer())
