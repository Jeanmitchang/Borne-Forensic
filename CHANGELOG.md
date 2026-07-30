# Journal des modifications

Toutes les évolutions notables de `guardian` (nom de travail) sont consignées dans ce
fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet
adhère au [versionnement sémantique](https://semver.org/lang/fr/).

> **Note probatoire.** Ce journal complète — sans le remplacer — l'historique Git.
> L'historique Git fait foi sur *quand* et *comment* la logique de détection a évolué ;
> ce fichier en donne la lecture humaine, orientée impact opérateur et juridique.

---

## [Non publié]

### Ajouté
- **Étape 10 — Autopsy** (`analysis/autopsy_runner.py`), corroboration **optionnelle** :
  `AutopsyRunner` (contrat `Analyzer`) produit un rapport de corroboration → Finding
  `INFO` (comme LEAPP, n'est pas une détection). Invocation **configurable**
  (`commande_autopsy`, `flag_entree`/`flag_sortie`, `args_supplementaires`) car la CLI
  d'Autopsy varie selon les versions — pas de contrat CLI figé et potentiellement faux.
  Accepté tel quel par `Affaire.analyser` sans changement (contrat générique). 7 tests.
- **Étape 9 — Interface & orchestration**, en deux sous-lots :
  - `guardian/affaire.py` (9.1, **sans PyQt**) : classe `Affaire` qui tient le
    contexte (dossier, `TracedExecutor`, custody, registre) et enchaîne les phases
    (ouverture + consentement → détection → acquisition → analyse → corrélation →
    rapport), en accumulant les Findings. Toute la logique, testable hors UI —
    couverte par un test de pipeline complet end-to-end.
  - `guardian/gui/app.py` (9.2, **PyQt6 optionnel** `[gui]`) : fenêtre cockpit, fine
    couche appelant `Affaire`. Phases longues dans un `QThread` (UI non figée),
    erreurs remontées à l'écran. PyQt6 jamais importé au chargement du paquet.
  - Réglages : extra `[gui]`, mypy relâché sur `guardian.gui.*` (le typage strict de
    Qt apporterait peu ; la logique est dans `affaire.py`). Tests GUI en mode
    « offscreen », ignorés si PyQt6 absent.
- **Étape 8 — Rapport** (`report/builder.py`), zéro dépendance (stdlib), en deux
  sous-lots (17 tests dédiés) :
  - `journal_probatoire.jsonl` (un Finding par ligne) + `journal_probatoire.html`
    (chaque Finding déplié, trace complète, ancres `id="F-xxxx"`) + `replay_manifest`
    `.jsonl` (commandes `DETERMINISTIC` rejouables, vide si aucune — honnête).
  - `rapport_synthese.html` : niveau qualitatif coloré, renvois `[F-xxxx]` cliquables,
    formulation épistémique du corrélateur. PDF **optionnel** via outil système (tracé,
    `None` si absent). `GenerateurRapport` assemble tout et produit `MANIFEST.sha256`
    **en dernier**. Échappement HTML attribut/texte (apostrophes préservées, XSS géré).
- **Étape 7 — Corrélateur** (`analysis/correlator.py`) : agrège les Findings en une
  `SyntheseCorrelation`. Score interne pondéré `Severity × Confidence` **restitué en
  niveaux qualitatifs** (`FORTS` / `MODERES` / `FAIBLES` / `AUCUN_OBSERVABLE`) —
  jamais un « % de culpabilité ». Niveau **piloté par la gravité** (pas un seuil
  arbitraire). Absence **toujours** formulée « aucun indicateur PARMI CEUX
  OBSERVABLES… », jamais « appareil sain » ; section **Limites** systématique ;
  rappel « oriente, ne conclut pas à la culpabilité » (§11). Synthèse consignée en
  custody. 14 tests dédiés.
- **Étape 6 — Analyse LEAPP** (`analysis/leapp_runner.py`) : `_LEAPPRunnerBase`
  partagée + `ALEAPPRunner` (Android) et `ILEAPPRunner` (iOS). LEAPP **extrait des
  artefacts** (corroboration, §5) → Finding `INFO` avec le rapport (`index.html`)
  comme pièce, pas `STRONG`. Type d'entrée validé (`fs`/`tar`/`zip`/`gz`) ; sortie
  vide ou en erreur signalée non concluante. 8 tests dédiés.
- **Étape 5 — Analyse MVT** (`analysis/mvt_runner.py` + `analysis/base.py`), en deux
  sous-lots (15 tests dédiés) :
  - Contrat `Analyzer` commun (toute commande via `TracedExecutor`, bornage custody).
  - `_MVTRunnerBase` partagée + `MVTAndroidRunner` (`check-bugreport`) et
    `MVTIOSRunner` (`check-backup`). Détection IOC → Finding STRONG ; aucune → INFO
    « aucun IOC parmi la base employée » ; échec → non concluant.
  - Base IOC **optionnelle** (« prévoir les deux ») : si fournie, passée via `--iocs`
    et son **empreinte consignée** (`base_ioc`) ; sinon détections MVT intégrées.
    La version de la base employée est toujours traçable (§5).
- **Étape 4 — Acquisition iOS** (`acquisition/ios_backup.py`), en deux sous-lots
  (13 tests dédiés) :
  - Gestion **sécurisée** du mot de passe de sauvegarde : callback fournisseur,
    transmission à `idevicebackup2` via **stdin** (jamais en argument → jamais
    archivé ni journalisé), non conservé ; garanti par un test « le mot de passe ne
    fuit nulle part » (custody + sorties brutes).
  - Détection de l'état du chiffrement (lecture seule, `ideviceinfo WillEncrypt`) ;
    activation du chiffrement en **opt-in explicite** uniquement (elle modifie
    l'appareil — arbitrage §2 vs §3/§10 en faveur du garde-fou lecture seule).
  - Sauvegarde `idevicebackup2 backup` avec hachage des manifestes ; `acquerir()`
    orchestre état → (opt-in) activation → sauvegarde. Sauvegarde vide/en erreur
    signalée non concluante (jamais un faux succès).
  - Helpers communs `_rel` / `_finding_echec` remontés dans `acquisition/base.py`.
- **Étape 3 — Acquisition Android logique** (`acquisition/android_logical.py`), le
  point clé du projet, en trois sous-lots (34 tests dédiés ; 98 au total) :
  - `acquisition/base.py` : contrat abstrait `Acquirer` (lecture seule sur le
    support source, tout via `TracedExecutor`), `ResultatAcquisition`, validation
    d'identifiant d'appareil, bornage custody début/fin.
  - Inventaire des signaux forts (§5) : services d'accessibilité, écouteurs de
    notifications, administrateurs d'appareil (STRONG), paquets tiers (MEDIUM) ;
    absence = INFO « observable sans root », échec = confiance faible, jamais masqué.
  - `adb bugreport`, pull `/sdcard`, et extraction ciblée des **APK des paquets
    impliqués dans les signaux forts** ; tous les artefacts hachés (SHA-256). Étapes
    lourdes activables/désactivables. `acquerir()` orchestre l'ensemble.
- **Étape 2 — Détection device** (`detection/usb_watch.py`) : premier module métier
  consommant le socle. Détection USB iOS (`idevice_id -l`) et Android (`adb devices`)
  via le `TracedExecutor` (identité d'appareil + instant de connexion consignés dans
  la custody). Diagnostic des prérequis Android (clé RSA non autorisée, hors-ligne,
  permissions udev, débogage USB). Disponibilité des outils testée sans exécution
  (`shutil.which`) pour dégrader proprement. Parseurs purs testés séparément
  (15 tests ; 71 au total).
- **Étape 1 — Socle `core/`** : le socle du projet, développé en quatre sous-lots,
  chacun couvert par des tests unitaires (56 tests au total ; ruff + mypy `--strict`).
  - `exceptions.py` : hiérarchie métier enracinée sur `GuardianError`.
  - `logging_conf.py` : logging applicatif JSONL horodaté UTC, filtre de rédaction
    des secrets, rotation, sans handler réseau.
  - `custody.py` : hachage SHA-256, journal de custody **append-only chaîné par
    hachage** (tamper-evident), consentement, `MANIFEST.sha256` (format `sha256sum`).
  - `provenance.py` : `Finding`/`CommandTrace`, enums `Severity`/`Confidence`/
    `Reproducibility`, `RegistreVersions`, et `TracedExecutor` (porte unique vers
    `subprocess`, archivage + hachage + journalisation).
  - `environment.py` : vérification des dépendances (§8) sans crash, capture de
    version tracée, diagnostic autonome `python -m guardian.core.environment`.
- **Étape 0 — Bootstrap** : `pyproject.toml` (Python ≥ 3.11, version dynamique
  depuis `guardian.__version__`, config Ruff/mypy strict/pytest, aucune dépendance
  runtime), paquet `guardian/` avec sous-paquets (`core`, `detection`,
  `acquisition`, `analysis`, `report`, `gui`), point d'entrée affichant la bannière
  `guardian v0.0.0` (via `python -m guardian`, `python main.py`, ou l'entrée console
  `guardian`), et test de fumée (`tests/test_bootstrap.py`, 3 tests verts).
- Ossature de gouvernance du dépôt : `.gitignore` (durci « forensic »),
  `.gitattributes` (fins de ligne LF forcées, cible Linux), `CHANGELOG.md`,
  templates d'issue et de pull request (`.github/`).
- Documentation fondatrice : `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `LICENSE` (GPLv3), `CLAUDE.md` (spécification technique complète).

### Feuille de route
- **Étapes 0 → 10 terminées.** Prochains chantiers hors feuille de route initiale :
  CI (GitHub Actions sur Ubuntu), essais sur appareils réels, empaquetage.

---

<!--
Gabarit pour une future version publiée :

## [0.1.0] — AAAA-MM-JJ
### Ajouté
### Modifié
### Corrigé
### Sécurité
### Retiré
-->
