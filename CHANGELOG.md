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

### Corrigé
- **`.gitignore` : livrables d'affaire toujours ignorés (protection des données).**
  `rapport_synthese.pdf` → `rapport_synthese.*` : le rapport HTML d'un dossier d'affaire
  (données potentiellement sensibles) n'était pas ignoré et pouvait remonter dans un
  `git status` si le dossier était nommé hors convention. Désormais couvert quel que
  soit l'emplacement (§2 : aucune donnée d'affaire dans le dépôt).
- **APK en splits non capturés (P1-D) — confirmé sur appareil réel.** `extraire_apk`
  ne récupérait que le **premier** chemin de `pm path` (`base.apk`). Or les applications
  modernes (app bundles) sont réparties sur plusieurs APK : sur un OPPO réel, GMS a
  `base.apk` **+ 10 splits**, le Play Store **+ 6**, dont `split_config.arm64_v8a`
  portant le **code natif (.so)** — souvent l'essentiel d'un malware. La capture était
  donc **incomplète** (pièce contestable). Désormais **tous** les composants (base +
  splits) sont pullés et hachés ; une capture partielle (un split en échec) est
  signalée en **confiance faible** avec le décompte des composants manquants. 2 tests.
- **Fausse absence silencieuse sur échec masqué (P0-C′) — révélé sur appareil réel.**
  Les relevés Android ne jugeaient l'échec que sur le **code de sortie**. Or, sur un
  OPPO réel, `dumpsys <service_absent>` sort en **code 0** avec un **stdout vide** et
  l'erreur sur **stderr** (« Can't find service ») : le relevé aurait été interprété
  « aucun résultat » (fausse absence) au lieu d'« échec ». Un relevé qui sort en code 0
  mais sans aucune sortie exploitable **et** avec une erreur sur stderr est désormais
  traité comme **non concluant** (confiance faible), jamais comme une absence (§2.6,
  §5). Le message d'échec distingue ce cas et rappelle « ce n'est PAS une absence de
  signal ». Ajout de `ExecutionTracee.texte_stderr()` (symétrique de `texte_stdout`).
  1 test de non-régression (adb simulé reproduisant la sortie réelle).
- **Faux positifs d'administrateurs d'appareil (P0-A) — confirmé sur appareil réel.**
  `_parser_composants_admin` relevait *tout* motif « paquet/classe » dans la sortie de
  `dumpsys device_policy` : sur un OPPO réel, une ligne de statistiques
  `… max calls/s=… max dur/s=…` produisait deux faux administrateurs (`calls/s`,
  `dur/s`) — un **signal FORT erroné**, à portée juridique. Le parseur s'ancre désormais
  sur la section « Enabled Device Admins » et n'accepte que les formes strictes d'une
  entrée d'admin (composant nu `com.pkg/.Cls:` **ou** `ComponentInfo{com.pkg/.Cls}`),
  avec repli sur ces mêmes formes si aucun en-tête n'est reconnu. Vérifié sur la vraie
  sortie (2 vrais admins, 0 bruit) ; 2 tests de non-régression ajoutés.
- **Analyse MVT iOS sur sauvegarde chiffrée (angle mort).** `mvt-ios check-backup` ne
  peut lire une sauvegarde chiffrée sans le mot de passe ; le runner ne le fournissait
  pas → risque de « aucun IOC » **silencieux** sur le cas nominal (le chiffré capture
  plus de données). `MVTIOSRunner` accepte désormais un `fournisseur_mot_de_passe`
  (callback), transmis à MVT via la variable d'environnement `MVT_IOS_BACKUP_PASSWORD`
  — jamais en argument, jamais journalisé (§2). Sans fournisseur, comportement inchangé
  (backup en clair uniquement). Détecté en préparation des essais terrain.

### Ajouté
- **Chaîne d'analyse complète dans le cockpit** (`gui/app.py`) : le pipeline enchaîne
  désormais **MVT + LEAPP (A/iLEAPP) + Autopsy** (Android et iOS), là où seul MVT était
  câblé. Chaque analyseur ne tourne que si son **artefact d'entrée existe** ET si
  l'**outil est installé** ; sinon l'étape est **sautée proprement** avec un message
  clair (dégrader sans planter, §5) — ce qui corrige aussi le cas où un MVT absent
  faisait échouer tout le pipeline. Helper testable `_raison_saut_analyse`. 1 test.
- **Options d'acquisition Android dans le cockpit** (`gui/app.py`) : trois cases à
  cocher — `bugreport`, `pull /sdcard`, `APK des signaux forts`. Cochées par défaut
  (acquisition complète). **Tout décoché = inventaire des signaux seul**, sans aucune
  copie de données — un premier relevé non intrusif, adapté à un appareil non rincé.
  Les états sont lus dans le thread UI puis passés à `AndroidLogicalAcquirer`. 1 test.
- **Intégration continue** (`.github/workflows/ci.yml`, GitHub Actions, Ubuntu) :
  verrouille la cible Linux réelle (dev sous Windows) et les fins de ligne LF, et
  rejoue la chaîne qualité exigée avant chaque commit. Trois jobs — `lint` (ruff
  lint + format, `mypy --strict`, contrôle anti-CRLF), `tests` (pytest sur la matrice
  Python 3.11/3.12/3.13), `gui` (tests PyQt6 en mode offscreen sous xvfb). Permissions
  en lecture seule ; aucun outil forensic réel requis (simulacres).
- **Voie `env` de `TracedExecutor.executer`** : passage de variables d'environnement
  **surchargeant** `os.environ` (héritage préservé), réservé aux **secrets** hors
  `args` — comme `entree` (stdin), `env` n'est **ni archivé** dans `raw/` **ni
  journalisé** en custody. Couvert par des tests de transmission et de **non-fuite**
  (raw + custody). Sert au mot de passe MVT iOS (cf. Corrigé).
- **Protocole d'essai sur appareils réels** (`docs/ESSAIS_TERRAIN.md`) : commandes
  exactes lancées par chaque runner, grille de consignation des écarts, et **audit
  priorisé** des points où le parsing risque de diverger des vraies sorties
  (`dumpsys device_policy` en regex, propagation du code retour d'`adb shell`, APK en
  splits, timeouts, codes de sortie MVT…). Doctrine « observer d'abord, corriger ensuite ».
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
