# Carnet de bord — guardian

> **But de ce fichier.** Assurer le suivi du projet et permettre une **reprise
> fluide** après une pause. Il complète — sans les remplacer — `CLAUDE.md` (la
> spécification, source de vérité), `CHANGELOG.md` (le détail des changements) et
> l'historique Git. Ici : *où en est-on, comment reprendre, quelles décisions ont
> été prises, que reste-t-il à faire.*
>
> **Convention** : à chaque session de travail, ajouter une entrée datée dans la
> section « Journal des sessions » (en bas).

---

## 1. État au 2026-07-31

- **Dépôt distant** : `Jeanmitchang/Borne-Forensic` (**privé**) · branche `main`.
- **Dernier commit** : `153a16f` · **CI GitHub Actions verte** (lint + tests 3.11/3.12/3.13
  + GUI, sur Ubuntu).
- **Avancement** : **feuille de route `CLAUDE.md` §10 terminée — étapes 0 → 10** ;
  **CI en place et verte**, **dépôt poussé (privé)**.
- **Volume** : 22 modules `guardian/` · 19 fichiers de tests ·
  **182 tests, tous verts**.
- **Chaîne qualité** : `ruff` (lint + format) ✅ · `mypy --strict` (26 fichiers) ✅ ·
  `pytest` ✅.
- **Statut fonctionnel** : pipeline complet **détection → acquisition (Android/iOS) →
  analyse (MVT/LEAPP/Autopsy) → corrélation → dossier livrable haché**, avec GUI
  cockpit PyQt6. Validé avec des **outils simulés** ; **pas encore essayé sur
  appareils réels**.

---

## 2. Reprendre le travail (procédure)

```bash
# 1. Se placer dans le dépôt et vérifier l'état
git status && git log --oneline -5

# 2. Environnement Python (cible Linux ; dev possible sous Windows)
python3.11 -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -e ".[dev,gui]"

# 3. Vérifier que tout est vert AVANT de coder
ruff check . && ruff format --check . && mypy guardian && pytest

# 4. Diagnostic des dépendances système (adb, libimobiledevice, MVT, Java…)
python -m guardian.core.environment

# 5. Lancer la GUI (si PyQt6 installé)
python -m guardian.gui.app
```

**Avant de committer** : toujours relancer la chaîne du point 3. Tout doit rester
vert (priorité robustesse §4).

**Prochaine action recommandée** (cf. §5) : mettre en place la **CI GitHub Actions
(Ubuntu)** avant les essais terrain.

---

## 3. Carte du code (qui fait quoi)

| Module | Rôle |
|---|---|
| `core/exceptions.py` | Hiérarchie métier (`GuardianError` racine). |
| `core/logging_conf.py` | Logs applicatifs JSONL, rédaction des secrets, rotation. |
| `core/custody.py` | SHA-256, journal **append-only chaîné par hachage**, consentement, `MANIFEST.sha256`. |
| `core/provenance.py` | `Finding`, `CommandTrace`, enums, **`TracedExecutor` (porte unique)**, registre versions. |
| `core/environment.py` | Vérif dépendances (présence sans exécution + version tracée). |
| `detection/usb_watch.py` | Détection USB iOS/Android + diagnostic prérequis Android. |
| `acquisition/base.py` | Contrat `Acquirer` (lecture seule) + helpers communs. |
| `acquisition/android_logical.py` | Signaux forts `dumpsys`/`settings` + bugreport + pull + APK. |
| `acquisition/ios_backup.py` | Sauvegarde `idevicebackup2` ; mot de passe via stdin ; chiffrement opt-in. |
| `analysis/base.py` | Contrat `Analyzer`. |
| `analysis/mvt_runner.py` | MVT Android/iOS ; base IOC optionnelle consignée. |
| `analysis/leapp_runner.py` | iLEAPP / ALEAPP (corroboration). |
| `analysis/autopsy_runner.py` | Autopsy (corroboration, invocation configurable). |
| `analysis/correlator.py` | Agrégation → niveau qualitatif + formulation épistémique. |
| `report/builder.py` | Journal JSONL/HTML, replay_manifest, synthèse HTML, PDF opt., MANIFEST. |
| `affaire.py` | **Orchestrateur** (sans PyQt) : enchaîne tout le pipeline. |
| `gui/app.py` | Cockpit PyQt6 (fine couche sur `affaire.py`). |

Point d'entrée logique de bout en bout : **`guardian/affaire.py` → classe `Affaire`**
(ouvrir → detecter → acquerir → analyser → correler → generer_rapport). La GUI ne
fait qu'appeler cette classe.

---

## 4. Décisions prises pendant le développement

Ces arbitrages ont été tranchés en cours de route (au-delà des décisions verrouillées
de `CLAUDE.md` §3). **Ne pas les rediscuter sans raison.**

| Sujet | Décision | Motif |
|---|---|---|
| Disposition du code | Paquet `guardian/` + shim `main.py` racine | README suppose `guardian.core.*` ; évite `import core` global. |
| Exception environnement | `EnvironmentCheckError` (pas `EnvironmentError`) | Ne pas masquer le builtin (alias d'`OSError`). |
| Journal de custody | Append-only **chaîné par hachage** (tamper-evident) | Renforce l'intégrité probatoire (au-delà du simple append). |
| Chiffrement iOS vs lecture seule | Lecture seule par défaut ; **activation = opt-in explicite** | §3/§10 « chiffré » vs §2 « aucune modif » → garde-fou §2 gagne. |
| Mot de passe sauvegarde iOS | Fourni par callback, transmis **via stdin**, jamais conservé | stdin n'est ni archivé ni journalisé par `TracedExecutor`. |
| Base IOC MVT | **Optionnelle** ; si fournie, empreinte consignée ; sinon détections intégrées | 100 % hors-ligne (§2) + traçabilité de version. |
| Sortie du corrélateur | Score interne **restitué en niveaux qualitatifs** (FORTS/MODERES/FAIBLES/AUCUN_OBSERVABLE) | Éviter un faux « % de culpabilité ». |
| Niveau du corrélateur | Piloté par la **gravité**, pas par un seuil sur le score | Défendable juridiquement. |
| Rapport PDF | HTML zéro-dépendance ; **PDF optionnel** via outil système tracé | Doctrine « zéro dépendance non justifiée » (§3). |
| Échappement HTML | `_attr` (guillemets) vs `_txt` (apostrophes conservées) | `html.escape(quote=True)` cassait le français (`l'appareil`). |
| Architecture GUI | **Orchestrateur d'abord** (`affaire.py`, sans PyQt), GUI ensuite | Logique 100 % testable hors UI. |
| PyQt6 | **Extra optionnel `[gui]`** ; jamais importé au chargement du paquet | Cœur utilisable headless/CLI ; doctrine minimaliste. |
| mypy sur la GUI | `ignore_errors` sur `guardian.gui.app` | Typage strict de Qt peu utile ; logique déjà typée dans `affaire.py`. |
| Autopsy | Invocation **configurable** (flags/args) | La CLI d'Autopsy varie selon les versions : ne pas figer un contrat faux. |

---

## 5. Points ouverts / À faire (par priorité)

1. ~~**CI GitHub Actions (Ubuntu)**~~ — **FAIT** (`.github/workflows/ci.yml`) : jobs
   `lint` (ruff + `mypy --strict` + contrôle anti-CRLF), `tests` (matrice Python
   3.11/3.12/3.13), `gui` (PyQt6 offscreen sous `xvfb`). *S'exécutera au premier push
   sur GitHub (aucun remote configuré à ce jour).*
2. **Essais sur appareils réels** — les runners sont validés avec des outils simulés
   (adb/mvt/idevicebackup2/leapp/autopsy factices). Confronter aux vraies sorties.
   **Protocole + audit priorisé** disponibles : `docs/ESSAIS_TERRAIN.md`. Points
   restant à vérifier terrain : timeouts (iOS/pull), codes de sortie MVT, **vrai
   positif** (activer un vecteur FORT et confirmer la détection). **Corrigés & confirmés
   sur appareil réel** : **P0-A** (faux admins `calls/s`/`dur/s`), **P1-D** (splits APK
   désormais tous capturés). **P0-B corrigé** (mdp MVT iOS via `env`). **P0-C vérifié**
   (propagation code retour OK sur adb v36) ; **P0-C′ corrigé** (échec masqué `dumpsys`
   exit 0 + stderr = fausse absence). Cf. §7 sessions (6)–(7).
3. ~~**`SECURITY.md`**~~ — **traité** : ligne PGP retirée ; contact sécurité transformé
   en **champ libre documenté** (à renseigner par le mainteneur/redistributeur — le
   projet est destiné à être partagé, l'adresse varie selon l'hébergeur). *Reste : le
   mainteneur renseigne SON adresse avant de rendre le dépôt public.*
4. ~~**`.github/ISSUE_TEMPLATE/config.yml`**~~ + **README** — **fait** : `OWNER/REPO` →
   `Jeanmitchang/Borne-Forensic` ; badge CI ajouté au README (visible une fois public).
5. **Empaquetage / doc d'installation Linux** (Budgie/Ubuntu).
6. **Base de signatures/IOC** — documenter comment l'opérateur fournit et met à jour
   la base (chemin, format STIX2, versionnement) — le code la consomme déjà (`base_ioc`).

### Limites connues (assumées, pas des bugs)
- `replay_manifest.jsonl` est **souvent vide** : la plupart des relevés sur appareil
  vivant sont `POINT_IN_TIME` (non rejouables à l'identique). C'est honnête et voulu.
- Les tests utilisent des **outils simulés** : ils valident *notre* logique (parsing,
  provenance, custody, formulation), pas le comportement réel des outils tiers.
- Unicité des `finding_id` garantie **au sein d'un `TracedExecutor`** (compteur
  continu). Une affaire = un executor partagé (via `Affaire`) → OK. À garder en tête
  si un jour plusieurs executors coexistent.

---

## 6. Rappels — garde-fous non négociables (`CLAUDE.md` §2)

1. **Lecture seule** sur le support source. Aucune écriture sur le téléphone.
2. **100 % hors-ligne.** Aucun appel réseau, jamais.
3. **Aucun secret en clair** (logs, custody, rapports, arguments de commande).
4. **Honnêteté épistémique** : jamais « appareil sain » ; toujours « parmi ceux
   observables… ».
5. **Reproductibilité** : chaque résultat porte sa commande exacte (`TracedExecutor`).
6. **Échouer bruyamment** plutôt que dégrader en silence.

Ces règles sont, pour beaucoup, **verrouillées par des tests** (ex. non-fuite du mot
de passe, formulation « jamais sain », chaînage custody). Un test rouge sur ces points
est un signal probatoire, pas un simple échec technique.

---

## 7. Journal des sessions

### 2026-07-30 — Amorçage complet du projet (étapes 0 → 10)
- Départ : uniquement la documentation fondatrice (README, CONTRIBUTING, SECURITY,
  LICENSE, CLAUDE.md). Pas de code, pas de dépôt Git.
- Posé le cadre de gouvernance (Git init, `.gitignore` durci, `.gitattributes` LF,
  `CHANGELOG`, templates `.github/`).
- Construit **toute** la feuille de route §10, étape par étape, en sous-lots testés :
  socle `core/`, détection, acquisitions Android/iOS, analyses MVT/LEAPP/Autopsy,
  corrélateur, rapport, orchestrateur + GUI.
- Fin de session : 22 commits, 177 tests verts, chaîne qualité complète au vert.
- **Reprise prévue** : mettre en place la CI (§5.1), puis premiers essais sur
  appareils réels.

### 2026-07-31 — Préparation des essais terrain + correctif P0-B (MVT iOS chiffré)
- **Fait** :
  - Rédigé `docs/ESSAIS_TERRAIN.md` : protocole d'essai sur appareils réels calé sur
    les commandes exactes des runners, grille de consignation des écarts, et **audit
    priorisé** des fragilités de parsing face aux vraies sorties.
  - **Corrigé P0-B** (angle mort) : `MVTIOSRunner` ne pouvait pas lire une sauvegarde
    iOS **chiffrée** (pas de mot de passe transmis) → « aucun IOC » silencieux sur le
    cas nominal. Ajout d'un `fournisseur_mot_de_passe` (callback) transmis via la
    nouvelle **voie `env`** de `TracedExecutor.executer` (variable
    `MVT_IOS_BACKUP_PASSWORD`), jamais en argument, jamais journalisée.
  - Tests : +5 (2 provenance : transmission `env` + non-fuite raw/custody ; 3 MVT iOS :
    transmission, absence sans fournisseur, non-fuite custody). **182 tests verts**,
    ruff + mypy `--strict` au vert.
- **Décidé** : le passage de secrets à un sous-processus se fait par `env` (fusionné à
  `os.environ`, non tracé), au même titre que `stdin` — jamais par `args`.
- **En cours / bloqué** : rien. P0-A, P0-C, P1-D et les timeouts restent à **confronter
  au matériel réel** (pas faisable sans appareil).
- **Prochaine action** : essais terrain guidés par `docs/ESSAIS_TERRAIN.md`, ou CI
  GitHub Actions (§5.1), selon disponibilité du matériel.

### 2026-07-31 (2) — CI GitHub Actions
- **Fait** : `.github/workflows/ci.yml` — jobs `lint` (ruff lint + format,
  `mypy --strict`, contrôle anti-CRLF), `tests` (pytest sur matrice Python
  3.11/3.12/3.13), `gui` (PyQt6 offscreen sous `xvfb`, libs Qt système). Permissions
  lecture seule, annulation des runs obsolètes. YAML validé, contrôle LF vérifié
  localement (aucun CRLF committé).
- **En cours / bloqué** : aucun remote Git configuré → la CI ne s'exécutera qu'au
  premier `git push` vers GitHub. Badge README à ajouter une fois le slug connu (§5.4).
- **Prochaine action** : publier le dépôt (remplir `SECURITY.md` §5.3 et les templates
  `.github` §5.4 **avant** publication), ou essais terrain.

### 2026-07-31 (3) — Dépôt poussé (privé) + CI verte
- **Fait** :
  - Créé le dépôt **privé** `Jeanmitchang/Borne-Forensic` (compte GitHub `Jeanmitchang` ;
    les commits restent signés `Blinkjeremy` = `user.name` Git local) et poussé `main`.
  - **CI verte** après un correctif : `ruff 0.16` (installé par la CI) reformate les
    blocs de code Python dans les `.md` → `ruff format --check .` voulait retoucher
    `CLAUDE.md`. Corrigé par `extend-exclude = ["*.md"]` dans `pyproject.toml` (la doc
    Markdown sort du périmètre ruff, lint ET format).
  - Résultat : `lint` + `tests` (3.11/3.12/3.13) + `gui` (PyQt6 offscreen) tous verts.
- **À noter (dette légère, non bloquant)** :
  - **Divergence de version ruff** : local `0.13.3` (site-packages système Windows,
    non-writeable, masque le user `0.16.1`) vs CI `0.16.1`. **La CI fait foi.** Aligner
    l'environnement local un jour, ou épingler ruff dans `[dev]`.
  - Annotation CI « Node.js 20 deprecated » : `actions/checkout@v4` /
    `actions/setup-python@v5` forcés sur Node 24. Passer à `checkout@v5` le moment venu.
- **Avant de rendre le dépôt public** : remplir `SECURITY.md` (§5.3, email + PGP) et
  le template `.github/ISSUE_TEMPLATE/config.yml` (§5.4, `OWNER/REPO` →
  `Jeanmitchang/Borne-Forensic`) ; ajouter le badge CI au README.
- **Prochaine action** : essais terrain (`docs/ESSAIS_TERRAIN.md`), ou préparation de
  la mise en public (SECURITY.md + templates + badge).

### 2026-07-31 (4) — Préparation de la mise en public
- **Fait** :
  - `.github/ISSUE_TEMPLATE/config.yml` : `OWNER/REPO` → `Jeanmitchang/Borne-Forensic`.
  - `README.md` : badge CI ajouté (s'affichera une fois le dépôt public).
  - `SECURITY.md` : ligne PGP/Signal retirée ; contact sécurité converti en **champ
    libre documenté** — décision opérateur : le module sera **redistribué**, donc
    l'adresse de signalement dépend de l'hébergeur et n'est pas figée en dur.
- **Reste avant de rendre PUBLIC** : le mainteneur (Jeanmitchang) renseigne son adresse
  de contact sécurité dans `SECURITY.md`, puis `gh repo edit --visibility public`.
- **Prochaine action** : **essais terrain** (`docs/ESSAIS_TERRAIN.md`).

### 2026-07-31 (5) — Checklist appareil Android de test
- **Fait** : `docs/CHECKLIST_APPAREIL_ANDROID.md` — mise en place pas à pas d'un
  appareil Android de test (prérequis adb Linux, débogage USB, clé RSA, détection
  guardian via GUI), **activation contrôlée des 3 vecteurs FORTS** (accessibilité via
  TalkBack, admin via « Localiser mon appareil », écouteur de notifications), scénario
  de contrôle négatif, et remise à zéro. Référencée depuis `ESSAIS_TERRAIN.md` §4.0.
- **Souligné** : le test de l'admin d'appareil est l'occasion de vérifier **P0-A**
  (faux positifs de la regex `dumpsys device_policy`) — comparer admins réels vs
  composants remontés par guardian.
- **Ouvert (optionnel)** : construire une **APK de test dédiée** (déclarant les 3
  services, bénigne) pour un jeu de tests reproductible — non fait, à la demande.
- **Prochaine action** : essais réels dès qu'un appareil est disponible.

### 2026-07-31 (6) — Premier essai terrain réel (OPPO CPH2173) → P0-A corrigé
- **Contexte** : premier branchement d'un appareil Android réel (OPPO CPH2173, série
  `cc379894`) en USB. Déroulé du process d'essai `docs/ESSAIS_TERRAIN.md` §4 : pont
  `adb` établi, relevé des 4 signaux bruts, puis application des **parseurs réels** de
  guardian aux vraies sorties.
- **Découverte (P0-A confirmé)** : sur `dumpsys device_policy` (631 lignes), la regex
  globale extrayait **4** « administrateurs » dont **2 faux** (`calls/s`, `dur/s`,
  issus d'une ligne de stats `LockGuard.guard(): … max calls/s=… max dur/s=…`).
- **Décidé & fait** : refonte de `_parser_composants_admin` — **ancrage sur la section
  « Enabled Device Admins » + formes strictes** (composant nu `pkg/cls:` **ou**
  `ComponentInfo{pkg/cls}`) + repli sans en-tête. Découverte au passage que les tests
  simulaient le format `ComponentInfo{}` alors que l'OPPO réel utilise la forme nue :
  **les deux formats coexistent** et sont désormais gérés.
- **Résultat** : 2 vrais admins sur données réelles, 0 bruit ; fixtures existantes
  toujours vertes ; +2 tests de non-régression. **184 tests verts**, chaîne qualité OK.
- **Autres relevés (bénins, bien parsés)** : accessibilité `null` ; 3 écouteurs de
  notifications légitimes (Android Auto, Wear OS, HeyTap Health OPPO) — rappel : un
  signal FORT ≠ malveillant, l'expert triangule ; 300 paquets tiers.
- **Prochaine action** : poursuivre les relevés terrain — **P0-C** (code retour
  `adb shell`), puis créer des signaux FORTS contrôlés (checklist §F) pour valider les
  vrais positifs.

### 2026-07-31 (7) — Terrain (suite) : P0-C vérifié, P0-C′ durci
- **Fait** : batterie de tests `adb shell` sur l'OPPO réel pour P0-C (propagation du
  code retour).
  - **P0-C** : propagation **fonctionnelle** (`exit 7`→7, binaire absent→127,
    `ls` absent→1). Le risque historique « adb shell renvoie toujours 0 » ne se
    matérialise pas sur adb v36/Android récent.
  - **P0-C′ (découverte)** : `dumpsys <service_absent>` → **exit 0 + stdout vide +
    stderr** « Can't find service ». Guardian n'examinait que code+stdout → risque de
    **fausse absence silencieuse**.
- **Décidé & fait** : durcissement — `Acquirer._releve_non_concluant` traite « code 0 +
  stdout vide + stderr non vide » comme non concluant (confiance faible) ; message
  d'échec distingue le cas et affirme « ce n'est PAS une absence ». Ajout de
  `ExecutionTracee.texte_stderr()`. Relevés accessibilité/notifications/admins/paquets
  branchés dessus. **185 tests verts.**
- **Non commité** : lots P0-A + P0-C′ cumulés (commit différé à la demande de
  l'opérateur).
- **Prochaine action** : valider un **vrai positif** (checklist §F : activer TalkBack →
  guardian doit remonter le service d'accessibilité en FORT).

### 2026-07-31 (8) — Terrain (suite) : P1-D corrigé (splits APK)
- **Fait** : `pm path` sur 4 paquets réels de l'OPPO → **tous en splits** (GMS base +
  10 splits, Play Store +6, YouTube +3, Chrome +5). `extraire_apk` ne prenait que
  `chemins[0]` (base.apk) → **P1-D confirmé** : capture incomplète (les splits
  `config.arm64_v8a` portent le code natif .so).
- **Décidé & fait** : `extraire_apk` pulle désormais **tous** les composants (base +
  splits), les hache tous ; capture partielle (split en échec) → confiance faible +
  décompte des composants manquants. +2 tests. **187 tests verts.**
- **Non commité** : lots P0-A + P0-C′ + P1-D cumulés (commit différé, à la demande).
- **Vrai positif validé** : TalkBack activé → `enabled_accessibility_services` passe de
  `null` au composant `com.google.android.marvin.talkback/…TalkBackService` ; le parseur
  guardian l'extrait correctement (remontée FORT). Cycle accessibilité complet OK
  (négatif → positif). **Aucune correction nécessaire** sur ce vecteur.
- **Prochaine action** : committer les lots cumulés ; puis, autres vecteurs (activer un
  admin d'appareil / un écouteur de notifications) et P0-C′ côté iOS/pull si besoin.

### 2026-07-31 (9) — Test d'intégration : pipeline réel sur l'OPPO
- **Fait** : lancé le **vrai pipeline** guardian (`TracedExecutor` + `JournalCustody` +
  `AndroidLogicalAcquirer.inventorier_signaux`, **sans** `acquerir` pour ne rien puller
  de personnel) contre l'appareil réel. 4 Findings produits (F-0001..F-0004),
  chacun tracé (commande exacte), sorties brutes archivées + hachées dans `raw/`,
  custody chaînée horodatée UTC.
- **Confirmé en contexte réel** : F-0003 (admins) remonte **2** composants → le correctif
  P0-A tient dans le pipeline complet, pas seulement en test unitaire.
- **Rapport réel généré** (chaîne complète inventaire → corrélation → livrable) :
  niveau `FORTS` (2 STRONG, bénins mais guardian oriente sans conclure) ; journal
  JSONL+HTML, synthèse HTML, `MANIFEST.sha256` (hache tout le dossier), tous produits.
  `replay_manifest.jsonl` **vide** (tous POINT_IN_TIME — honnête). Intégrité vérifiée :
  le sha256 de `raw/F-0001.out` dans le MANIFEST == celui porté par le Finding.
  **Toute la chaîne est validée sur appareil réel.**
- **Reste (idées)** : bugreport/pull réels (volumineux, données perso → prudence) ;
  côté iOS quand un appareil sera dispo ; PDF optionnel (wkhtmltopdf).

<!--
### AAAA-MM-JJ — Titre
- Fait :
- Décidé :
- En cours / bloqué :
- Prochaine action :
-->
