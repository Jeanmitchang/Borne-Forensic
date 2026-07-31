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

- **Branche** : `main` · **dernier commit** : `ec8a243` (+ lot en préparation, non commité)
- **Avancement** : **feuille de route `CLAUDE.md` §10 terminée — étapes 0 → 10.**
  Chantier en cours : **préparation des essais terrain** (protocole + correctif P0-B).
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
   restant à vérifier terrain : **P0-A** (`dumpsys device_policy` parsé en regex →
   faux admin FORT ?), **P0-C** (propagation du code retour `adb shell`), **P1-D** (APK
   en splits non capturés), timeouts, codes de sortie MVT. **P0-B corrigé** (mot de
   passe MVT iOS via `env`, cf. §7 session 2026-07-31).
3. **`SECURITY.md`** — remplir les contacts sécurité (`<À COMPLÉTER>` : email + PGP)
   **avant** toute publication publique du dépôt.
4. **`.github/ISSUE_TEMPLATE/config.yml`** — remplacer `OWNER/REPO` par le vrai dépôt.
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

<!--
### AAAA-MM-JJ — Titre
- Fait :
- Décidé :
- En cours / bloqué :
- Prochaine action :
-->
