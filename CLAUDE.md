# CLAUDE.md — Contexte projet pour Claude Code

> **À lire en premier à chaque session.** Ce fichier est la source de vérité du projet.
> Il consigne les décisions déjà prises, l'architecture cible, les conventions et l'état
> d'avancement. **Ne pas remettre en cause les décisions verrouillées sans demande
> explicite de l'opérateur.**

---

## 0. Démarrage rapide

**Nom de travail** : `guardian` (à renommer plus tard).
**Plateforme cible** : Linux (Budgie / base Ubuntu). Windows/macOS non supportés.
**Opérateur unique** : expert forensic (l'utilisateur). UI peut être dense, pas bridée.
**Statut** : documentation fondatrice terminée (README, CONTRIBUTING, SECURITY, LICENSE).
Le code n'existe pas encore. **Prochaine action = Étape 0 puis Étape 1** (cf. §10).

---

## 1. Contexte & finalité

Outil forensic open-source destiné à des **associations d'aide aux victimes** de
cyberharcèlement et de violences conjugales, sans budget pour Cellebrite/Oxygen/AXIOM.

**Cas d'usage type** : une victime de violences conjugales suspecte que son
(ex-)conjoint a installé un mouchard sur son téléphone. L'outil détecte, documente et
produit un **faisceau de premières preuves** susceptible d'orienter un dépôt de plainte
et une saisie officielle par un expert judiciaire.

**Ce n'est PAS** :
- un antivirus ;
- un substitut à l'expertise judiciaire ;
- un outil pouvant conclure « téléphone sain » (sans root, certaines zones restent
  inaccessibles).

**Cadre d'usage strict** : analyse uniquement de supports pour lesquels le
propriétaire a donné son autorisation explicite (consignée dans `consent.json` à
l'ouverture d'affaire).

---

## 2. Garde-fous non négociables (ne pas dévier)

1. **Lecture seule sur le support source.** Aucune écriture sur le téléphone analysé.
   Pas de root, pas de jailbreak, pas de FFS.
2. **100 % hors-ligne.** Aucun appel réseau, même localhost. Pas de télémétrie.
3. **Aucun secret en clair** dans logs, code, commits, rapports (mot de passe backup
   iOS, identifiants de victimes, etc.).
4. **Honnêteté épistémique.** Ne jamais écrire « téléphone sain ». Toujours formuler
   « aucun indicateur détecté **parmi ceux observables par les méthodes employées** ».
5. **Reproductibilité** : chaque résultat porte la commande exacte qui l'a produit
   (via `TracedExecutor`, cf. §6).
6. **Échouer bruyamment** plutôt que produire un résultat silencieusement dégradé.

---

## 3. Décisions verrouillées

Ces choix ont été discutés et tranchés. **Ne pas les rediscuter sans demande explicite.**

| Décision | Choix | Motif rapide |
|---|---|---|
| Plateforme cible v1 | Linux (Budgie) | Terrain naturel pour forensic ; libimobiledevice/adb fiables |
| FFS / image physique | **Écarté** | Trop chronophage, exige root, risque juridique |
| Périmètre acquisition | Sauvegarde iOS chiffrée + acquisition logique Android | Suffit pour stalkerware commercial (~95 % des cas) |
| `adb backup` | **Écarté** | Déprécié Android 12, cassé sur appareils récents |
| Acquisition Android | `adb bugreport` + `dumpsys` + pull ciblé + APK suspects | Meilleur compromis sans root |
| Interface | PyQt6 desktop, 100 % hors-ligne | Rassurant pour données sensibles, pas de « faux SaaS » |
| Style UI | **Cockpit dense**, pas assistant pas-à-pas | L'opérateur est expert |
| Autopsy | Module **optionnel** post-acquisition | Corroboration timeline/keyword ; jamais dans l'acquisition |
| Archivage brut | **TOUTES** les sorties, y compris commandes sans résultat | L'absence est aussi une preuve |
| Format journal | JSONL (machine) **+** HTML (lisible) | Multi-audience |
| Licence | **GPLv3** | Copyleft fort, aligné éthique du projet |
| Langue code/UI | **Français** | Cohérence contexte associatif/juridique FR |

---

## 4. Priorités du projet (dans cet ordre)

1. 🏗️ **Robustesse / gestion d'erreurs / logs**
2. 🔎 **Couverture détection** (stalkerware, IOC, comptes liés)
3. ⚖️ **Rigueur juridique / chaîne de custody**
4. 🖥️ **Ergonomie**

Toute contribution qui améliorerait (4) au détriment de (1) ou (3) doit être refusée
ou renégociée avec l'opérateur.

---

## 5. Ce que l'analyse peut / ne peut pas voir

### Signaux forts (vecteurs directs de surveillance)
- Services d'accessibilité activés (`settings get secure enabled_accessibility_services`)
- Administrateurs d'appareil (`dpm list-owners`, `dumpsys device_policy`)
- Accès aux notifications (`settings get secure enabled_notification_listeners`)
- Permissions sensibles : localisation background, SMS, micro, caméra, overlay

### Signaux moyens (contexte & persistance)
- Apps cachées / sans icône (`pm list packages -u`)
- Source d'installation (sideload = suspect ; via `dumpsys package`)
- Dates d'installation/màj (corréler à date clé : séparation, dispute)
- Comptes liés au device (`dumpsys account`)
- Apps désactivant Play Protect / persistantes au boot

### Signaux faibles (corroboration)
- Usage stats, batterie, connexions réseau, logcat

### Ce qui n'est PAS visible (à écrire dans chaque rapport)
- Contenu supprimé / espace non alloué
- Bases SQLite système protégées (`/data/data/<pkg>` sans root)
- Données chiffrées d'apps
- Aucune garantie d'exhaustivité (un malware root masquerait sa présence)

### Base de signatures
MVT compare packages/IOC à des blocklists de stalkerware connues (mSpy, FlexiSpy,
Cerberus, Hoverwatch…). **Consigner la version de la blocklist utilisée dans la
provenance.**

---

## 6. Architecture reproductibilité (le cœur du projet)

### Principe

Chaque résultat est un objet `Finding` **auto-traçant** :

```python
@dataclass
class Finding:
    finding_id: str            # ex. "F-0007"
    value: str                 # ce qui s'affiche en synthèse
    severity: Severity         # STRONG / MEDIUM / WEAK / INFO
    confidence: Confidence     # niveau de confiance explicite
    trace: CommandTrace        # binaire, version, args, cwd
    raw_output_ref: str        # chemin raw/F-xxxx.out
    raw_output_sha256: str     # hash de la sortie brute
    timestamp_utc: str         # ISO-8601 UTC
    operator: str
    reproducibility: Reproducibility  # cf. ci-dessous
```

### Le `TracedExecutor` — porte UNIQUE

**Aucun module n'exécute de commande externe directement.** Tous passent par
`core.provenance.TracedExecutor`, qui capture stdout/stderr/exit code, hache et
archive la sortie dans `raw/<id>.out`, horodate UTC, journalise en append-only, et
retourne un `Finding` déjà tracé.

```
ALEAPP_runner ─┐
MVT_runner    ─┼──►  TracedExecutor  ──►  [exécution]
Android_acq   ─┤          │
iOS_acq       ─┘          ├─► raw/<id>.out (+ SHA-256)
                          ├─► journal append-only (JSONL)
                          └─► Finding{value, provenance} ──► corrélateur
```

**Règle absolue** : `subprocess.run` direct dans acquisition/ ou analysis/ = bug.

### Reproductible ≠ déterministe (3 états)

- `DETERMINISTIC` — rejeu = résultat identique (hash de fichier, version paquet…)
- `POINT_IN_TIME` — capture d'instant T (ex. `dumpsys batterystats`) ; méthode
  rejouable mais pas résultat
- `ENVIRONMENT_DEPENDENT` — dépend d'un état externe

**Ne jamais** marquer `DETERMINISTIC` un résultat qui ne l'est pas — c'est un faux pas
juridique exploitable par un contradicteur.

### Manifeste de rejeu

En fin d'analyse, produire `replay_manifest.jsonl` : liste ordonnée des commandes
`DETERMINISTIC` qu'un tiers peut rejouer pour contre-expertise.

---

## 7. Architecture du code (cible)

> **Disposition retenue (tranchée à l'Étape 0)** : le code applicatif vit dans un
> **paquet Python `guardian/`** (importable `guardian`, `python -m guardian`), et
> non à plat à la racine. Motif : le README suppose `guardian.core.*` et
> `pip install -e .` ; un `import core` à plat polluerait l'espace de noms global.
> Un shim `main.py` à la racine permet aussi `python main.py`.

```
Borne-Forensic/               # racine du dépôt
├── CLAUDE.md                 # ce fichier
├── README.md · CONTRIBUTING.md · SECURITY.md · LICENSE   # gouvernance
├── CHANGELOG.md              # journal des modifications (Keep a Changelog)
├── .github/                  # templates d'issue + de PR
├── pyproject.toml            # métadonnées + outillage (Étape 0) ✅
├── main.py                   # shim racine → guardian.main:main ✅
├── guardian/                 # LE PAQUET Python
│   ├── __init__.py           # __version__ (source unique) ✅
│   ├── __main__.py           # « python -m guardian » ✅
│   ├── main.py               # point d'entrée (banniere + main) ✅
│   ├── affaire.py            # ORCHESTRATEUR (sans PyQt) : enchaîne tout le pipeline ✅
│   ├── core/                 # SOCLE — Étape 1 ✅
│   │   ├── exceptions.py     # erreurs métier explicites
│   │   ├── logging_conf.py   # logs structurés JSONL, rotation, rédaction secrets
│   │   ├── custody.py        # SHA-256, journal append-only chaîné, consentement, manifeste
│   │   ├── provenance.py     # Finding, CommandTrace, TracedExecutor, registre versions
│   │   └── environment.py    # vérif dépendances + capture versions (tracée)
│   ├── detection/            # Étape 2
│   │   └── usb_watch.py      # veille USB iOS + Android + diagnostic prérequis
│   ├── acquisition/          # Étapes 3-4
│   │   ├── base.py           # interface commune Acquirer
│   │   ├── android_logical.py # bugreport + dumpsys + pull ciblé
│   │   └── ios_backup.py     # idevicebackup2 chiffré
│   ├── analysis/             # Étapes 5-7 et 10
│   │   ├── base.py
│   │   ├── mvt_runner.py     # MVT iOS + Android
│   │   ├── leapp_runner.py   # iLEAPP / ALEAPP
│   │   ├── autopsy_runner.py # optionnel, corroboration
│   │   └── correlator.py     # agrégation Findings → score + confiance
│   ├── report/               # Étape 8
│   │   └── builder.py        # PDF synthèse + HTML/JSONL + replay_manifest + MANIFEST.sha256
│   └── gui/                  # Étape 9
│       └── app.py            # PyQt6 cockpit
└── tests/                    # tout au long (miroir des modules)
```

*(✅ = déjà en place.)*

### Livrable par affaire

```
dossier_affaire_2026-XXX/
├── rapport_synthese.pdf      # Niveau 1 — lisible (justice), renvois [F-xxxx]
├── journal_probatoire.html   # Niveau 2 — chaque Finding déplié
├── journal_probatoire.jsonl  # Niveau 2 — format machine
├── replay_manifest.jsonl     # Commandes déterministes rejouables
├── custody.jsonl             # Journal append-only horodaté
├── consent.json              # Consentement consigné à l'ouverture
├── raw/                      # TOUTES les sorties brutes hachées
│   ├── F-0001.out
│   └── ...
└── MANIFEST.sha256           # Hash de tout le dossier
```

---

## 8. Prérequis système (Linux Budgie)

À vérifier par `core/environment.py` au démarrage. Capturer la version de chacun pour
la provenance ; lister clairement les manquants sans crasher.

| Dépendance | Rôle | Installation |
|---|---|---|
| Python ≥ 3.11 | runtime | `apt install python3.11` |
| `libimobiledevice-utils` | acquisition iOS (idevicebackup2, idevice_id, ideviceinfo) | `apt install libimobiledevice-utils` |
| `android-tools-adb` | acquisition Android | `apt install android-tools-adb` |
| MVT (`mvt-ios`, `mvt-android`) | analyse IOC/blocklist | `pip install mvt` |
| iLEAPP / ALEAPP | analyse artefacts | `pip` ou clone GitHub |
| Autopsy + Java | corroboration (optionnel) | installeur |
| PyQt6 | GUI | `pip install PyQt6` |

---

## 9. Conventions de code

- **Python 3.11+**, type hints partout, `dataclasses` pour les structures.
- **Français** pour commentaires, docstrings, messages utilisateur, logs.
- **Logs structurés** via `core/logging_conf.py`. Zéro `print` en prod.
- **Aucun `except: pass`.** Toute exception ignorée est justifiée par commentaire.
- **Aucun `shell=True`** avec concaténation. Toujours arguments en liste, via
  `TracedExecutor`.
- **Validation systématique des entrées** : chemins, IDs de device, sorties d'outils
  tiers. Ne jamais faire confiance aveuglément à la sortie d'`adb` ou de MVT.
- **Tests** : tout ajout dans `core/` doit être couvert. Fixtures synthétiques
  uniquement, jamais de donnée réelle de victime.

### Nommage des refontes

Refonte majeure d'un fichier → `module_v2.1_fix-adb-timeout.py`, avec explicitation du
changement dans la PR. Corrections mineures = Git normal.

---

## 10. Feuille de route (ordre STRICT de construction)

Chaque étape doit être fonctionnelle et testée avant la suivante. **Ne pas sauter
d'étape.** Demander validation de l'opérateur avant de passer à la suivante.

- [x] **Étape 0 — Bootstrap** : `pyproject.toml` (Python 3.11+, dépendances de base),
      arborescence complète (dossiers avec `__init__.py`), `main.py` minimal qui
      démarre et affiche « guardian v0.0 ». *(Fait : paquet `guardian/`, bannière
      `guardian v0.0.0`, version dynamique, ruff/mypy strict/pytest configurés.)*
- [x] **Étape 1 — Socle `core/`** (priorité absolue) :
  - `exceptions.py` : hiérarchie d'exceptions métier (`GuardianError` racine,
    `AcquisitionError`, `AnalysisError`, `CustodyError`, `EnvironmentError`, etc.)
  - `logging_conf.py` : logging structuré, rotation, niveaux, formateur JSONL
  - `custody.py` : hachage SHA-256, journal append-only horodaté UTC,
    consentement à l'ouverture, génération de `MANIFEST.sha256`
  - `provenance.py` : dataclasses `Finding`, `CommandTrace`, enums `Severity` /
    `Confidence` / `Reproducibility` ; classe `TracedExecutor` (porte unique) ;
    registre des versions d'outils capté au démarrage
  - `environment.py` : vérification de chaque dépendance (§8), capture de version,
    message clair si manquante
  - **Tests unitaires** pour chaque module (pytest, fixtures synthétiques)
  - *(Fait : 5 modules + 56 tests ; journal de custody append-only **chaîné par
    hachage** ; `EnvironmentError` renommé `EnvironmentCheckError` pour ne pas
    masquer le builtin ; capture de version tracée via `TracedExecutor`.)*
- [x] **Étape 2 — Détection device** (`detection/usb_watch.py`) :
      veille USB iOS (`idevice_id -l`) + Android (`adb devices`) + diagnostic
      prérequis Android (débogage USB / clé RSA)
- [x] **Étape 3 — Acquisition Android logique** (`acquisition/android_logical.py`) :
      **point clé du projet**. `adb bugreport` + inventaire `dumpsys` (signaux forts
      §5) + pull `/sdcard` + APK suspects. **Tout via `TracedExecutor`, tout haché.**
- [x] **Étape 4 — Acquisition iOS** (`acquisition/ios_backup.py`) : `idevicebackup2`
      chiffré, gestion du mot de passe via custody (jamais en clair dans logs).
      *(Lecture seule par défaut ; activation du chiffrement = opt-in explicite, §2.)*
- [x] **Étape 5 — Analyse MVT** (`analysis/mvt_runner.py`) : iOS + Android,
      IOC/blocklist ; consigner la version de la blocklist. *(Base IOC optionnelle.)*
- [x] **Étape 6 — Analyse LEAPP** (`analysis/leapp_runner.py`) : iLEAPP / ALEAPP.
- [x] **Étape 7 — Corrélateur** (`analysis/correlator.py`) : agrégation Findings →
      score + niveau de confiance explicite. *(Score interne → niveau qualitatif.)*
- [x] **Étape 8 — Rapport** (`report/builder.py`) : synthèse HTML + journal HTML/JSONL
      + `replay_manifest.jsonl` + `MANIFEST.sha256`. *(PDF optionnel, zéro dépendance.)*
- [x] **Étape 9 — GUI cockpit** (`gui/app.py`) : PyQt6, assemble tout le pipeline.
      *(Logique dans `guardian/affaire.py`, orchestrateur sans PyQt, testé ; PyQt6 =
      extra optionnel `[gui]`.)*
- [x] **Étape 10 — Autopsy** (`analysis/autopsy_runner.py`) : module optionnel de
      corroboration, CLI/ingest. *(Invocation configurable — flags/args — car la CLI
      d'Autopsy varie ; Finding INFO, comme LEAPP. Accepté tel quel par l'orchestrateur
      via le contrat `Analyzer`.)*

---

## 11. Rappels de formulation (juridique)

- Ne jamais écrire « le téléphone est sain / non compromis ».
- Toujours écrire « aucun indicateur détecté **parmi ceux observables par les méthodes
  employées (acquisition logique sans root)** ».
- Toujours inclure une section **« Limites de l'analyse »** dans le rapport (§5).
- Horodater en **UTC** ISO-8601 ; préciser le fuseau de l'opérateur séparément.
- Le rapport **oriente** vers un dépôt de plainte / une saisie officielle ; il ne
  conclut pas à la culpabilité de qui que ce soit.

---

## 12. Comportement attendu de Claude Code

- **Lire ce fichier en premier** à chaque session.
- **Suivre la feuille de route (§10) dans l'ordre.** Ne pas sauter d'étape.
- **Demander validation** de l'opérateur avant de passer d'une étape à la suivante.
- **Ne pas rediscuter les décisions verrouillées (§3)** sans demande explicite.
- **En cas de doute technique**, poser une question à l'opérateur plutôt qu'inventer.
- **En cas de refonte importante** d'un fichier, utiliser la convention de nommage §9.
- **Toujours proposer des améliorations pertinentes** en fin de réponse (« Suggestion
  profil »), mais sans dévier du plan en cours.
- **Répondre en français.**
