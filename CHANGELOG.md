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

### À venir (feuille de route — cf. `CLAUDE.md` §10)
- Étape 2 — Détection device : veille USB iOS/Android + diagnostic prérequis Android.

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
