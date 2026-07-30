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
- Ossature de gouvernance du dépôt : `.gitignore` (durci « forensic »),
  `.gitattributes` (fins de ligne LF forcées, cible Linux), `CHANGELOG.md`,
  templates d'issue et de pull request (`.github/`).
- Documentation fondatrice : `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `LICENSE` (GPLv3), `CLAUDE.md` (spécification technique complète).

### À venir (feuille de route — cf. `CLAUDE.md` §10)
- Étape 0 — Bootstrap : `pyproject.toml`, arborescence, `main.py` minimal.
- Étape 1 — Socle `core/` : exceptions, logging, custody, provenance, environment.

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
