# guardian *(nom de travail)*

> Station d'analyse forensic open-source pour aider les associations à détecter des
> logiciels de surveillance (**stalkerware**) sur les smartphones de victimes de
> cyberharcèlement et de violences conjugales, **sans budget forensic commercial**.

[![CI](https://github.com/Jeanmitchang/Borne-Forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/Jeanmitchang/Borne-Forensic/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE)
[![Status](https://img.shields.io/badge/status-en%20développement-orange)]()
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)]()

---

## ⚠️ Avant tout : ce que cet outil N'EST PAS

Cet avertissement est en tête, pas en bas, parce qu'un outil forensic mal compris peut
nuire à la personne qu'on cherche à protéger.

- Ce n'est **pas un antivirus** : il ne « nettoie » pas un téléphone.
- Ce n'est **pas une expertise judiciaire** : il produit un **faisceau de premières
  preuves** susceptible d'orienter un dépôt de plainte et une saisie officielle par un
  expert judiciaire mandaté.
- Il ne peut **pas conclure qu'un téléphone est sain**. Sans root/jailbreak, certaines
  zones du système sont inaccessibles. Un résultat négatif signifie « aucun indicateur
  détecté parmi ceux observables par les méthodes employées », rien de plus.
- Il ne doit **jamais être utilisé sur un téléphone dont on n'a pas l'autorisation
  explicite du propriétaire**. Analyser à l'insu d'autrui est une infraction pénale.

Le projet doit être utilisé dans un cadre associatif ou professionnel, accompagné d'un
conseil juridique.

---

## Pourquoi ce projet

Les solutions forensic professionnelles (Cellebrite, Oxygen, Magnet AXIOM) coûtent des
dizaines de milliers d'euros par an — inaccessibles pour une petite association d'aide
aux victimes. Pourtant, ces associations sont en première ligne face à des victimes qui
suspectent que leur (ex-)conjoint installe des mouchards, lit leurs messages, suit leur
localisation.

`guardian` orchestre des **outils open-source éprouvés** (MVT, iLEAPP, ALEAPP, Autopsy)
dans une station d'analyse cohérente, avec une **rigueur probatoire** (hachage,
horodatage, reproductibilité) suffisante pour constituer un dossier utile à la justice.

---

## Ce qu'il fait

```
Téléphone branché → détection auto → acquisition → analyse → rapport horodaté & haché
```

- **Android** — Acquisition logique sans root : `adb bugreport`, inventaire `dumpsys`,
  services d'accessibilité, administrateurs d'appareil, permissions sensibles, pull des
  APK suspects. Comparaison contre blocklists de stalkerware connu (via MVT).
- **iOS** — Sauvegarde chiffrée via `libimobiledevice`, analyse via MVT et iLEAPP.
- **Corrélation** — Agrégation des signaux (forts / moyens / faibles) en un score avec
  niveau de confiance explicite.
- **Rapport** — Synthèse lisible (PDF) + journal probatoire complet (HTML + JSONL) +
  manifeste de rejeu pour contre-expertise.

Détail des signaux détectés, des méthodes d'acquisition et des limites : voir
[`CLAUDE.md`](./CLAUDE.md) (spécification technique complète).

---

## Principes de conception

1. **Lecture seule sur le support source** — aucune modification du téléphone analysé.
2. **100 % hors-ligne** — aucune donnée ne transite par un réseau, pas même localhost.
3. **Reproductibilité** — chaque résultat porte la trace exacte de la commande qui l'a
   produit ; un tiers peut rejouer les opérations déterministes.
4. **Honnêteté épistémique** — l'outil documente toujours ce qu'il N'A PAS pu observer.
5. **Robustesse d'abord** — en cas de doute, l'outil s'arrête et journalise ; jamais de
   résultat silencieusement dégradé.

---

## État du projet

**En développement actif — pré-1.0.** L'ossature (custody, provenance, détection USB)
est prioritaire, puis les modules d'acquisition, d'analyse, et enfin la GUI.

Feuille de route détaillée : voir la section 10 de [`CLAUDE.md`](./CLAUDE.md).

---

## Prérequis

### Système

- **Linux** (testé sur Budgie / base Ubuntu). Windows et macOS non supportés pour
  l'instant.
- Environ 20 Go d'espace libre par affaire (dépend du volume du téléphone).

### Dépendances externes (vérifiées au démarrage)

| Dépendance | Rôle | Installation (Debian/Ubuntu) |
|---|---|---|
| Python ≥ 3.11 | Runtime | `apt install python3.11` |
| `libimobiledevice-utils` | Acquisition iOS | `apt install libimobiledevice-utils` |
| `android-tools-adb` | Acquisition Android | `apt install android-tools-adb` |
| MVT | Analyse IOC/stalkerware | `pip install mvt` |
| iLEAPP / ALEAPP | Analyse artefacts | via `pip` ou clone GitHub |
| Autopsy + Java | Corroboration (optionnel) | installeur Autopsy |
| PyQt6 | Interface | `pip install PyQt6` |

Au démarrage, `guardian` vérifie chaque dépendance et capture sa version (pour la
provenance) ; les manquantes sont signalées clairement sans crash.

---

## Installation

> À compléter au fur et à mesure du développement.

```bash
# 1. Cloner
git clone <url-du-dépôt> guardian
cd guardian

# 2. Environnement Python
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .

# 3. Vérifier l'environnement
python -m guardian.core.environment
```

---

## Usage

> À compléter au fur et à mesure du développement.

```bash
# Lancer la GUI cockpit
python -m guardian

# Ou en CLI (à venir)
python -m guardian --help
```

Le workflow opérateur :

1. Ouvrir une affaire (identifiant, consentement du propriétaire consigné).
2. Brancher le téléphone (détection automatique iOS / guidée Android).
3. Lancer l'acquisition (sauvegarde iOS chiffrée / bugreport + dumpsys Android).
4. Lancer l'analyse (MVT, LEAPP, éventuellement Autopsy).
5. Générer le rapport (synthèse + journal probatoire + manifeste de rejeu).

---

## Livrable d'une affaire

Chaque analyse produit un dossier autonome et vérifiable :

```
dossier_affaire_2026-XXX/
├── rapport_synthese.pdf        # Lisible, pour la justice
├── journal_probatoire.html     # Détail de chaque résultat + provenance
├── journal_probatoire.jsonl    # Même chose, format machine
├── replay_manifest.jsonl       # Commandes rejouables pour contre-expertise
├── custody.jsonl               # Journal append-only horodaté
├── consent.json                # Consentement consigné
├── raw/                        # Toutes les sorties brutes, hachées
└── MANIFEST.sha256             # Hash de tout le dossier
```

Trois niveaux de lecture : le juge lit le PDF, l'expert ouvre le journal, le
contre-expert rejoue le manifeste.

---

## Cadre légal & éthique

L'utilisation de cet outil implique :

- L'**autorisation explicite et documentée** du propriétaire du téléphone analysé.
- L'accompagnement par un **conseil juridique** (avocat, structure spécialisée).
- Une **formation minimale** de l'opérateur aux principes forensic (chaîne de custody,
  interprétation des résultats, limites).
- Le respect des lois en vigueur (RGPD pour les données personnelles, code pénal pour
  l'accès aux STAD, code de procédure pénale pour la production de preuves).

L'analyse d'un appareil à l'insu de son propriétaire est **illégale** (article 226-1 et
suivants du code pénal français). Ne le faites pas.

---

## Contribuer

Voir [`CONTRIBUTING.md`](./CONTRIBUTING.md). Les règles sont **strictes** : le code
manipule des preuves et des données de victimes, la qualité passe avant la vélocité.

---

## Sécurité

Signaler une vulnérabilité : voir [`SECURITY.md`](./SECURITY.md). **Ne pas ouvrir
d'issue publique** pour une faille.

---

## Licence

[GNU General Public License v3.0](./LICENSE). Copyleft fort : toute réutilisation
distribuée doit rester ouverte. Ce choix est délibéré : il empêche qu'un acteur privé
s'approprie et ferme un outil destiné à des victimes.

---

## Remerciements

Ce projet n'existerait pas sans le travail d'équipes qui ont ouvert leur code :

- [MVT (Mobile Verification Toolkit)](https://github.com/mvt-project/mvt) —
  Amnesty International Security Lab
- [iLEAPP / ALEAPP](https://github.com/abrignoni) — Alexis Brignoni & contributeurs
- [Autopsy](https://www.autopsy.com/) — Basis Technology
- [libimobiledevice](https://libimobiledevice.org/) — communauté

Et plus largement : les associations d'aide aux victimes qui documentent les cas et
identifient les menaces, notamment autour du [Coalition Against Stalkerware](https://stopstalkerware.org/).
