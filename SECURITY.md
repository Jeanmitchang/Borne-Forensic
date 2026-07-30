# Politique de sécurité

> Ce projet est un outil d'analyse forensic destiné à aider des associations à détecter
> des logiciels de surveillance (stalkerware) sur les smartphones de victimes de
> cyberharcèlement et de violences conjugales. Il manipule des **données extrêmement
> sensibles** et s'inscrit dans un **contexte où la sécurité d'une personne peut être en
> jeu**. La sécurité n'est pas une option : c'est une condition de l'usage.

---

## 1. Signaler une vulnérabilité

**Ne créez pas d'issue publique pour une faille de sécurité.** Une divulgation publique
prématurée pourrait exposer des victimes ou alerter des agresseurs.

- Signalez en privé à : `<À COMPLÉTER : email de contact sécurité>`
- Chiffrez votre message si possible : `<À COMPLÉTER : clé PGP / Signal>`
- Délai de première réponse visé : **72 heures**.
- Merci d'inclure : description, étapes de reproduction, impact estimé, version/commit
  concerné, et toute piste de correctif.

Nous nous engageons à traiter les signalements de bonne foi et à créditer les personnes
qui le souhaitent après correction.

---

## 2. Périmètre

### Dans le périmètre

- Le code de ce dépôt (acquisition, analyse, corrélation, rapport, GUI, custody).
- La gestion des secrets (mots de passe de sauvegarde, etc.).
- L'intégrité de la chaîne de custody et la traçabilité des résultats.
- Toute fuite de données sensibles (vers le réseau, les logs, le système de fichiers).

### Hors périmètre

- Les vulnérabilités des **outils tiers orchestrés** (MVT, iLEAPP, ALEAPP, Autopsy,
  `libimobiledevice`, `adb`) : signalez-les à leurs projets respectifs. Signalez-nous en
  revanche tout usage **non sécurisé** que nous en ferions.
- Les failles du système d'exploitation hôte.

---

## 3. Modèle de menace propre à ce projet

Ce projet a des adversaires inhabituels pour un logiciel. Les contributeurs doivent les
garder en tête à chaque ligne de code.

### 3.1 L'agresseur / la personne surveillante

- Peut avoir un **accès physique** ou distant au téléphone analysé.
- Peut chercher à **détecter que le téléphone a été analysé** (tipping-off), ce qui
  pourrait déclencher une escalade de violence.
  → **Conséquence** : l'acquisition doit rester en **lecture seule** et minimiser toute
  trace sur le support source. Aucune écriture, aucune installation, aucune modification
  de réglage sur le téléphone analysé.
- Peut être l'éditeur d'un stalkerware cherchant à contourner la détection.
  → **Conséquence** : les listes d'IOC/signatures et la logique de détection doivent
  pouvoir être mises à jour ; ne pas considérer une détection comme exhaustive.

### 3.2 La fuite de données de la victime

- Les artefacts extraits (sauvegarde iOS, pull Android, bugreport) contiennent des
  données **hautement personnelles** (messages, localisation, santé, médias).
  → **Conséquences** :
  - L'outil est **100 % hors-ligne**. Aucune donnée ne doit transiter par un réseau,
    **même localhost**. Toute tentative d'exfiltration est un bug critique.
  - Les **secrets** (mot de passe de sauvegarde iOS, etc.) ne doivent **jamais**
    apparaître en clair dans les logs, les rapports, ou la custody.
  - Les dossiers d'affaire doivent rester sur la machine de l'opérateur, sous son
    contrôle.

### 3.3 L'intégrité probatoire

- Un résultat non traçable ou altérable est inexploitable, voire dangereux (faux
  positif opposable à la victime).
  → **Conséquences** :
  - Toute commande passe par le `TracedExecutor` (porte unique). Aucun module n'exécute
    de commande hors traçabilité.
  - Le journal de custody est **append-only** ; toute écriture est horodatée (UTC) et
    chaque artefact haché (SHA-256).
  - L'outil ne conclut jamais « téléphone sain » ; il documente toujours ses limites.

---

## 4. Règles de sécurité pour les contributeurs

- **Jamais de secret en clair** dans le code, les logs, les commits ou les rapports.
- **Aucun appel réseau** dans le chemin d'exécution principal (l'outil est hors-ligne).
  Les seules exceptions admissibles (ex. mise à jour manuelle des listes d'IOC) doivent
  être explicites, optionnelles, et déclenchées par l'opérateur.
- **Lecture seule sur le support source** : toute opération d'acquisition doit être
  démontrée non destructive et non modifiante.
- **Échouer bruyamment** : en cas de doute sur l'intégrité d'une acquisition, stopper et
  journaliser, jamais produire un résultat silencieusement dégradé.
- **Valider toutes les entrées** : chemins de fichiers, identifiants de device, sorties
  d'outils tiers (ne jamais faire confiance aveuglément à la sortie d'`adb` ou de MVT).
- **Pas d'injection de commande** : construire les appels externes de façon sûre (pas de
  concaténation shell non échappée à partir d'entrées non maîtrisées).
- **Dépendances** : épingler les versions, surveiller les avis de sécurité.

---

## 5. Versions supportées

Le projet est en développement actif. Tant qu'aucune version stable (1.0) n'est publiée,
seul le dernier état de la branche principale reçoit des correctifs de sécurité.

| Version | Supportée |
|---|---|
| `main` (développement) | ✅ |
| Pré-1.0 antérieures | ❌ |

Ce tableau sera mis à jour à la première version stable.

---

## 6. Avertissement d'usage

Cet outil produit des **premières réponses** et un **faisceau d'indices**. Il **ne se
substitue pas à une expertise judiciaire** réalisée par un expert mandaté. Son usage doit
s'inscrire dans un cadre légal (accès autorisé au support, accompagnement juridique) et
les résultats doivent être interprétés par une personne compétente. Une mauvaise
utilisation peut nuire à la personne que l'on cherche à protéger.
