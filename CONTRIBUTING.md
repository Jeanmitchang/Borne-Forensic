# Contribuer à guardian

> Ce projet n'est pas un logiciel comme les autres. Le code manipule des **preuves**
> destinées à la justice et des **données de victimes** de violences. Une régression
> silencieuse, une dépendance douteuse ou une modification bien intentionnée mais
> non tracée peut nuire à une personne réelle. Les règles ci-dessous sont strictes ;
> elles ne le sont pas par bureaucratie mais parce que la qualité est une exigence
> éthique.

Merci de lire ce document **avant** d'ouvrir une issue ou une pull request.

---

## 1. Avant de contribuer

- Lisez [`CLAUDE.md`](./CLAUDE.md) en entier. C'est la spécification du projet.
- Lisez [`SECURITY.md`](./SECURITY.md), en particulier le modèle de menace (section 3).
- Familiarisez-vous avec les **priorités du projet** :
  1. Robustesse / gestion d'erreurs / logs
  2. Couverture détection
  3. Rigueur juridique / chaîne de custody
  4. Ergonomie

  Toute contribution doit servir ces priorités **dans cet ordre**. Une contribution qui
  améliore l'ergonomie au prix de la custody sera refusée.

---

## 2. Ce qui est bienvenu

- Corrections de bugs, en particulier ceux touchant à la robustesse.
- Ajout de tests, surtout sur les modules `core/` (custody, provenance, environment).
- Amélioration de la couverture de détection (nouveaux signaux, nouveaux IOC).
- Documentation, traductions, améliorations d'ergonomie sans compromis sur le reste.
- Retours d'usage terrain de la part d'associations et d'experts forensic.

## 3. Ce qui n'est PAS bienvenu

- Ajout de fonctionnalité **en ligne** ou de télémétrie, même optionnelle. Le projet
  est hors-ligne par conception.
- Ajout de dépendance non justifiée par une **nécessité fonctionnelle claire**. Chaque
  dépendance est une surface d'attaque supplémentaire.
- Bypass de la couche `TracedExecutor`. Aucune commande externe ne s'exécute hors
  provenance. Une PR qui appelle `subprocess` directement sera refusée.
- Écriture sur le support source du téléphone analysé, sous quelque forme que ce soit.
- Fonctionnalités « offensives » : root, jailbreak, exploitation de vulnérabilités.
  Ce n'est pas le rôle de l'outil et cela sortirait du cadre légal.

---

## 4. Signaler un bug

Ouvrez une issue avec :

- La **version / commit** utilisé.
- L'**environnement** (distribution Linux, version Python, versions des outils tiers
  détectés au démarrage).
- Les **étapes de reproduction** précises.
- Le **comportement attendu** vs **observé**.
- Les logs pertinents, **expurgés de toute donnée sensible** (identifiants d'affaire,
  identifiants de device, contenus d'artefacts). Si vous ne pouvez pas expurger sans
  perdre l'information, ne postez pas publiquement — passez par le canal privé décrit
  dans `SECURITY.md`.

---

## 5. Proposer une évolution

Ouvrez d'abord une **issue de discussion** avant d'écrire du code, surtout si la
proposition touche :

- Le socle `core/` (custody, provenance, environment).
- L'acquisition (règle de lecture seule sur le support source).
- Le format du dossier d'affaire (compatibilité descendante).
- Les dépendances.

Une PR non discutée sur ces zones a peu de chances d'être fusionnée.

---

## 6. Règles de code

Ces règles reprennent et durcissent la section 9 de `CLAUDE.md`.

### Style

- **Python 3.11+**. Type hints partout. `dataclasses` pour les structures.
- Commentaires et messages utilisateur en **français**.
- Logs structurés via `core/logging_conf.py`. **Aucun `print`** en dehors des scripts
  ponctuels.
- **Aucun secret en clair** dans le code, les logs, les commits, les rapports (mots de
  passe de sauvegarde iOS, chemins contenant des noms de victimes, etc.).

### Robustesse

- Échouer proprement et bruyamment. Interdiction d'`except: pass`, d'`except Exception:
  pass`, ou d'`except` silencieux. Une exception ignorée doit être justifiée par un
  commentaire.
- Validation systématique des entrées (chemins, identifiants, sorties d'outils tiers).
  **Ne jamais faire confiance aveuglément à la sortie d'`adb` ou de MVT.**
- Construction sûre des appels externes : pas de `shell=True` avec concaténation. Passer
  les arguments en liste, via `TracedExecutor`.

### Provenance

- **Aucun appel direct à `subprocess`** dans les modules d'acquisition ou d'analyse. Ils
  doivent passer par `TracedExecutor`.
- Toute nouvelle méthode d'analyse doit produire des `Finding` typés avec provenance
  complète et niveau de reproductibilité explicite (`DETERMINISTIC`,
  `POINT_IN_TIME`, `ENVIRONMENT_DEPENDENT`).

### Tests

- Tout ajout dans `core/` **doit** être couvert par des tests unitaires.
- Les modules d'acquisition et d'analyse doivent avoir des tests d'intégration avec des
  fixtures (sorties `adb` mockées, backups iOS de test) — pas de tests dépendant d'un
  vrai téléphone en CI.
- Les tests ne doivent contenir **aucune donnée réelle** de victime. Utiliser des
  fixtures synthétiques.

### Dépendances

- Toute nouvelle dépendance doit être :
  - **Justifiée** dans la PR (pourquoi elle est nécessaire, alternatives évaluées).
  - **Épinglée** à une version précise dans `pyproject.toml`.
  - **Vérifiée** côté licence (compatible GPLv3) et côté maintenance (projet actif, pas
    d'auteur unique disparu).
- Les outils tiers orchestrés (adb, mvt, libimobiledevice…) restent des dépendances
  **système**, pas embarquées.

---

## 7. Processus de pull request

1. **Fork** puis branche dédiée, nom explicite : `fix/custody-hash-race`,
   `feat/android-notification-listeners`, etc.
2. **Commits atomiques**, messages clairs en français ou anglais, en mode impératif
   (« ajoute X », « corrige Y », pas « ajouté X »).
3. **Tests** : ajoutés/mis à jour, verts localement.
4. **Documentation** : `CLAUDE.md`, `README.md` ou docstrings mis à jour si la PR change
   un comportement observable.
5. **Description de PR** :
   - Ce que la PR change.
   - Pourquoi (lien vers l'issue).
   - Impact sur la custody, la provenance ou le format du dossier d'affaire (« aucun »
     est une réponse valide, mais elle doit être présente).
   - Comment tester manuellement.
6. **Revue** : au moins une revue est requise. Les PR touchant `core/` requièrent une
   revue particulièrement attentive.

Les PR incomplètes (sans test, sans description d'impact) seront demandées en révision
et non fusionnées telles quelles.

---

## 8. Convention de nommage des versions de fichiers

En cas de refonte importante d'un fichier (correctif majeur, changement d'approche), la
convention est :

```
module_v2.1_fix-adb-timeout.py
```

- Le suffixe explicite ce qui change.
- L'ancien fichier reste versionné dans l'historique Git ; la PR doit expliciter la
  différence de comportement.

Cette convention s'applique aux **refontes** ; les corrections mineures restent en
place, versionnées par Git normalement.

---

## 9. Code de conduite

- Respect et bienveillance dans les échanges, sur les issues comme dans les PR.
- Pas de tolérance pour le harcèlement, les propos discriminatoires ou l'intimidation.
- Rappelez-vous du contexte : ce projet existe parce que des personnes subissent des
  violences. La rigueur n'exclut pas l'humanité.

Les manquements sont traités par les mainteneurs, avec avertissement puis exclusion si
nécessaire.

---

## 10. Licence des contributions

En soumettant une PR, vous acceptez que votre contribution soit distribuée sous la
même licence que le projet : **GNU General Public License v3.0** (voir
[`LICENSE`](./LICENSE)).

---

Merci de contribuer. Chaque amélioration peut aider concrètement une personne en
danger — ne l'oubliez pas quand vous cliquez sur « Merge ».
