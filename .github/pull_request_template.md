<!--
  Merci de contribuer à guardian. Ce projet manipule des preuves et des données de
  victimes : la qualité passe avant la vélocité (cf. CONTRIBUTING.md).
  Une PR sans test ni description d'impact sera renvoyée en révision.
-->

## Ce que change cette PR

<!-- Décrire clairement le changement, en une à trois phrases. -->

## Pourquoi

<!-- Lien vers l'issue de discussion. Les zones sensibles (core/, acquisition,
     format du dossier d'affaire, dépendances) exigent une issue préalable. -->

Issue liée : #

## Impact sur custody / provenance / format d'affaire

<!--
  Réponse OBLIGATOIRE (« aucun » est valide, mais doit être présent).
  - La chaîne de custody est-elle affectée ?
  - La provenance des Finding change-t-elle ?
  - Le format du dossier d'affaire reste-t-il rétrocompatible ?
-->

- [ ] Aucun impact sur la custody, la provenance ou le format d'affaire.
- [ ] Impact décrit ci-dessous :

## Conformité aux garde-fous (cf. CLAUDE.md §2)

- [ ] **Lecture seule** : aucune écriture sur le support source du téléphone.
- [ ] **Hors-ligne** : aucun appel réseau introduit (même localhost).
- [ ] **Pas de secret en clair** dans le code, les logs, les commits, les rapports.
- [ ] **Pas de `subprocess` direct** en dehors de `TracedExecutor`.
- [ ] **Pas d'`except` silencieux** ; toute exception ignorée est justifiée par commentaire.

## Tests

- [ ] Tests ajoutés / mis à jour et verts localement.
- [ ] Aucune donnée réelle de victime dans les tests (fixtures synthétiques uniquement).

Comment tester manuellement :

<!-- Étapes précises. -->

## Documentation

- [ ] `CLAUDE.md` / `README.md` / docstrings mis à jour si un comportement observable change.
- [ ] `CHANGELOG.md` mis à jour (section « Non publié »).
