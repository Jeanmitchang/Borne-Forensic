# Checklist — mise en place d'un appareil Android de test

> **But.** Préparer un téléphone Android **de test** pour les essais terrain
> (`docs/ESSAIS_TERRAIN.md`), avec des **signaux forts contrôlés** afin de vérifier
> que guardian les détecte (vrai positif) *et* qu'il ne crie pas au loup sur un
> appareil propre (vrai négatif).
>
> **Cadre (rappel §2).** Uniquement un appareil **dont tu es propriétaire**, rincé,
> sans données réelles de victime. Consentement consigné (`consent.json`) même en
> test. Les « signaux » sont créés avec des **apps bénignes** que tu contrôles —
> **jamais** un vrai stalkerware (risque réel, y compris pour toi).
>
> **Où.** La préparation de l'appareil (sections B–C) est indépendante de l'OS ;
> la partie `adb` / guardian (sections A, D–I) se fait sur le **poste d'analyse Linux**
> (cible du projet), pas sous Windows.

---

## A. Poste d'analyse (Linux) — prérequis

- [ ] `adb` installé : `sudo apt install android-tools-adb` (Ubuntu/Budgie).
- [ ] Diagnostic guardian au vert pour Android : `python -m guardian.core.environment`
      (doit lister `adb` présent + version).
- [ ] Accès USB non-root : l'utilisateur est dans le groupe `plugdev` et/ou des règles
      udev Android sont en place (sinon `adb` verra l'appareil en `no permissions`).
- [ ] **Câble USB de données** (beaucoup de câbles sont « charge seule » → l'appareil
      n'apparaîtra jamais dans `adb devices`).

---

## B. Préparer l'appareil — état de départ propre

- [ ] Appareil **réinitialisé** (réglages d'usine) ou dédié aux tests, sans compte
      personnel sensible.
- [ ] Noter le **modèle**, le **fabricant** et la **version d'Android** (utile car le
      parsing varie selon les OEM — cf. `ESSAIS_TERRAIN.md` §7 P2-G) :
      ```bash
      adb shell getprop ro.product.manufacturer
      adb shell getprop ro.product.model
      adb shell getprop ro.build.version.release
      ```
      *(ces commandes ne fonctionneront qu'après la section D)*

---

## C. Activer le débogage USB

- [ ] **Options pour les développeurs** : Réglages → À propos du téléphone → taper
      **7 fois** sur « Numéro de build » jusqu'à « Vous êtes développeur ».
- [ ] Réglages → Système → **Options pour les développeurs** → activer **Débogage USB**.
- [ ] *(Recommandé pour un essai propre)* dans le même écran, **Révoquer les
      autorisations de débogage USB** (repart d'une clé RSA vierge → on testera
      l'autorisation en D).

---

## D. Brancher & autoriser la clé RSA

- [ ] Brancher l'appareil au poste Linux (câble données).
- [ ] `adb devices -l` → l'appareil apparaît d'abord en **`unauthorized`**.
- [ ] Sur le téléphone : accepter « **Autoriser le débogage USB ?** », cocher
      « Toujours autoriser depuis cet ordinateur ».
- [ ] `adb devices -l` → l'appareil est maintenant **`device`** (prêt).
- [ ] En cas de blocage : `adb kill-server && adb start-server`, rebrancher, revérifier.

**Miroir de ce que guardian diagnostique** (`detection/usb_watch.py`) : un appareil
`unauthorized`/`offline` doit être signalé comme **non prêt** avec un diagnostic clair
(clé RSA non autorisée). C'est déjà un point à vérifier en D.

---

## E. Vérifier la détection par guardian

- [ ] Lancer la GUI : `python -m guardian.gui.app`.
- [ ] Ouvrir une affaire (dossier, identifiant, opérateur, propriétaire, description)
      → consentement consigné.
- [ ] Bouton **Détecter** → l'appareil Android doit être listé **prêt**, avec sa série.
- [ ] Débrancher → re-détecter : guardian doit signaler l'absence (pas de faux positif).

---

## F. Créer des signaux FORTS contrôlés (le cœur du test)

> Objectif : activer manuellement chacun des trois vecteurs directs de surveillance
> (§5 CLAUDE.md), avec une app **identifiable**, puis vérifier que guardian le remonte
> en **FORT** avec le **bon nom de composant**. Après chaque activation, comparer à la
> commande brute (colonne de droite) *avant* de lancer guardian.

| Vecteur | Activation (bénigne, contrôlée) | Vérification brute |
|---|---|---|
| **Service d'accessibilité** | Réglages → Accessibilité → **TalkBack** (préinstallé Google) → activer | `adb shell settings get secure enabled_accessibility_services` |
| **Administrateur d'appareil** | Réglages → Sécurité → Applis d'administration → activer **« Localiser mon appareil »** | `adb shell dumpsys device_policy` |
| **Écouteur de notifications** | Réglages → Notifications → Accès aux notifications → activer une app tierce installée | `adb shell settings get secure enabled_notification_listeners` |

- [ ] Après chaque activation, la commande brute doit **lister le composant** attendu.
- [ ] Lancer guardian (acquisition/inventaire) → le Finding correspondant doit être
      **STRONG** et **nommer le bon composant**.

> ⚠️ **TalkBack** modifie l'interaction tactile (navigation par double-tap). Pour le
> désactiver ensuite : maintenir simultanément **Volume + / Volume −** 3 s, ou refaire
> le chemin Réglages.
>
> 🎯 **Point P0-A à surveiller** (`ESSAIS_TERRAIN.md` §7) : sur l'admin d'appareil,
> guardian extrait les composants de `dumpsys device_policy` **par regex**. Note le
> **nombre réel** d'administrateurs actifs et leurs noms, puis compare à ce que
> guardian liste : tout composant **en trop** = faux positif de l'heuristique (à
> corriger). C'est le test le plus important de la session.

> 🧪 **Pour un jeu de test reproductible et couvrant les 3 vecteurs proprement**, une
> **APK de test dédiée** (déclarant un `AccessibilityService`, un
> `NotificationListenerService` et un `DeviceAdminReceiver` bien nommés) est l'idéal.
> Elle n'existe pas encore — demande-la si tu veux la construire (petit projet Android
> minimal, bénin).

---

## G. Scénario de contrôle négatif (vrai négatif)

- [ ] Désactiver **tous** les vecteurs de la section F.
- [ ] Relancer l'inventaire guardian → aucun signal FORT ; la formulation doit être
      « **aucun indicateur détecté parmi ceux observables sans root** » (jamais
      « appareil sain », §11).

---

## H. Références à relever (pour la grille `ESSAIS_TERRAIN.md` §6)

- [ ] `adb --version` · version d'Android · modèle · fabricant.
- [ ] Composants **attendus** vs **remontés** par guardian, pour chaque vecteur activé.
- [ ] Tout écart de parsing (multi-ligne, bruit regex, code retour) → une ligne dans
      la grille §6, avec le `raw/F-xxxx.out` correspondant comme pièce.

---

## I. Remise à zéro après essais

- [ ] Désactiver TalkBack, l'admin « Localiser mon appareil », l'accès notifications.
- [ ] Options développeur → **Révoquer les autorisations de débogage USB**.
- [ ] *(Optionnel)* désactiver le débogage USB / les options développeur.
- [ ] Conserver le **dossier d'affaire** de l'essai (custody + `raw/`) : c'est la pièce
      justificative des écarts observés.
