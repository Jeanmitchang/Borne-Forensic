# Protocole d'essai sur appareils réels — guardian

> **Objet.** Le pipeline (détection → acquisition → analyse → corrélation → rapport)
> est validé avec des **outils simulés** : les tests valident *notre* logique
> (parsing, provenance, custody, formulation), pas le comportement réel d'`adb`,
> `idevicebackup2`, `ideviceinfo`, `mvt-*`. Ce document cadre la **confrontation aux
> vraies sorties**.
>
> **Doctrine.** *Observer d'abord, corriger ensuite.* On ne « corrige » pas un parseur
> sur des suppositions : on capture la vraie sortie, on note l'écart, **puis** on
> décide. Chaque écart observé devient une entrée de la grille (§6) et, si nécessaire,
> une issue. Les corrections spéculatives sont proscrites (CLAUDE.md §12 : ne pas
> inventer).
>
> **Rappel garde-fous (CLAUDE.md §2).** Lecture seule sur le support ; 100 % hors-ligne ;
> aucun secret en clair. Les essais se font **sur des appareils de test dont vous êtes
> propriétaire**, jamais sur le téléphone d'une victime réelle. Consentement consigné
> (`consent.json`) même en essai.

---

## 1. Matériel & environnement

- **Poste d'analyse** : Linux (cible Budgie/Ubuntu). Les essais terrain ne se font
  **pas** sous Windows (dev uniquement) — la cible de production est Linux.
- **Appareil Android de test** : un téléphone jetable/rincé, débogage USB activé,
  idéalement avec **un faux « stalkerware »** contrôlé installé (voir §4.0) pour
  vérifier qu'on le *voit*, et un second essai *propre* pour vérifier qu'on ne crie
  pas au loup à tort.
- **Appareil iOS de test** : iPhone rincé, appairé (« Faire confiance »), code connu.
- **Dépendances** : lancer d'abord le diagnostic intégré —

  ```bash
  python -m guardian.core.environment
  ```

  Il liste présence + version d'`adb`, `libimobiledevice-utils`, `mvt-*`, Java/Autopsy.
  **Ne pas commencer un essai avec une dépendance manquante** (échouer bruyamment §2.6).
- **Versions à noter** (elles conditionnent les écarts) : `adb --version`,
  `idevicebackup2 --version` (ou paquet `libimobiledevice`), `mvt-ios/--version`,
  `mvt-android --version`, version d'Android et d'iOS des appareils.

---

## 2. Principe de confrontation

Pour chaque relevé, le code lance une **commande précise**, en **suppose une forme**,
et en **déduit un `Finding`**. L'essai consiste à :

1. lancer *à la main* la même commande que le code (colonne « Commande réelle » §4/§5) ;
2. comparer la vraie sortie à ce que **notre parseur** attend ;
3. lancer ensuite le pipeline guardian et vérifier que le `Finding` produit **dit vrai** ;
4. consigner tout écart dans la grille §6.

La sortie brute de chaque commande est de toute façon archivée par le `TracedExecutor`
dans `raw/F-xxxx.out` (hachée) : **conservez le dossier d'affaire de l'essai**, il est
la pièce justificative de l'écart.

---

## 3. Déroulé d'un essai complet (pipeline)

Deux façons de rejouer le pipeline réel :

- **GUI** : `python -m guardian.gui.app` (cockpit) — ouvrir une affaire, brancher,
  détecter, acquérir, analyser.
- **Orchestrateur** (scriptable, sans PyQt) : `guardian/affaire.py` → classe `Affaire`
  (`ouvrir → detecter → acquerir → analyser → correler → generer_rapport`).

À la fin, ouvrir `journal_probatoire.html` et vérifier chaque `Finding` **contre la
réalité observée**. Le `rapport_synthese` ne doit jamais affirmer plus que ce que la
méthode permet (formulation « parmi ceux observables… », CLAUDE.md §11).

---

## 4. Android — commandes exactes lancées par le code

> Source : `guardian/acquisition/android_logical.py`. Le code préfixe tout par
> `adb -s <série>`. La série est celle de `adb devices`.

### 4.0 Préparer un signal FORT contrôlé (recommandé)
Installer une app de test bénigne et **lui accorder** un service d'accessibilité ou
l'accès aux notifications (Réglages → Accessibilité / Accès aux notifications). But :
vérifier que guardian la fait bien remonter en **FORT**, avec le bon nom de composant.

### 4.1 Signaux forts (Severity.STRONG possible)

| Relevé | Commande réelle (à lancer à la main) | Ce que le parseur suppose |
|---|---|---|
| Accessibilité | `adb -s <s> shell settings get secure enabled_accessibility_services` | `null`/vide, ou composants `pkg/cls` séparés par `:` |
| Écouteurs notif. | `adb -s <s> shell settings get secure enabled_notification_listeners` | idem |
| Admins appareil | `adb -s <s> shell dumpsys device_policy` | **heuristique** : tout `pkg/cls` trouvé par regex |
| Paquets tiers | `adb -s <s> shell pm list packages -3` | lignes `package:<nom>` |

### 4.2 Captures lourdes

| Capture | Commande réelle | Piège à surveiller |
|---|---|---|
| Bugreport | `adb -s <s> bugreport <cible.zip>` | appareils anciens (<7) : dump texte, pas de zip |
| Pull stockage | `adb -s <s> pull /sdcard <dossier>` | fichiers illisibles → exit ≠ 0 partiel (géré si des fichiers existent) |
| APK suspect | `adb -s <s> shell pm path <pkg>` puis `adb -s <s> pull <chemin> <dest>` | **splits** : `pm path` renvoie plusieurs lignes ; le code ne pull que la 1ʳᵉ |

---

## 5. iOS — commandes exactes lancées par le code

> Source : `guardian/acquisition/ios_backup.py`. Préfixe `-u <udid>`.

| Étape | Commande réelle | Ce que le code en déduit |
|---|---|---|
| État chiffrement | `ideviceinfo -u <udid> -q com.apple.mobile.backup -k WillEncrypt` | `true/yes/1` → ACTIF ; `false/no/0` → INACTIF ; sinon INCONNU |
| Activation (opt-in) | `idevicebackup2 -u <udid> encryption on` (mot de passe ×2 via **stdin**) | modifie l'appareil — **jamais** sans opt-in explicite (§2) |
| Sauvegarde | `idevicebackup2 -u <udid> backup <dossier>` | crée un sous-dossier UDID ; on hache `Manifest/Status/Info.plist` |

**Attention essai** : `idevicebackup2 backup` exige souvent de **déverrouiller** et de
**faire confiance** ; une grosse sauvegarde peut dépasser le `timeout_lourd` (1800 s).
Notez la durée réelle.

---

## 6. Grille de consignation des écarts

Une ligne par écart observé. Reporter aussi dans une issue si correction nécessaire.

| # | Module / relevé | Commande | Attendu (parseur) | Observé (réel) | Impact Finding | Action |
|---|---|---|---|---|---|---|
| 1 | | | | | | |
| 2 | | | | | | |

**Impact Finding** = le `Finding` produit est-il *juste* ? (bon niveau de gravité, bon
libellé, pas de faux FORT, pas de fausse absence). C'est le seul critère qui compte.

---

## 7. Points de fragilité priorisés (audit du code)

> Résultat d'une revue statique des runners. Ce sont les endroits où **notre logique**
> risque de diverger du réel. À vérifier **en priorité** pendant l'essai. Priorité
> décroissante (P0 = à trancher en premier, risque probatoire le plus élevé).

### P0 — risque de Finding faux, ou trou fonctionnel

- **[P0-A] `dumpsys device_policy` parsé par regex** (`android_logical._parser_composants_admin`).
  La sortie n'a **pas de format stable** ; on relève *tout* motif `pkg/cls`. Un
  administrateur d'appareil est un **signal FORT** : un faux positif ici est un faux pas
  juridique. *À vérifier* : comparer la liste extraite à la réalité (nombre et noms
  d'admins réellement actifs). Si bruit → restreindre l'heuristique (ancrage sur les
  sections « Admin: » de la sortie) plutôt que regex globale.

- **[P0-B] MVT iOS + sauvegarde chiffrée = angle mort** (`mvt_runner.MVTIOSRunner`).
  La doctrine recommande la sauvegarde **chiffrée** (capture plus de données : trousseau,
  santé…). Or `mvt-ios check-backup` a besoin du **mot de passe** pour lire une
  sauvegarde chiffrée (via env `MVT_IOS_BACKUP_PASSWORD` ou `--backup-password`), et le
  runner **ne le fournit pas**. *Conséquence probable* : sur une vraie sauvegarde
  chiffrée, MVT échoue ou n'analyse rien — silencieusement « aucun IOC ». *À trancher* :
  transmettre le mot de passe **par variable d'environnement** au sous-processus (jamais
  en argument — §2), non tracée par le `TracedExecutor`. **Ce point ne nécessite pas le
  terrain pour être décidé** ; le terrain le confirmera.

- **[P0-C] Propagation du code de sortie via `adb shell`.** Historiquement, `adb shell
  <cmd>` renvoyait `0` même si `<cmd>` échouait (avant le shell protocol v2). Le code
  décide « échec » sur `exit_code != 0` ; si l'exit n'est pas propagé, une commande
  `settings`/`dumpsys` en échec verrait sa **sortie d'erreur parsée comme donnée**
  (faux composants, ou fausse absence). *À vérifier* : provoquer une erreur
  (`adb -s <s> shell settings get secure inexistant ; echo "exit=$?"`) et regarder si le
  code retour remonte. Si non propagé sur la version cible → détecter les marqueurs
  d'erreur dans stdout en plus du code retour.

### P1 — perte de preuve / robustesse

- **[P1-D] APK en splits non capturés** (`android_logical.extraire_apk`). Les apps
  modernes ont `base.apk` + `split_config.*.apk` ; le code ne pull que `chemins[0]`. Un
  stalkerware distribué en bundle serait figé **incomplet**. *Envisager* : puller
  **tous** les chemins de `pm path`.

- **[P1-E] Timeout sauvegarde iOS** (`timeout_lourd=1800 s`). Un iPhone bien rempli peut
  dépasser 30 min. *Noter la durée réelle* ; ajuster si dépassement.

- **[P1-F] Exit code MVT non-zéro bénin.** MVT peut retourner ≠ 0 pour des
  avertissements (module absent, artefact manquant) ; le code marque alors
  `complete=False` (analyse non concluante). *Vérifier* les codes réels et distinguer
  avertissement vs échec réel.

### P2 — forme de sortie / interaction

- **[P2-G] `settings get` multi-ligne / valeurs OEM.** Le parseur `split(':')` suppose
  une valeur mono-ligne. Vérifier sur plusieurs OEM (Samsung, Xiaomi…).

- **[P2-H] Sous-dossier UDID de la sauvegarde.** `idevicebackup2 backup <dir>` écrit
  sous `<dir>/<UDID>/`. Le `rglob("*")` récursif devrait le voir — *confirmer* que les
  manifestes sont bien hachés.

- **[P2-I] Ordre des invites `encryption on`.** Selon la version, l'outil peut demander
  l'ancien mot de passe avant le nouveau. Le code envoie `mdp\nmdp\n`. *Vérifier* si
  opt-in utilisé.

---

## 8. Après l'essai

1. Remplir la grille §6 et le tableau des versions (§1).
2. Ouvrir une issue par écart nécessitant correction (référencer le `F-xxxx` et
   joindre le `raw/F-xxxx.out` de l'essai comme pièce).
3. Toute correction de runner suit la convention de nommage des refontes (CLAUDE.md §9)
   et **ré-exécute la chaîne qualité** (`ruff` + `mypy --strict` + `pytest`) au vert.
4. Ajouter une entrée datée au `CARNET_DE_BORD.md` (§7 Journal des sessions).
