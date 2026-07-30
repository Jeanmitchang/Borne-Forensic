"""Hiérarchie d'exceptions métier de guardian.

Toutes les erreurs prévisibles du domaine dérivent de :class:`GuardianError`, ce
qui permet à l'appelant de rattraper l'ensemble des erreurs métier sans capturer
par mégarde des erreurs système. Conformément aux garde-fous (CLAUDE.md §2, §6),
le projet **échoue bruyamment** : on lève une exception explicite plutôt que de
poursuivre sur un état dégradé.

Note de conception — ``EnvironmentCheckError`` (et non ``EnvironmentError``) :
le nom builtin ``EnvironmentError`` est un alias déprécié d'``OSError``. Le
réutiliser masquerait le builtin et créerait un piège pour un contributeur
écrivant ``except EnvironmentError``. On choisit donc un nom distinct.
"""

from __future__ import annotations


class GuardianError(Exception):
    """Racine de toutes les erreurs métier de guardian.

    Rattraper ``GuardianError`` capture toute erreur *attendue* du domaine
    (environnement, custody, provenance, acquisition, analyse, validation) sans
    avaler les erreurs de programmation ou système (``ValueError``, ``OSError``…),
    qui doivent rester visibles.
    """


class EnvironmentCheckError(GuardianError):
    """Prérequis système absent ou incompatible.

    Levée par la vérification d'environnement (Étape 1, ``core.environment``)
    quand une dépendance obligatoire manque ou n'est pas exploitable.
    """


class CustodyError(GuardianError):
    """Atteinte à l'intégrité de la chaîne de custody.

    Hachage impossible, journal append-only non inscriptible, consentement
    absent ou invalide, manifeste incohérent… Toute condition qui compromettrait
    la valeur probatoire du dossier d'affaire.
    """


class ProvenanceError(GuardianError):
    """Échec de traçabilité d'une exécution.

    Levée quand la porte unique ``TracedExecutor`` ne peut garantir une trace
    complète (binaire introuvable, archivage de la sortie brute impossible,
    hachage de sortie échoué). Un résultat sans provenance fiable est inexploitable.
    """


class ValidationError(GuardianError):
    """Entrée invalide.

    Chemin, identifiant de device, ou sortie d'outil tiers ne respectant pas le
    format attendu. Ne jamais faire confiance aveuglément aux entrées ni à la
    sortie d'``adb`` ou de MVT (CLAUDE.md §9).
    """


class AcquisitionError(GuardianError):
    """Échec d'une opération d'acquisition (Étapes 3-4).

    Couvre notamment toute condition mettant en péril la règle de **lecture
    seule** sur le support source : dans le doute, on stoppe et on journalise.
    """


class AnalysisError(GuardianError):
    """Échec d'une opération d'analyse (Étapes 5-7, 10).

    Outil d'analyse (MVT, LEAPP, Autopsy) en erreur, ou sortie inexploitable.
    """
