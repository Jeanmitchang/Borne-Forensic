"""Tests du runner MVT iOS (``guardian.analysis.mvt_runner.MVTIOSRunner``)."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

from guardian.analysis.mvt_runner import MVTIOSRunner
from guardian.core.custody import JournalCustody
from guardian.core.provenance import Severity, TracedExecutor

# mvt-ios simulé : crée le dossier de sortie et un fichier de détection.
_MVT_DETECTE = """
import os, sys
argv = sys.argv
out = argv[argv.index("--output") + 1]
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "sms_detected.json"), "w") as f:
    f.write("[]")
"""
_MVT_RIEN = """
import os, sys
argv = sys.argv
out = argv[argv.index("--output") + 1]
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "sms.json"), "w") as f:
    f.write("[]")
"""


def _executor(tmp_path: Path) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal)


# mvt-ios simulé qui NE détecte QUE si le mot de passe de sauvegarde lui est parvenu
# par l'environnement — sonde de transmission du secret (sans jamais l'écho).
_MVT_EXIGE_MDP = """
import os, sys
argv = sys.argv
out = argv[argv.index("--output") + 1]
os.makedirs(out, exist_ok=True)
if os.environ.get("MVT_IOS_BACKUP_PASSWORD"):
    with open(os.path.join(out, "sms_detected.json"), "w") as f:
        f.write("[]")
"""


def _runner(
    tmp_path: Path,
    prog: str,
    *,
    fournisseur_mot_de_passe: Callable[[], str] | None = None,
) -> MVTIOSRunner:
    backup = tmp_path / "backup_ios"
    backup.mkdir()
    (backup / "Manifest.plist").write_bytes(b"<plist/>")
    return MVTIOSRunner(
        _executor(tmp_path),
        backup,
        commande_mvt=[sys.executable, "-c", prog],
        fournisseur_mot_de_passe=fournisseur_mot_de_passe,
    )


def test_outil_est_mvt_ios(tmp_path: Path) -> None:
    assert _runner(tmp_path, _MVT_RIEN).outil == "mvt-ios"


def test_analyse_ios_detection_forte(tmp_path: Path) -> None:
    resultat = _runner(tmp_path, _MVT_DETECTE).analyser()
    assert resultat.complete is True
    assert resultat.findings[0].severity is Severity.STRONG
    assert "sms" in resultat.findings[0].value


def test_analyse_ios_sans_detection(tmp_path: Path) -> None:
    resultat = _runner(tmp_path, _MVT_RIEN).analyser()
    assert resultat.findings[0].severity is Severity.INFO


def test_mot_de_passe_transmis_a_mvt_par_environnement(tmp_path: Path) -> None:
    """Avec un fournisseur, MVT reçoit le mot de passe (sauvegarde chiffrée lisible)."""
    resultat = _runner(
        tmp_path, _MVT_EXIGE_MDP, fournisseur_mot_de_passe=lambda: "motdepasse-backup"
    ).analyser()
    # Le MVT sonde n'a produit une détection que parce que le mot de passe est arrivé.
    assert resultat.findings[0].severity is Severity.STRONG


def test_sans_fournisseur_mot_de_passe_absent_de_l_environnement(tmp_path: Path) -> None:
    """Sans fournisseur, la variable n'est pas posée : backup chiffré non lisible."""
    resultat = _runner(tmp_path, _MVT_EXIGE_MDP).analyser()
    assert resultat.findings[0].severity is Severity.INFO


def test_mot_de_passe_ne_fuit_pas_dans_la_custody(tmp_path: Path) -> None:
    """Le mot de passe transmis à MVT n'apparaît jamais dans le journal de custody."""
    secret = "motdepasse-tres-secret-42"
    _runner(tmp_path, _MVT_EXIGE_MDP, fournisseur_mot_de_passe=lambda: secret).analyser()
    assert secret not in (tmp_path / "custody.jsonl").read_text(encoding="utf-8")


def test_sous_commande_check_backup_est_utilisee(tmp_path: Path) -> None:
    """La commande tracée doit employer « check-backup » (sous-commande iOS)."""
    _runner(tmp_path, _MVT_RIEN).analyser()
    entrees = [
        json.loads(ligne)
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    commande = next(e for e in entrees if e["evenement"] == "commande_executee")
    assert "check-backup" in commande["details"]["args"]
