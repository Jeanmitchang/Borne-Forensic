"""Tests de la porte unique et de l'objet Finding (``guardian.core.provenance``)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from guardian.core.custody import JournalCustody, hacher_donnees
from guardian.core.exceptions import ProvenanceError, ValidationError
from guardian.core.provenance import (
    Confidence,
    RegistreVersions,
    Reproducibility,
    Severity,
    TracedExecutor,
)

# Programme externe portable : écrit des octets déterministes (indépendants de l'OS)
# sur stdout/stderr et sort avec un code choisi.
_PROG_SORTIES = (
    "import sys; sys.stdout.buffer.write(b'bonjour'); "
    "sys.stderr.buffer.write(b'oups'); sys.exit(3)"
)
_PROG_VIDE = "pass"


def _executor(tmp_path: Path, registre: RegistreVersions | None = None) -> TracedExecutor:
    journal = JournalCustody(tmp_path / "custody.jsonl", operateur="expert.forensic")
    return TracedExecutor(tmp_path, "expert.forensic", journal, registre)


# --- Enums -----------------------------------------------------------------
def test_enums_exposent_les_valeurs_attendues() -> None:
    assert Severity.STRONG.value == "STRONG"
    assert Confidence.HIGH.value == "HIGH"
    # StrEnum : comparaison directe avec la chaîne.
    assert Reproducibility.DETERMINISTIC == "DETERMINISTIC"


# --- Registre des versions -------------------------------------------------
def test_registre_versions() -> None:
    registre = RegistreVersions()
    assert registre.version_de("adb") is None
    registre.enregistrer("adb", "35.0.2")
    assert registre.version_de("adb") == "35.0.2"
    assert registre.vers_dict() == {"adb": "35.0.2"}


# --- TracedExecutor : exécution, archivage, custody ------------------------
def test_executer_capture_archive_et_journalise(tmp_path: Path) -> None:
    ex = _executor(tmp_path)
    res = ex.executer([sys.executable, "-c", _PROG_SORTIES])

    assert res.finding_id == "F-0001"
    assert res.stdout == b"bonjour"
    assert res.texte_stdout() == "bonjour"
    assert res.trace.exit_code == 3

    # Sortie brute archivée et hachée.
    assert res.raw_output_ref == "raw/F-0001.out"
    assert res.raw_output_sha256 == hacher_donnees(b"bonjour")
    assert (tmp_path / "raw" / "F-0001.out").read_bytes() == b"bonjour"
    assert res.trace.stderr_ref == "raw/F-0001.err"
    assert (tmp_path / "raw" / "F-0001.err").read_bytes() == b"oups"

    # Événement consigné dans la custody.
    entrees = [
        json.loads(ligne)
        for ligne in (tmp_path / "custody.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    dernier = entrees[-1]
    assert dernier["evenement"] == "commande_executee"
    assert dernier["details"]["finding_id"] == "F-0001"
    assert dernier["details"]["exit_code"] == 3
    assert dernier["details"]["raw_output_sha256"] == hacher_donnees(b"bonjour")


def test_finding_id_s_incremente(tmp_path: Path) -> None:
    ex = _executor(tmp_path)
    r1 = ex.executer([sys.executable, "-c", _PROG_VIDE])
    r2 = ex.executer([sys.executable, "-c", _PROG_VIDE])
    assert (r1.finding_id, r2.finding_id) == ("F-0001", "F-0002")


def test_sans_stderr_pas_d_archive_err(tmp_path: Path) -> None:
    ex = _executor(tmp_path)
    prog = "import sys; sys.stdout.buffer.write(b'x')"
    res = ex.executer([sys.executable, "-c", prog])
    assert res.trace.stderr_ref is None
    assert res.trace.stderr_sha256 is None
    assert not (tmp_path / "raw" / "F-0001.err").exists()


def test_binaire_introuvable_leve_provenance(tmp_path: Path) -> None:
    ex = _executor(tmp_path)
    with pytest.raises(ProvenanceError):
        ex.executer(["binaire_inexistant_guardian_xyz"])


def test_args_vides_invalides(tmp_path: Path) -> None:
    ex = _executor(tmp_path)
    with pytest.raises(ValidationError):
        ex.executer([])


def test_args_chaine_invalide(tmp_path: Path) -> None:
    ex = _executor(tmp_path)
    # Une chaîne est bien un Sequence[str] pour le typeur ; le refus est au runtime.
    with pytest.raises(ValidationError):
        ex.executer("echo bonjour")


def test_timeout_leve_provenance(tmp_path: Path) -> None:
    ex = _executor(tmp_path)
    with pytest.raises(ProvenanceError):
        ex.executer([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)


def test_env_transmis_et_environnement_systeme_preserve(tmp_path: Path) -> None:
    """``env`` surcharge l'environnement sans écraser l'héritage (PATH conservé)."""
    ex = _executor(tmp_path)
    # Le sous-programme confirme la présence de la var fournie ET d'une var héritée,
    # sans jamais réécrire la valeur du secret sur sa sortie.
    prog = (
        "import os, sys; "
        "ok = os.environ.get('GUARDIAN_TEST_VAR') == 'attendu' and 'PATH' in os.environ; "
        "sys.stdout.write('PRESENT' if ok else 'ABSENT')"
    )
    res = ex.executer([sys.executable, "-c", prog], env={"GUARDIAN_TEST_VAR": "attendu"})
    assert res.texte_stdout() == "PRESENT"


def test_env_secret_ne_fuit_ni_dans_raw_ni_dans_custody(tmp_path: Path) -> None:
    """Un secret passé par ``env`` n'apparaît ni dans la trace, ni raw/, ni custody."""
    secret = "S3cr3t-NE-DOIT-PAS-FUITER"
    ex = _executor(tmp_path)
    prog = "import sys; sys.stdout.write('ok')"
    res = ex.executer([sys.executable, "-c", prog], env={"MVT_IOS_BACKUP_PASSWORD": secret})
    # La commande a bien tourné, mais le secret n'est nulle part.
    assert res.texte_stdout() == "ok"
    assert secret not in " ".join(res.trace.args)
    assert secret not in (tmp_path / "raw" / f"{res.finding_id}.out").read_text(
        encoding="utf-8"
    )
    assert secret not in (tmp_path / "custody.jsonl").read_text(encoding="utf-8")


def test_version_binaire_provient_du_registre(tmp_path: Path) -> None:
    registre = RegistreVersions()
    registre.enregistrer(sys.executable, "3.x-test")
    ex = _executor(tmp_path, registre)
    res = ex.executer([sys.executable, "-c", _PROG_VIDE])
    assert res.trace.binary_version == "3.x-test"


# --- Finding : interprétation + sérialisation ------------------------------
def test_en_finding_attache_l_interpretation_et_serialise(tmp_path: Path) -> None:
    ex = _executor(tmp_path)
    res = ex.executer([sys.executable, "-c", _PROG_VIDE])
    finding = res.en_finding(
        value="aucun service d'accessibilité suspect observé",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        reproducibility=Reproducibility.POINT_IN_TIME,
    )
    assert finding.finding_id == res.finding_id
    assert finding.severity is Severity.INFO
    assert finding.raw_output_sha256 == res.raw_output_sha256

    dico = finding.vers_dict()
    # Doit être sérialisable en JSON sans adaptateur.
    json.dumps(dico)
    assert dico["severity"] == "INFO"
    assert dico["reproducibility"] == "POINT_IN_TIME"
    assert dico["trace"]["exit_code"] == 0
    assert dico["trace"]["binary"] == sys.executable
