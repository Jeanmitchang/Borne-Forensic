"""Génération des livrables d'affaire (CLAUDE.md §7, §10, §11).

Zéro dépendance : tout est produit avec la bibliothèque standard. Le dossier
livrable comporte trois niveaux de lecture (§7) :

1. ``rapport_synthese.html`` — lisible (justice), renvois ``[F-xxxx]``.
2. ``journal_probatoire.html`` / ``.jsonl`` — chaque Finding déplié.
3. ``replay_manifest.jsonl`` — commandes déterministes rejouables.

Le ``MANIFEST.sha256`` est produit en dernier (il hache tout le reste).

Échappement HTML : ``_attr`` (guillemets échappés) pour les valeurs d'attribut ;
``_txt`` (apostrophes conservées) pour le texte de contenu — les deux échappent
``< > &`` (défense XSS), mais on garde les apostrophes du français lisibles.
"""

from __future__ import annotations

import html
import json
import shutil
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from guardian.analysis.correlator import SyntheseCorrelation
from guardian.core.custody import JournalCustody, generer_manifeste
from guardian.core.logging_conf import obtenir_logger
from guardian.core.provenance import Finding, Reproducibility, TracedExecutor

_logger = obtenir_logger("report.builder")


def _attr(valeur: object) -> str:
    """Échappe une valeur destinée à un attribut HTML (guillemets inclus)."""
    return html.escape(str(valeur), quote=True)


def _txt(valeur: object) -> str:
    """Échappe un texte de contenu HTML (``< > &``), apostrophes conservées."""
    return html.escape(str(valeur), quote=False)


# ---------------------------------------------------------------------------
#  Niveau machine : JSONL + manifeste de rejeu
# ---------------------------------------------------------------------------
def ecrire_journal_jsonl(chemin: Path | str, findings: Iterable[Finding]) -> Path:
    """Écrit le journal probatoire machine : un ``Finding`` sérialisé par ligne."""
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    lignes = [json.dumps(f.vers_dict(), ensure_ascii=False) for f in findings]
    chemin.write_text("\n".join(lignes) + ("\n" if lignes else ""), encoding="utf-8")
    return chemin


def ecrire_replay_manifest(chemin: Path | str, findings: Iterable[Finding]) -> Path:
    """Écrit le manifeste de rejeu : commandes **DETERMINISTIC** rejouables par un tiers.

    Seuls les Findings dont la reproductibilité est ``DETERMINISTIC`` y figurent
    (rejeu → résultat identique). Un fichier vide est un résultat honnête : la
    plupart des relevés sur appareil vivant sont ``POINT_IN_TIME``, non rejouables
    à l'identique.
    """
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    entrees: list[str] = []
    for f in findings:
        if f.reproducibility is not Reproducibility.DETERMINISTIC:
            continue
        entrees.append(
            json.dumps(
                {
                    "finding_id": f.finding_id,
                    "binary": f.trace.binary,
                    "binary_version": f.trace.binary_version,
                    "args": list(f.trace.args),
                    "cwd": f.trace.cwd,
                    "raw_output_sha256": f.raw_output_sha256,
                },
                ensure_ascii=False,
            )
        )
    chemin.write_text("\n".join(entrees) + ("\n" if entrees else ""), encoding="utf-8")
    return chemin


# ---------------------------------------------------------------------------
#  Niveau expert : journal HTML (chaque Finding déplié)
# ---------------------------------------------------------------------------
_STYLE = """
body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
h1 { font-size: 1.4rem; }
.finding { border: 1px solid #ccc; border-radius: 6px; margin: 1rem 0; padding: 1rem; }
.finding h2 { font-size: 1.05rem; margin: 0 0 .4rem; }
.sev-STRONG { border-left: 6px solid #b00020; }
.sev-MEDIUM { border-left: 6px solid #e08600; }
.sev-WEAK   { border-left: 6px solid #3b7dd8; }
.sev-INFO   { border-left: 6px solid #6b6b6b; }
.meta { color: #444; font-size: .85rem; }
table { border-collapse: collapse; margin-top: .5rem; font-size: .85rem; }
td, th { border: 1px solid #ddd; padding: .25rem .5rem;
         text-align: left; vertical-align: top; }
code { background: #f3f3f3; padding: 0 .25rem; word-break: break-all; }
"""


def _bloc_finding_html(f: Finding) -> str:
    """Construit le bloc HTML déplié d'un Finding (identifiant ancré pour renvois)."""
    trace = f.trace
    args = " ".join(_txt(a) for a in trace.args)
    stderr = (
        f"<tr><th>stderr</th><td><code>{_txt(trace.stderr_ref)}</code> "
        f"(sha256 {_txt(trace.stderr_sha256)})</td></tr>"
        if trace.stderr_ref is not None
        else ""
    )
    return f"""
<div class="finding sev-{_attr(f.severity.value)}" id="{_attr(f.finding_id)}">
  <h2>[{_txt(f.finding_id)}] {_txt(f.value)}</h2>
  <p class="meta">
    gravité <b>{_txt(f.severity.value)}</b> ·
    confiance <b>{_txt(f.confidence.value)}</b> ·
    reproductibilité <b>{_txt(f.reproducibility.value)}</b> ·
    {_txt(f.timestamp_utc)} · opérateur {_txt(f.operator)}
  </p>
  <table>
    <tr><th>binaire</th><td><code>{_txt(trace.binary)}</code>
        (version {_txt(trace.binary_version)})</td></tr>
    <tr><th>arguments</th><td><code>{args}</code></td></tr>
    <tr><th>cwd</th><td><code>{_txt(trace.cwd)}</code></td></tr>
    <tr><th>code de sortie</th><td>{_txt(trace.exit_code)}
        ({_txt(trace.duration_ms)} ms)</td></tr>
    <tr><th>sortie brute</th><td><code>{_txt(f.raw_output_ref)}</code>
        (sha256 {_txt(f.raw_output_sha256)})</td></tr>
    {stderr}
  </table>
</div>""".strip()


def rendre_journal_html(
    findings: Iterable[Finding], *, titre: str = "Journal probatoire"
) -> str:
    """Rend le journal probatoire HTML (chaîne autonome, chaque Finding déplié)."""
    findings = list(findings)
    blocs = "\n".join(_bloc_finding_html(f) for f in findings)
    corps = blocs if findings else "<p>Aucun finding.</p>"
    sous_titre = (
        f"{len(findings)} finding(s). Chaque entrée porte la commande exacte qui l'a produite."
    )
    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>{_txt(titre)}</title><style>{_STYLE}</style></head>
<body>
<h1>{_txt(titre)}</h1>
<p class="meta">{_txt(sous_titre)}</p>
{corps}
</body></html>"""


def ecrire_journal_html(
    chemin: Path | str, findings: Iterable[Finding], *, titre: str = "Journal probatoire"
) -> Path:
    """Écrit le journal probatoire HTML dans ``chemin``."""
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    chemin.write_text(rendre_journal_html(findings, titre=titre), encoding="utf-8")
    return chemin


# ---------------------------------------------------------------------------
#  Niveau justice : rapport de synthèse (renvois [F-xxxx])
# ---------------------------------------------------------------------------
_STYLE_SYNTHESE = """
body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
h1 { font-size: 1.5rem; }
.niveau { display: inline-block; padding: .3rem .9rem; border-radius: 4px;
          color: #fff; font-weight: bold; }
.niveau-FORTS { background: #b00020; }
.niveau-MODERES { background: #e08600; }
.niveau-FAIBLES { background: #3b7dd8; }
.niveau-AUCUN_OBSERVABLE { background: #6b6b6b; }
pre.formulation { white-space: pre-wrap; background: #f7f7f7; padding: 1rem;
                  border-radius: 6px; font-family: inherit; }
table { border-collapse: collapse; margin-top: 1rem; width: 100%; }
td, th { border: 1px solid #ddd; padding: .3rem .5rem; text-align: left; }
.sev-STRONG td { background: #fdecee; }
.meta { color: #444; font-size: .9rem; }
"""


def rendre_synthese_html(
    synthese: SyntheseCorrelation,
    *,
    titre: str = "Rapport de synthèse",
    identifiant_affaire: str | None = None,
    lien_journal: str = "journal_probatoire.html",
) -> str:
    """Rend le rapport de synthèse HTML : niveau qualitatif, formulation, renvois.

    Chaque finding renvoie vers son entrée dépliée du journal (``[F-xxxx]`` →
    ``journal_probatoire.html#F-xxxx``). La formulation (qui inclut limites et
    rappel épistémique) provient du corrélateur — source unique du texte.
    """
    lignes = []
    for f in synthese.findings:
        lien = f"{_attr(lien_journal)}#{_attr(f.finding_id)}"
        lignes.append(
            f'<tr class="sev-{_attr(f.severity.value)}">'
            f'<td><a href="{lien}">[{_txt(f.finding_id)}]</a></td>'
            f"<td>{_txt(f.severity.value)}</td>"
            f"<td>{_txt(f.value)}</td></tr>"
        )
    table = "\n".join(lignes) or '<tr><td colspan="3">Aucun finding.</td></tr>'
    affaire = (
        f'<p class="meta">Affaire : {_txt(identifiant_affaire)}</p>'
        if identifiant_affaire is not None
        else ""
    )
    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>{_txt(titre)}</title><style>{_STYLE_SYNTHESE}</style></head>
<body>
<h1>{_txt(titre)}</h1>
{affaire}
<p>Niveau du faisceau d'indices :
   <span class="niveau niveau-{_attr(synthese.niveau.value)}"
   >{_txt(synthese.niveau.value)}</span></p>
<pre class="formulation">{_txt(synthese.formulation())}</pre>
<h2>Indices relevés</h2>
<table>
  <tr><th>Réf.</th><th>Gravité</th><th>Observation</th></tr>
  {table}
</table>
</body></html>"""


def ecrire_synthese_html(
    chemin: Path | str,
    synthese: SyntheseCorrelation,
    *,
    titre: str = "Rapport de synthèse",
    identifiant_affaire: str | None = None,
) -> Path:
    """Écrit le rapport de synthèse HTML dans ``chemin``."""
    chemin = Path(chemin)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    chemin.write_text(
        rendre_synthese_html(synthese, titre=titre, identifiant_affaire=identifiant_affaire),
        encoding="utf-8",
    )
    return chemin


# ---------------------------------------------------------------------------
#  Conversion PDF optionnelle (tracée, hors-ligne)
# ---------------------------------------------------------------------------
def convertir_html_en_pdf(
    executor: TracedExecutor,
    source_html: Path | str,
    cible_pdf: Path | str,
    *,
    commande_pdf: Sequence[str] = ("wkhtmltopdf",),
    timeout: float = 120.0,
) -> Path | None:
    """Convertit un HTML en PDF via un outil système, **si présent**. Sinon ``None``.

    La conversion passe par le ``TracedExecutor`` (porte unique). Absence de l'outil
    ou échec → ``None`` : on livre alors le HTML, sans dépendance obligatoire.
    """
    binaire = commande_pdf[0]
    if shutil.which(binaire) is None:
        return None
    cible_pdf = Path(cible_pdf)
    tracee = executor.executer(
        [*commande_pdf, str(source_html), str(cible_pdf)], timeout=timeout
    )
    if tracee.trace.exit_code != 0 or not cible_pdf.is_file():
        return None
    return cible_pdf


# ---------------------------------------------------------------------------
#  Orchestration : assemblage du dossier livrable
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DossierRapport:
    """Chemins des livrables produits pour une affaire."""

    journal_jsonl: Path
    journal_html: Path
    replay_manifest: Path
    synthese_html: Path
    synthese_pdf: Path | None
    manifest: Path


class GenerateurRapport:
    """Assemble le dossier d'affaire livrable (§7).

    Produit, dans ``dossier_affaire`` : journal probatoire (JSONL + HTML), manifeste
    de rejeu, rapport de synthèse (HTML, PDF optionnel), puis le ``MANIFEST.sha256``
    **en dernier** (il hache tout le reste). Un ``executor`` n'est requis que pour la
    conversion PDF ; un ``journal`` permet de consigner la génération en custody.
    """

    def __init__(
        self,
        dossier_affaire: Path | str,
        findings: Iterable[Finding],
        synthese: SyntheseCorrelation,
        *,
        journal: JournalCustody | None = None,
        executor: TracedExecutor | None = None,
        identifiant_affaire: str | None = None,
        convertir_pdf: bool = False,
        commande_pdf: Sequence[str] = ("wkhtmltopdf",),
    ) -> None:
        self._dossier = Path(dossier_affaire)
        self._findings = tuple(findings)
        self._synthese = synthese
        self._journal = journal
        self._executor = executor
        self._identifiant = identifiant_affaire
        self._convertir_pdf = convertir_pdf
        self._commande_pdf = tuple(commande_pdf)

    def generer(self) -> DossierRapport:
        """Produit tous les livrables et retourne leurs chemins."""
        self._dossier.mkdir(parents=True, exist_ok=True)
        journal_jsonl = ecrire_journal_jsonl(
            self._dossier / "journal_probatoire.jsonl", self._findings
        )
        journal_html = ecrire_journal_html(
            self._dossier / "journal_probatoire.html", self._findings
        )
        replay = ecrire_replay_manifest(
            self._dossier / "replay_manifest.jsonl", self._findings
        )
        synthese_html = ecrire_synthese_html(
            self._dossier / "rapport_synthese.html",
            self._synthese,
            identifiant_affaire=self._identifiant,
        )
        synthese_pdf: Path | None = None
        if self._convertir_pdf and self._executor is not None:
            synthese_pdf = convertir_html_en_pdf(
                self._executor,
                synthese_html,
                self._dossier / "rapport_synthese.pdf",
                commande_pdf=self._commande_pdf,
            )

        # Consigner AVANT le manifeste : ce dernier hache l'état final de custody.
        if self._journal is not None:
            self._journal.consigner(
                "rapport_genere",
                {
                    "niveau": self._synthese.niveau.value,
                    "nb_findings": len(self._findings),
                    "pdf": synthese_pdf is not None,
                },
            )
        manifest = generer_manifeste(self._dossier, journal=self._journal)
        _logger.info(
            "rapport généré",
            extra={
                "niveau": self._synthese.niveau.value,
                "pdf": synthese_pdf is not None,
            },
        )
        return DossierRapport(
            journal_jsonl=journal_jsonl,
            journal_html=journal_html,
            replay_manifest=replay,
            synthese_html=synthese_html,
            synthese_pdf=synthese_pdf,
            manifest=manifest,
        )
