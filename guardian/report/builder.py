"""Génération des livrables d'affaire (CLAUDE.md §7, §10, §11).

Zéro dépendance : tout est produit avec la bibliothèque standard. Le dossier
livrable comporte trois niveaux de lecture (§7) :

1. ``rapport_synthese`` — lisible (justice), renvois ``[F-xxxx]`` — *sous-lot 8.2*.
2. ``journal_probatoire.html`` / ``.jsonl`` — chaque Finding déplié (ce fichier).
3. ``replay_manifest.jsonl`` — commandes déterministes rejouables (ce fichier).

Le ``MANIFEST.sha256`` est produit en dernier par l'orchestration (sous-lot 8.2),
via ``core.custody.generer_manifeste``.
"""

from __future__ import annotations

import html
import json
from collections.abc import Iterable
from pathlib import Path

from guardian.core.provenance import Finding, Reproducibility


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


def _echapper(valeur: object) -> str:
    return html.escape(str(valeur))


def _bloc_finding_html(f: Finding) -> str:
    """Construit le bloc HTML déplié d'un Finding (identifiant ancré pour renvois)."""
    trace = f.trace
    args = " ".join(_echapper(a) for a in trace.args)
    stderr = (
        f"<tr><th>stderr</th><td><code>{_echapper(trace.stderr_ref)}</code> "
        f"(sha256 {_echapper(trace.stderr_sha256)})</td></tr>"
        if trace.stderr_ref is not None
        else ""
    )
    return f"""
<div class="finding sev-{_echapper(f.severity.value)}" id="{_echapper(f.finding_id)}">
  <h2>[{_echapper(f.finding_id)}] {_echapper(f.value)}</h2>
  <p class="meta">
    gravité <b>{_echapper(f.severity.value)}</b> ·
    confiance <b>{_echapper(f.confidence.value)}</b> ·
    reproductibilité <b>{_echapper(f.reproducibility.value)}</b> ·
    {_echapper(f.timestamp_utc)} · opérateur {_echapper(f.operator)}
  </p>
  <table>
    <tr><th>binaire</th><td><code>{_echapper(trace.binary)}</code>
        (version {_echapper(trace.binary_version)})</td></tr>
    <tr><th>arguments</th><td><code>{args}</code></td></tr>
    <tr><th>cwd</th><td><code>{_echapper(trace.cwd)}</code></td></tr>
    <tr><th>code de sortie</th><td>{_echapper(trace.exit_code)}
        ({_echapper(trace.duration_ms)} ms)</td></tr>
    <tr><th>sortie brute</th><td><code>{_echapper(f.raw_output_ref)}</code>
        (sha256 {_echapper(f.raw_output_sha256)})</td></tr>
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
<title>{_echapper(titre)}</title><style>{_STYLE}</style></head>
<body>
<h1>{_echapper(titre)}</h1>
<p class="meta">{sous_titre}</p>
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
