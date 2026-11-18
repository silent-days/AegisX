"""
AegisX — investigation report generator.

Produces professional, self-contained branded reports:
  * HTML — print-ready, inline CSS, embeds the AegisX logo
  * JSON — full machine-readable export

Reports are stored under ~/.local/share/aegisx/reports and indexed in the
database. Content is strictly evidence-driven: source attributions,
confidence levels, risk factors and MITRE ATT&CK associations. Campaign
attribution is reported only with its stored confidence, never asserted.
"""

from __future__ import annotations

import base64
import json
import html as html_mod
from datetime import datetime
from pathlib import Path

from ..database.repository import Repository, iso, parse_iso
from ..utils.paths import reports_dir
from ..utils.validators import sanitize_filename
from ..version import APP_NAME, APP_TAGLINE, APP_VERSION

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _esc(text) -> str:
    return html_mod.escape(str(text if text is not None else ""))


def _fmt_ts(value) -> str:
    dt = parse_iso(str(value)) if value else None
    if not dt:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _logo_b64() -> str:
    for name in ("icons/aegisx.png", "logos/aegisx-logo.png"):
        p = Path(__file__).resolve().parents[2] / "assets" / name
        if p.is_file():
            return base64.b64encode(p.read_bytes()).decode()
    return ""


def generate_html_report(report: dict, out_path: Path) -> Path:
    """Render the investigation HTML report. ``report`` built by build_report()."""
    logo = _logo_b64()
    meta = report["meta"]
    items = report["items"]

    rows_html = []
    for it in items:
        ind = it["indicator"]
        risk = it["risk"]
        findings = it["findings"]
        sev_class = risk["severity"]
        findings_rows = "".join(
            f"<tr><td>{_esc(f.get('source'))}</td>"
            f"<td>{_esc((f.get('severity') or '').upper())}</td>"
            f"<td>{_esc(f.get('score') if f.get('score') is not None else '—')}</td>"
            f"<td>{round((f.get('confidence') or 0) * 100)}%</td>"
            f"<td>{_esc(f.get('summary'))}</td>"
            f"<td>{_fmt_ts(f.get('observed_at'))}</td></tr>"
            for f in findings
        ) or "<tr><td colspan='6' class='dim'>No source findings recorded.</td></tr>"

        mitre_chips = " ".join(
            f"<span class='chip'>{_esc(m['id'])} · {_esc(m['name'])}</span>"
            for m in it.get("mitre", [])
        ) or "<span class='dim'>No ATT&CK associations derived</span>"

        factors = "".join(
            f"<li><b>{_esc(f['label'])}</b> ({f['impact']:+d})"
            + (f" — {_esc(f['detail'])}" if f.get("detail") else "")
            + "</li>"
            for f in risk.get("factors", [])
        )

        rows_html.append(f"""
        <div class="indicator">
          <div class="ind-head">
            <div>
              <div class="ind-value">{_esc(ind['value'])}</div>
              <div class="dim">{_esc(ind['type'].upper())} · ASN {_esc(ind.get('asn') or '—')}
               · {_esc(ind.get('asn_name') or '')} · {_esc(ind.get('country') or '—')}</div>
            </div>
            <div class="riskbox sev-{sev_class}">
              <div class="score">{risk['score']}<span>/100</span></div>
              <div class="band">{sev_class.upper()}</div>
              <div class="dim">confidence {round(risk['confidence'] * 100)}%</div>
            </div>
          </div>
          <p class="verdict">{_esc(risk.get('verdict'))}</p>
          <h4>Evidence factors</h4>
          <ul class="factors">{factors or '<li class="dim">No scored factors</li>'}</ul>
          <h4>MITRE ATT&amp;CK associations</h4>
          <div class="chips">{mitre_chips}</div>
          <h4>Source findings</h4>
          <table>
            <tr><th>Source</th><th>Severity</th><th>Score</th><th>Confidence</th>
                <th>Summary</th><th>Observed</th></tr>
            {findings_rows}
          </table>
        </div>""")

    campaign_rows = "".join(
        f"<tr><td>{_esc(c['name'])}</td><td>{_esc(c['severity'].upper())}</td>"
        f"<td>{round(c['confidence'] * 100)}%</td>"
        f"<td>{_esc(c.get('attribution') or 'No attribution claimed')}</td>"
        f"<td>{_esc(', '.join(c.get('tags', [])))}</td></tr>"
        for c in report.get("campaigns", [])
    ) or "<tr><td colspan='5' class='dim'>No campaign associations recorded.</td></tr>"

    logo_html = f'<img class="logo" src="data:image/png;base64,{logo}" alt="AegisX"/>' if logo else ""

    document = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>AegisX Report — {_esc(meta['title'])}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI','Noto Sans',sans-serif; background:#F5F7FA; color:#111827;
         margin:0; padding:32px; }}
  .page {{ max-width: 980px; margin: 0 auto; }}
  .head {{ background:#fff; border:1px solid #E5E7EB; border-radius:16px; padding:28px;
          display:flex; align-items:center; gap:20px; }}
  .head img.logo {{ height:64px; }}
  h1 {{ font-size:24px; margin:0 0 4px; }}
  h2 {{ font-size:17px; margin:28px 0 10px; }}
  h4 {{ font-size:13px; margin:14px 0 6px; color:#374151; }}
  .sub {{ color:#64748B; font-size:13px; }}
  .meta-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-top:18px; }}
  .meta {{ background:#F8FAFC; border:1px solid #EEF1F5; border-radius:10px; padding:10px 12px;
          font-size:12px; }}
  .meta b {{ display:block; font-size:11px; color:#64748B; text-transform:uppercase;
            letter-spacing:.8px; margin-bottom:4px; }}
  .indicator {{ background:#fff; border:1px solid #E5E7EB; border-radius:14px; padding:20px;
               margin-bottom:16px; }}
  .ind-head {{ display:flex; justify-content:space-between; gap:16px; align-items:flex-start; }}
  .ind-value {{ font-family:'JetBrains Mono','DejaVu Sans Mono',monospace; font-size:17px;
               font-weight:700; word-break:break-all; }}
  .dim {{ color:#64748B; font-size:12px; }}
  .riskbox {{ text-align:center; min-width:130px; border-radius:12px; padding:10px 14px;
             border:1px solid #E5E7EB; }}
  .riskbox .score {{ font-size:26px; font-weight:800; }}
  .riskbox .band {{ font-size:11px; font-weight:800; letter-spacing:1px; margin:2px 0; }}
  .sev-critical .score,.sev-critical .band {{ color:#DC2626; }}
  .sev-high .score,.sev-high .band {{ color:#F97316; }}
  .sev-medium .score,.sev-medium .band {{ color:#F59E0B; }}
  .sev-low .score,.sev-low .band {{ color:#3B82F6; }}
  .sev-info .score,.sev-info .band {{ color:#64748B; }}
  .verdict {{ background:#F8FAFC; border-left:3px solid #DC2626; padding:8px 12px;
             font-size:13px; margin:12px 0; }}
  .factors {{ margin:4px 0; padding-left:18px; font-size:12.5px; color:#374151; }}
  .chips .chip {{ display:inline-block; background:#FEF2F2; color:#B91C1C; border:1px solid #FCA5A5;
           border-radius:999px; padding:3px 10px; font-size:11px; font-weight:600; margin:2px; }}
  table {{ border-collapse:collapse; width:100%; font-size:12px; margin-top:4px; }}
  th {{ text-align:left; color:#64748B; border-bottom:1.5px solid #E5E7EB; padding:7px 8px;
       font-size:10.5px; text-transform:uppercase; letter-spacing:.6px; }}
  td {{ border-bottom:1px solid #EEF1F5; padding:7px 8px; vertical-align:top; }}
  .foot {{ color:#94A3B8; font-size:11px; text-align:center; margin-top:26px; line-height:1.7; }}
  .banner {{ background:#FEF3C7; border:1px dashed #FCD34D; color:#92400E; padding:10px 14px;
            border-radius:10px; font-size:12.5px; margin:14px 0; }}
  @media print {{ body {{ background:#fff; padding:10px; }} }}
</style></head>
<body><div class="page">
  <div class="head">
    {logo_html}
    <div>
      <h1>AegisX Intelligence Report</h1>
      <div class="sub">{_esc(meta['title'])} — generated {_fmt_ts(meta['generated_at'])}</div>
    </div>
  </div>

  {'<div class="banner">This report contains <b>labelled demonstration data</b> (RFC 5737 sample indicators). It does not represent live threat intelligence.</div>' if meta.get('demo') else ''}

  <div class="meta-grid">
    <div class="meta"><b>Investigation</b>{_esc(meta['investigation'])}</div>
    <div class="meta"><b>Analyst</b>{_esc(meta.get('analyst') or 'analyst')}</div>
    <div class="meta"><b>Indicators</b>{len(items)}</div>
    <div class="meta"><b>Findings</b>{sum(len(i['findings']) for i in items)}</div>
  </div>

  {('<div class="banner" style="background:#EFF6FF;border-style:solid;border-color:#BFDBFE;color:#1E40AF">' + _esc(meta['description']) + '</div>') if meta.get('description') else ''}

  <h2>Indicator Analysis</h2>
  {''.join(rows_html) or '<div class="indicator dim">No indicators in this investigation.</div>'}

  <h2>Campaign Associations</h2>
  <table>
    <tr><th>Campaign</th><th>Severity</th><th>Confidence</th><th>Attribution</th><th>Tags</th></tr>
    {campaign_rows}
  </table>

  <h2>Methodology &amp; Disclaimer</h2>
  <p class="dim" style="font-size:12px; line-height:1.8">
    Risk scores are produced by AegisX's evidence-weighted consensus model across all
    configured sources; every score lists its contributing factors and confidence level.
    MITRE ATT&amp;CK associations are behaviour-derived and indicative. Threat-actor
    attribution is <b>not</b> asserted by AegisX; any attribution shown originates from
    provider pulse metadata and is presented with its stated confidence only.
    Intelligence reflects the moment of generation and provider coverage at that time.
  </p>

  <div class="foot">
    {APP_NAME} v{APP_VERSION} — {APP_TAGLINE}<br/>
    Generated by {APP_NAME} for {_esc(meta.get('analyst') or 'analyst')} · Developed by Silent Days · MIT License
  </div>
</div></body></html>"""

    out_path.write_text(document, encoding="utf-8")
    return out_path


def build_report(repo: Repository, investigation_id: int | None = None,
                 indicator_ids: list[int] | None = None, *,
                 analyst: str = "analyst") -> dict:
    """Assemble the report payload from the repository."""
    items: list[dict] = []
    campaigns: list[dict] = []

    if investigation_id:
        inv = repo.get_investigation(investigation_id) or {}
        items_raw = repo.investigation_items(investigation_id)
        title = f"Investigation: {inv.get('name', 'Untitled')}"
        description = inv.get("description", "")
        analyst = inv.get("analyst") or analyst
    else:
        inv = {}
        title = "Ad-hoc intelligence review"
        description = ""
        items_raw = [repo.get_indicator(i) for i in (indicator_ids or [])]
        items_raw = [i for i in items_raw if i]

    for ind in items_raw:
        findings = repo.findings_for_indicator(ind["id"])
        risk_meta = {
            "score": ind.get("risk_score", 0),
            "severity": ind.get("severity", "info"),
            "confidence": ind.get("confidence", 0),
            "factors": (ind.get("meta") or {}).get("risk_factors", []),
            "verdict": (ind.get("meta") or {}).get("verdict", ""),
        }
        items.append({"indicator": ind, "risk": risk_meta, "findings": findings})

    # Campaigns that contain any investigated indicator
    for camp in repo.list_campaigns():
        member_ids = {m["id"] for m in repo.campaign_indicators(camp["id"])}
        used_ids = {i["indicator"]["id"] for i in items}
        if member_ids & used_ids:
            campaigns.append(camp)

    items.sort(key=lambda i: SEV_ORDER.get(i["risk"]["severity"], 9))
    return {
        "meta": {
            "title": title,
            "investigation": inv.get("name", "—"),
            "investigation_id": investigation_id,
            "description": description,
            "analyst": analyst,
            "generated_at": iso(),
            "demo": bool(items and items[0]["indicator"].get("demo")),
        },
        "items": items,
        "campaigns": campaigns,
    }


def export_report(payload: dict, fmt: str = "html",
                  filename: str | None = None) -> Path:
    """Write the report payload to disk in the requested format."""
    directory = reports_dir()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = sanitize_filename(payload["meta"]["title"].replace(":", "-"))
    filename = filename or f"AegisX-{safe}-{stamp}.{fmt}"
    path = directory / filename
    if fmt == "json":
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    else:
        generate_html_report(payload, path)
    return path
