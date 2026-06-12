"""Examiner Packet: a self-contained HTML artifact plus a JSON sidecar.

The packet is the demo's output artifact. It is rendered from a plain dict the
orchestrator assembles (Band room id, the @mention handoff trace, the typed
state-machine transitions, the message lifecycle states, the clocks, the diff
result, the drafted filings, and the replay hash). No external assets: the HTML
inlines its own CSS so it opens anywhere.
"""

from __future__ import annotations

import html
import json
from pathlib import Path


def write_packet(packet: dict, out_dir: str | Path, stem: str = "examiner-packet") -> tuple[str, str]:
    """Write <stem>.json and <stem>.html into out_dir. Returns both paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{stem}.json"
    html_path = out / f"{stem}.html"
    json_path.write_text(json.dumps(packet, indent=2), encoding="utf-8")
    html_path.write_text(_render_html(packet), encoding="utf-8")
    return str(json_path), str(html_path)


def _esc(v) -> str:
    return html.escape(str(v))


def _rows(headers: list[str], rows: list[list]) -> str:
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in r) + "</tr>"
        for r in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _render_html(p: dict) -> str:
    incident = p.get("incident", {})
    handoffs = p.get("handoff_trace", [])
    transitions = p.get("state_transitions", [])
    lifecycle = p.get("message_lifecycle", [])
    clocks = p.get("clocks", [])
    diff = p.get("diff", {})
    filings = p.get("filings", [])
    replay = p.get("replay", {})

    handoff_rows = _rows(
        ["#", "From", "To (@mention)", "Kind", "Band message id"],
        [[i + 1, h.get("from"), h.get("to"), h.get("kind"), h.get("message_id", "")]
         for i, h in enumerate(handoffs)],
    )
    transition_rows = _rows(
        ["Branch", "From state", "Event", "To state", "Admitted", "Actor"],
        [[t.get("correlation_id"), t.get("from_state"), t.get("event"),
          t.get("to_state") or t.get("reason"), t.get("admitted"), t.get("actor")]
         for t in transitions],
    )
    lifecycle_rows = _rows(
        ["Band message id", "States observed"],
        [[m.get("message_id"), " -> ".join(m.get("states", []))] for m in lifecycle],
    )
    clock_rows = _rows(
        ["Clock", "Branch", "Started", "Deadline", "Stopped", "Breached"],
        [[c.get("name"), c.get("correlation_id"), c.get("started"),
          c.get("deadline"), c.get("stopped") or "(running)", c.get("breached")]
         for c in clocks],
    )
    filing_blocks = "".join(
        f"<div class='filing'><h3>{_esc(f.get('regime'))} filing "
        f"<span class='by'>by {_esc(f.get('by'))} via {_esc(f.get('model'))}</span></h3>"
        f"<pre>{_esc(f.get('text'))}</pre></div>"
        for f in filings
    )
    diff_summary = (
        "<p class='ok'>No cross-filing contradictions: diff is GREEN.</p>"
        if not diff.get("conflicts")
        else "<ul class='bad'>" + "".join(
            f"<li>{_esc(c)}</li>" for c in diff.get("conflicts", [])) + "</ul>"
    )
    pending = p.get("pending", [])
    pending_block = (
        "<ul>" + "".join(f"<li>{_esc(x)}</li>" for x in pending) + "</ul>"
        if pending else "<p>None.</p>"
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Examiner Packet: {_esc(incident.get('incident_id', ''))}</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font: 15px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
        background: #0f1115; color: #e6e8eb; }}
.wrap {{ max-width: 980px; margin: 0 auto; padding: 32px 20px 64px; }}
h1 {{ font-size: 26px; margin: 0 0 4px; }}
h2 {{ font-size: 18px; margin: 32px 0 10px; border-bottom: 1px solid #2a2f3a;
      padding-bottom: 6px; }}
h3 {{ font-size: 15px; margin: 18px 0 6px; }}
.sub {{ color: #9aa3b2; margin: 0 0 8px; }}
.badge {{ display: inline-block; background: #1d6f42; color: #fff; border-radius: 4px;
          padding: 2px 8px; font-size: 12px; margin-right: 6px; }}
.badge.warn {{ background: #8a5a00; }}
table {{ width: 100%; border-collapse: collapse; margin: 6px 0 4px; font-size: 13px; }}
th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #232834;
          vertical-align: top; }}
th {{ color: #9aa3b2; font-weight: 600; }}
pre {{ background: #0a0c10; border: 1px solid #232834; border-radius: 6px;
       padding: 12px; white-space: pre-wrap; word-break: break-word; font-size: 13px; }}
.filing .by {{ color: #9aa3b2; font-weight: 400; font-size: 12px; }}
.ok {{ color: #5ad17a; }}
.bad {{ color: #ff8b8b; }}
code {{ background: #0a0c10; padding: 1px 5px; border-radius: 4px; }}
.hash {{ font-family: ui-monospace, monospace; font-size: 12px; word-break: break-all; }}
</style></head>
<body><div class="wrap">
<h1>Examiner Packet</h1>
<p class="sub">Deadline Room: deterministic protocol referee over a Band incident room.</p>
<p>
  <span class="badge">incident {_esc(incident.get('incident_id', ''))}</span>
  <span class="badge">Band room {_esc(incident.get('band_room_id', ''))}</span>
  <span class="badge {'warn' if replay.get('byte_identical') is False else ''}">
    replay {'byte-identical' if replay.get('byte_identical') else 'MISMATCH'}</span>
</p>

<h2>1. Incident fact-record (canonical)</h2>
<pre>{_esc(json.dumps(incident.get('fact_record', {}), indent=2))}</pre>

<h2>2. Band @mention handoff trace</h2>
<p class="sub">Every protocol envelope is delivered by @mention; this is the live room trace.</p>
{handoff_rows}

<h2>3. Message lifecycle states</h2>
<p class="sub">Per Band message: processing -&gt; processed (or failed), as advanced on the live API.</p>
{lifecycle_rows}

<h2>4. Typed state-machine transitions</h2>
<p class="sub">The Warden admits or rejects every handoff; illegal moves never execute.</p>
{transition_rows}

<h2>5. Statutory clocks</h2>
{clock_rows}

<h2>6. Cross-filing contradiction diff</h2>
{diff_summary}

<h2>7. Drafted filings</h2>
{filing_blocks or '<p>No filings drafted.</p>'}

<h2>8. Byte-identical replay</h2>
<p>Run-log SHA-256: <span class="hash">{_esc(replay.get('original_sha256', ''))}</span></p>
<p>Replayed SHA-256: <span class="hash">{_esc(replay.get('replayed_sha256', ''))}</span></p>
<p class="{'ok' if replay.get('byte_identical') else 'bad'}">
  {'Replay reproduced the run log byte for byte.' if replay.get('byte_identical')
   else 'Replay did not match.'}</p>

<h2>9. Pending (more Band agent keys required)</h2>
{pending_block}
</div></body></html>"""
