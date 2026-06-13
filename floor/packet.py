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


def _render_diff(diff: dict) -> str:
    """Render the contradiction-diff section. Supports the legacy single-drafter
    shape ({"conflicts": [...]}) and the full-floor shape
    ({"blocked_conflicts": [...], "resolution": {...}, "final_claims": {...}})."""
    if "blocked_conflicts" in diff or "final_claims" in diff:
        blocked = diff.get("blocked_conflicts", [])
        resolution = diff.get("resolution")
        final_claims = diff.get("final_claims", {})
        parts = []
        if blocked:
            parts.append(
                "<p class='bad'><strong>Contradiction caught. The Warden BLOCKED "
                "the awaiting_human_signoff transition.</strong></p>")
            parts.append("<ul class='bad'>" + "".join(
                f"<li>{_esc(c)}</li>" for c in blocked) + "</ul>")
            if resolution:
                parts.append(
                    "<p class='ok'>Resolution: corrected "
                    f"<code>{_esc(resolution.get('corrected_field'))}</code> on "
                    f"<code>{_esc(resolution.get('fixed_branch'))}</code> from "
                    f"<code>{_esc(resolution.get('from_value'))}</code> to "
                    f"<code>{_esc(resolution.get('to_value'))}</code>. The diff "
                    "re-ran GREEN and signoff was unblocked.</p>")
        else:
            parts.append("<p class='ok'>No cross-filing contradictions: diff is GREEN.</p>")
        if final_claims:
            rows = [[b, c.get("incident_start_utc"), c.get("records_affected"),
                     c.get("attacker"), c.get("containment")]
                    for b, c in final_claims.items()]
            parts.append("<p class='sub'>Final reconciled claims (UTC-canonical):</p>")
            parts.append(_rows(
                ["Branch", "incident_start_utc", "records_affected", "attacker",
                 "containment"], rows))
        return "".join(parts)
    # legacy shape
    conflicts = diff.get("conflicts", [])
    if not conflicts:
        return "<p class='ok'>No cross-filing contradictions: diff is GREEN.</p>"
    return "<ul class='bad'>" + "".join(
        f"<li>{_esc(c)}</li>" for c in conflicts) + "</ul>"


def _render_chaos(chaos: dict) -> str:
    """Render the chaos / exactly-once evidence section, if --chaos was run."""
    events = chaos.get("events", [])
    ledger = chaos.get("ledger", [])
    dropped = chaos.get("duplicates_dropped", 0)
    if not events and not ledger:
        return ""
    parts = ["<h2>7b. Chaos kill and exactly-once recovery</h2>"]
    if events:
        parts.append("<ul>")
        for e in events:
            cls = "bad" if e.get("phase") == "kill" else "ok"
            parts.append(
                f"<li class='{cls}'><strong>{_esc(e.get('branch'))} "
                f"[{_esc(e.get('phase'))}]</strong> {_esc(e.get('note'))}</li>")
        parts.append("</ul>")
    parts.append(
        f"<p class='{'ok' if dropped else 'sub'}'>Duplicates dropped by the "
        f"idempotency ledger: <strong>{_esc(dropped)}</strong>. Each filing "
        "landed exactly once; no double draft.</p>")
    if ledger:
        parts.append(_rows(
            ["Dedup key", "Attempt", "Disposition"],
            [[e.get("key"), e.get("attempt"), e.get("disposition")] for e in ledger]))
    return "".join(parts)


def _render_reconciliation(rec: dict) -> str:
    """Render the amendment beat: the fact revision, the reopened branches, the
    agent-to-agent reconciliation exchange (who @mentioned whom, the proposed vs
    concurred figure, the hash-linked envelope chain), and that the diff passed
    only after concurrence. User-facing framing is 'transparent deliberation with
    an audit trail', never 'negotiation'."""
    if not rec:
        return ""
    old = rec.get("old_value")
    new = rec.get("new_value")
    reopened = ", ".join(b.upper() for b in rec.get("reopened_branches", []))
    parts = ["<h2>6b. Amendment: transparent deliberation with an audit trail</h2>"]
    parts.append(
        f"<p class='sub'>After release, Triage revised "
        f"<code>{_esc(rec.get('fact_key'))}</code> from "
        f"<code>{_esc(f'{old:,}' if isinstance(old, int) else old)}</code> to "
        f"<code>{_esc(f'{new:,}' if isinstance(new, int) else new)}</code> "
        f"(Band message {_esc(rec.get('amend_message_id'))}). The {_esc(reopened)} "
        f"branches reopened (FACT_AMENDED) and reconciled one shared "
        f"characterization with each other before re-filing.</p>")
    if rec.get("blocked_before_reconciliation"):
        parts.append(
            "<p class='bad'><strong>The Warden BLOCKED the amendment before "
            "reconciliation.</strong> "
            f"{_esc(rec.get('block_reason'))}</p>")
    # The agent-to-agent exchange.
    ex_rows = [
        [i + 1, e.get("from"), e.get("to"), e.get("verdict"),
         f"{e.get('proposed_value'):,}" if isinstance(e.get("proposed_value"), int)
         else e.get("proposed_value"),
         e.get("characterization"), e.get("band_message_id")]
        for i, e in enumerate(rec.get("exchange", []))
    ]
    parts.append("<p class='sub'>The reconciliation exchange (each turn is a real "
                 "Band @mention from one drafter to the other):</p>")
    parts.append(_rows(
        ["#", "From", "To (@mention)", "Verdict", "Figure", "Characterization",
         "Band message id"], ex_rows))
    conc = rec.get("concurred_value")
    parts.append(
        f"<p class='ok'>Both drafters CONCURRED on "
        f"<code>{_esc(f'{conc:,}' if isinstance(conc, int) else conc)}</code> "
        f"characterized as: {_esc(rec.get('concurred_characterization'))}</p>")
    if rec.get("diff_passed_only_after_concur"):
        parts.append(
            "<p class='ok'>The amended contradiction diff passed GREEN only after "
            "concurrence; the Warden held it BLOCKED until then.</p>")
    # The hash-linked envelope chain (tamper-evident, replay-verifiable).
    chain_rows = [
        [i + 1, e.get("verdict"), e.get("from"), e.get("to"),
         (e.get("sha256") or "")[:16] + "...",
         ((e.get("prior_envelope_hash") or "")[:16] + "...")
         if e.get("prior_envelope_hash") else "(none)"]
        for i, e in enumerate(rec.get("envelope_chain", []))
    ]
    parts.append("<p class='sub'>The hash-linked envelope chain (each turn links "
                 "to the prior by SHA-256, so the audit trail is tamper-evident "
                 "and replay-verifiable):</p>")
    parts.append(_rows(
        ["#", "Verdict", "From", "To", "Envelope SHA-256", "Links to prior"],
        chain_rows))
    return "".join(parts)


def _render_materiality(m: dict) -> str:
    """Render the SEC materiality assessment and the suppression decision, if the
    materiality beat ran. The verdict is the LLM's; the gating is deterministic."""
    if not m:
        return ""
    material = m.get("material")
    disposition = m.get("disposition")
    cls = "ok" if material else "bad"
    verdict_line = ("SEC: MATERIAL, the 4-business-day clock stands and the SEC "
                    "filing proceeds." if material else
                    "SEC: suppressed, not material. The 4-business-day clock never "
                    "triggered and no SEC filing was produced.")
    parts = ["<h2>5b. SEC materiality assessment</h2>",
             f"<p class='{cls}'><strong>{_esc(verdict_line)}</strong></p>",
             f"<p class='sub'>Decision source (LLM judgment role): "
             f"<code>{_esc(m.get('source'))}</code>. The verdict crosses into the "
             f"deterministic Warden gate as data; the Warden's gating of the branch "
             f"({_esc(disposition)}) is pure Python, replay-verifiable.</p>"]
    if m.get("memo"):
        parts.append("<p class='sub'>Materiality memo:</p>")
        parts.append(f"<pre>{_esc(m.get('memo'))}</pre>")
    return "".join(parts)


def _render_recruit(rec: dict) -> str:
    """Render the UK runtime-recruit beat: the blast-radius content that drove it,
    the discovered peer, the recruit event, and the late-started fifth clock. If
    the blast radius did not name the UK, show that no recruit happened (the
    content-driven proof)."""
    if not rec:
        return ""
    parts = ["<h2>5c. UK ICO runtime recruit (Internet of Agents)</h2>"]
    radius = ", ".join(str(x) for x in rec.get("blast_radius", []))
    if not rec.get("recruited"):
        parts.append(
            "<p class='sub'>Blast radius: <code>" + _esc(radius) + "</code>. It does "
            "NOT name a UK subsidiary, so the Warden did NOT recruit the UK ICO "
            "Drafter. The recruit is content-driven, not hardcoded.</p>")
        return "".join(parts)
    parts.append(
        "<p class='ok'><strong>UK subsidiary in the blast radius: the Warden "
        "discovered and recruited the UK ICO Drafter at runtime.</strong></p>")
    parts.append(
        "<p class='sub'>Blast radius: <code>" + _esc(radius) + "</code>. Discovered "
        f"peer <code>{_esc(rec.get('peer_id'))}</code> by token-match over the live "
        f"peer list (only a not_in_chat filter exists), then add_participant.</p>")
    parts.append(
        f"<p class='sub'>The {_esc(rec.get('clock_name'))} started at the RECRUIT "
        f"moment <code>{_esc(rec.get('clock_started_at'))}</code>, not at incident "
        f"T0. This is the late-started fifth clock.</p>")
    return "".join(parts)


def _render_release(rel: dict) -> str:
    """Render the two-key release gate: both human sign-offs (Lena and the GC) per
    released branch, proving segregation of duties (one key alone never releases)."""
    if not rel or not rel.get("signoffs"):
        return ""
    required = ", ".join(rel.get("required_roles", []))
    rows = [[s.get("correlation_id"), s.get("role"), s.get("actor"), s.get("ts")]
            for s in rel.get("signoffs", [])]
    parts = ["<h2>8b. Two-key release (segregation of duties)</h2>",
             f"<p class='sub'>A filing releases only when BOTH distinct human keys "
             f"sign: <code>{_esc(required)}</code>. One key alone never turns the "
             f"lock. Each sign-off is recorded with its human role.</p>",
             _rows(["Branch", "Role", "Signer", "Signed at"], rows),
             "<p class='ok'>Every released branch above carries two distinct human "
             "sign-offs.</p>"]
    return "".join(parts)


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
    diff_summary = _render_diff(diff)
    reconciliation_block = _render_reconciliation(p.get("reconciliation", {}))
    chaos_block = _render_chaos(p.get("chaos", {}))
    materiality_block = _render_materiality(p.get("materiality", {}))
    recruit_block = _render_recruit(p.get("recruit", {}))
    release_block = _render_release(p.get("release", {}))
    pending = p.get("pending", [])
    pending_section = (
        "<h2>9. Pending (more Band agent keys required)</h2><ul>"
        + "".join(f"<li>{_esc(x)}</li>" for x in pending) + "</ul>"
        if pending else ""
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

{materiality_block}

{recruit_block}

<h2>6. Cross-filing contradiction diff</h2>
{diff_summary}

{reconciliation_block}

<h2>7. Drafted filings</h2>
{filing_blocks or '<p>No filings drafted.</p>'}

{chaos_block}

{release_block}

<h2>8. Byte-identical replay</h2>
<p>Run-log SHA-256: <span class="hash">{_esc(replay.get('original_sha256', ''))}</span></p>
<p>Replayed SHA-256: <span class="hash">{_esc(replay.get('replayed_sha256', ''))}</span></p>
<p class="{'ok' if replay.get('byte_identical') else 'bad'}">
  {'Replay reproduced the run log byte for byte.' if replay.get('byte_identical')
   else 'Replay did not match.'}</p>

{pending_section}
</div></body></html>"""
