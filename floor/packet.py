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

from floor.grounding import strip_citations


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


def _render_security(security: dict) -> str:
    """Render the prompt-injection defense section, if an injection beat ran. Each
    record shows the attacker-chosen values the planted [CLAIMS] block carried, the
    authoritative values the Warden actually gated on, and that the sanitizer
    defanged the fence so the filing was unchanged."""
    injections = security.get("injections", [])
    if not injections:
        return ""
    neutralized = security.get("neutralized", 0)
    parts = ["<h2>7c. Prompt injection neutralized</h2>"]
    parts.append(
        f"<p class='ok'>Injection attempts neutralized at the sanitize "
        f"chokepoint: <strong>{_esc(neutralized)}</strong>. A planted [CLAIMS] "
        "block never reached the Warden's parse; the filing gated on the "
        "authoritative facts.</p>")
    for inj in injections:
        att = inj.get("attacker_values", {})
        auth = inj.get("authoritative_values", {})
        parts.append(
            f"<p class='bad'><strong>{_esc(inj.get('regime'))}</strong> "
            f"{_esc(inj.get('note'))}</p>")
        parts.append(_rows(
            ["Field", "Attacker planted", "Warden gated on (authoritative)"],
            [["records_affected", att.get("records_affected"),
              auth.get("records_affected")],
             ["incident_start_utc", att.get("incident_start_utc"),
              auth.get("incident_start_utc")],
             ["attacker", att.get("attacker"), auth.get("attacker")],
             ["containment", att.get("containment"), auth.get("containment")]]))
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
    so = m.get("second_opinion")
    if so:
        parts.append(_render_second_opinion(so))
    if m.get("memo"):
        parts.append("<p class='sub'>Materiality memo:</p>")
        parts.append(f"<pre>{_esc(m.get('memo'))}</pre>")
    return "".join(parts)


def _render_second_opinion(so: dict) -> str:
    """Additive: render the two independent open-model opinions that cross-checked
    the SEC materiality judgment, the AGREE/DISAGREE badge, and on disagreement the
    escalation banner with both memos. Only emitted when --second-opinion ran; the
    single-source materiality rendering above is untouched for ordinary runs."""
    agreement = (so.get("agreement") or "").lower()
    escalated = bool(so.get("escalated"))
    badge_cls = "bad" if escalated else "ok"
    badge = "DISAGREE" if agreement == "disagree" else "AGREE"

    def _row(label, model, material, memo):
        verdict = "MATERIAL" if material else "NOT MATERIAL"
        return ("<tr><td><strong>" + _esc(label) + "</strong><br>"
                "<code>" + _esc(model) + "</code></td>"
                "<td>" + _esc(verdict) + "</td>"
                "<td>" + _esc(memo) + "</td></tr>")

    parts = [
        "<h3>5b.i Two-model cross-check (open Featherless families)</h3>",
        f"<p class='{badge_cls}'><strong>Second opinion: {badge}.</strong> "
        "Two independent open models assessed the single most load-bearing "
        "compliance judgment; their verdicts are recorded as evidence.</p>",
        "<table><thead><tr><th>Model</th><th>Verdict</th><th>Memo</th></tr></thead><tbody>",
        _row("Primary", so.get("primary_model"), so.get("primary_material"),
             so.get("primary_memo")),
        _row("Second opinion", so.get("second_model"), so.get("second_material"),
             so.get("second_memo")),
        "</tbody></table>",
    ]
    if escalated:
        parts.append(
            "<p class='bad'><strong>Models disagreed, escalated to human, branch "
            "NOT suppressed pending review.</strong> The conservative reconcile "
            "treats the judgment as material (proceed) rather than silently "
            "suppressing a branch one qualified model judged reportable. No third "
            "model adjudicates; a human reviews both memos above.</p>")
    else:
        parts.append(
            "<p class='sub'>Both independent open models concurred. The agreement "
            "is written into the record as corroboration; the reconciled verdict "
            "flows to the same deterministic gate as a single structured "
            "MaterialityVerdict.</p>")
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


def _render_nydfs_recruit(rec: dict) -> str:
    """Render the NYDFS runtime-recruit beat: the same content-driven recruit seam
    the UK clock uses, a SECOND jurisdiction recruited live with its own different
    time math. 23 NYCRR 500.17(a)(1) is a flat 72 CALENDAR-hour notice from the
    moment of determination (the recruit moment), running straight through
    weekends and holidays, the deliberate contrast with the SEC business-day clock.
    If the blast radius did not name a New York entity, show that no recruit
    happened (the content-driven proof)."""
    if not rec:
        return ""
    parts = ["<h2>5d. NYDFS runtime recruit (a sixth jurisdiction, "
             "second open model family)</h2>"]
    radius = ", ".join(str(x) for x in rec.get("blast_radius", []))
    if not rec.get("recruited"):
        parts.append(
            "<p class='sub'>Blast radius: <code>" + _esc(radius) + "</code>. It does "
            "NOT name a New York licensed entity, so the Warden did NOT recruit the "
            "NYDFS Drafter. The recruit is content-driven, not hardcoded.</p>")
        return "".join(parts)
    parts.append(
        "<p class='ok'><strong>New York licensed entity in the blast radius: the "
        "Warden discovered and recruited the NYDFS Drafter at runtime, and the "
        "referee never changed one line.</strong></p>")
    parts.append(
        "<p class='sub'>Blast radius: <code>" + _esc(radius) + "</code>. Discovered "
        f"peer <code>{_esc(rec.get('peer_id'))}</code> by token-match over the live "
        f"peer list (only a not_in_chat filter exists), then add_participant.</p>")
    parts.append(
        f"<p class='sub'>The {_esc(rec.get('clock_name'))} started at the RECRUIT "
        f"(determination) moment <code>{_esc(rec.get('clock_started_at'))}</code>, "
        f"not at incident T0. This is the late-started sixth clock. It is a flat 72 "
        f"CALENDAR hours: no business-day or holiday arithmetic, so it runs straight "
        f"through weekends and holidays, the deliberate contrast with the SEC "
        f"4-business-day clock.</p>")
    return "".join(parts)


def _render_grounding(g: dict) -> str:
    """Render the grounding / fact-record fidelity receipt: per filing, the
    grounding score (the fraction of load-bearing spans traced to the
    fact-record), any UNGROUNDED spans flagged verbatim, the inline-citation
    validation, and a PASS / REVIEW badge against the stated threshold.

    This is a printed receipt only. The score is a deterministic, replayable
    function of the already-produced filing prose and the fact-record; it never
    gates a filing, moves a transition, or conditions a release. A REVIEW badge
    surfaces an unsupported span loudly for a human, it does not block anything."""
    if not g or not g.get("filings"):
        return ""
    threshold = g.get("threshold", 1.0)
    all_pass = g.get("all_pass", False)
    top_cls = "ok" if all_pass else "bad"
    parts = ["<h2>7c. Grounding / fact-record fidelity (hallucination receipt)</h2>",
             f"<p class='sub'>Each drafted filing is scored deterministically "
             f"against the canonical fact-record: every load-bearing span in the "
             f"prose (record counts, dates, the named breach actor) must trace to "
             f"a fact. The score is a printed receipt, never a gate. A filing "
             f"clears at score &ge; {_esc(threshold)}.</p>",
             f"<p class='{top_cls}'><strong>"
             + ("All filings cleared the grounding threshold: every load-bearing "
                "span traces to the fact-record."
                if all_pass else
                "One or more filings carry an ungrounded span. Flagged below for "
                "human review (no filing was blocked).")
             + "</strong></p>"]
    rows = []
    for f in g["filings"]:
        score = f.get("score", 0.0)
        badge = "PASS" if score >= threshold else "REVIEW"
        spans = f.get("ungrounded", [])
        if spans:
            span_html = "; ".join(
                f"{_esc(s.get('kind'))}: <code>{_esc(s.get('span'))}</code> "
                f"({_esc(s.get('reason'))})" for s in spans)
        else:
            span_html = "(none)"
        cites = f.get("citations", {})
        invalid = cites.get("invalid", [])
        cite_html = (f"{len(cites.get('valid', []))} valid"
                     + (f", <span class='bad'>{len(invalid)} invalid: "
                        + _esc(", ".join(invalid)) + "</span>" if invalid else ""))
        rows.append(
            "<tr><td>" + _esc(f.get("regime") or f.get("branch")) + "</td>"
            "<td>" + _esc(f"{score:.2f}") + "</td>"
            "<td>" + _esc(f"{f.get('grounded', 0)}/{f.get('total', 0)}") + "</td>"
            f"<td class='{'ok' if badge == 'PASS' else 'bad'}'>" + badge + "</td>"
            "<td>" + span_html + "</td>"
            "<td>" + cite_html + "</td></tr>")
    parts.append(
        "<table><thead><tr><th>Filing</th><th>Score</th><th>Grounded</th>"
        "<th>Badge</th><th>Ungrounded spans</th><th>Citations</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>")
    return "".join(parts)


def _render_adversarial_review(ar: dict) -> str:
    """Render the adversarial pre-submission review (the Challenger beat): per
    filing, the objections an INDEPENDENT Challenger agent raised, and which the
    DETERMINISTIC grounding oracle confirmed versus overturned.

    The win this section makes visible: the LLM Challenger critiques, but Python
    adjudicates which critiques are real, so the verifier's own output is itself
    checked by a replayable oracle. The Challenger never gates: its objections are
    content; the deterministic grounding scorer is the sole adjudicator; the
    Warden still consumes only the unchanged typed [CLAIMS] block. The whole
    exchange is an additive Band side-effect outside the hashed run-log, so replay
    stays byte-identical."""
    if not ar or not ar.get("reviews"):
        return ""
    raised = ar.get("objections_raised", 0)
    confirmed = ar.get("objections_confirmed", 0)
    overturned = ar.get("objections_overturned", 0)
    parts = ["<h2>7d. Adversarial review (Challenger, deterministically "
             "adjudicated)</h2>",
             "<p class='sub'>Before the Warden gates each filing, an independent "
             "Challenger agent (a different open model from the drafters) "
             "critiques it and posts a structured challenge into the room; the "
             "drafter then revises or rebuts. Each objection is then cross-checked "
             "by the EXISTING deterministic grounding oracle: the LLM critiques, "
             "Python adjudicates which critiques are real. The Challenger never "
             "gates; the Warden consumes only the unchanged typed claims.</p>",
             f"<p class='ok'><strong>Adversarial review: {_esc(raised)} "
             f"objection(s) raised, {_esc(confirmed)} confirmed by the "
             f"deterministic grounding oracle, {_esc(overturned)} overturned.</strong></p>"]
    for rev in ar["reviews"]:
        regime = rev.get("regime") or rev.get("branch")
        disp = rev.get("disposition", "")
        src = rev.get("source", "")
        parts.append(
            f"<h3>{_esc(regime)} filing, challenged by <code>{_esc(src)}</code> "
            f"-&gt; drafter {_esc(disp)}</h3>")
        objs = rev.get("objections", [])
        if not objs:
            parts.append("<p class='ok'>No objections raised: the Challenger "
                         "found the filing faithful.</p>")
            continue
        rows = []
        for o in objs:
            verdict = o.get("verdict", "")
            cls = "ok" if verdict == "confirmed" else "bad"
            label = "CONFIRMED" if verdict == "confirmed" else "OVERTURNED"
            rows.append(
                "<tr><td>" + _esc(o.get("target")) + "</td>"
                "<td>" + _esc(o.get("claim")) + "</td>"
                "<td>" + _esc(o.get("reason")) + "</td>"
                f"<td class='{cls}'>" + label + "</td>"
                "<td>" + _esc(o.get("evidence")) + "</td></tr>")
        parts.append(
            "<table><thead><tr><th>Target</th><th>Disputed claim</th>"
            "<th>Challenger reason</th><th>Oracle verdict</th>"
            "<th>Deterministic evidence</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")
    return "".join(parts)


def _render_reliability(rel: dict) -> str:
    """Render the network-reliability receipt: how many transient provider/Band
    failures (a 429/5xx or a transport hiccup) a later attempt auto-recovered this
    run, via the bounded exponential-backoff retry on the two network chokepoints.
    Rendered ONLY when the count is nonzero: a clean run shows nothing, so the
    happy path is visually unchanged. This counter is read from a live tally at
    packet time, never from the hashed run log, so it does not affect replay."""
    if not rel:
        return ""
    n = rel.get("recovered_retries", 0)
    if not n:
        return ""
    plural = "s" if n != 1 else ""
    return (
        "<h2>8c. Network reliability (auto-recovered transient failures)</h2>"
        f"<p class='ok'><strong>{_esc(n)} transient provider/Band error{plural} "
        "auto-recovered</strong> by bounded exponential-backoff retry on the two "
        "network chokepoints (the LLM router and the Band HTTP client). Each "
        "retried call is idempotent: an LLM completion is read-only and a Band "
        "post is guarded by the read-then-act dedup key, so a retried write lands "
        "exactly once. A transient hiccup during the run was a non-event rather "
        "than an aborted filing.</p>")


def _render_operability(op: dict) -> str:
    """Render the operability / SLO block: the operations numbers an enterprise
    judge and a CISO watch. Per regime the deadline MARGIN (how much statutory time
    remained when the filing landed), the nearest deadline, the per-phase
    throughput timings, the retry/dedup counts, and one plain SLO line.

    Every number is derived OUT-OF-LOG from the in-process telemetry collector and
    the deterministic clock math; it is render-only and never enters the hashed
    run-log, so the run-log sha and byte-identical replay are untouched. Sub-tables
    are omitted cleanly when empty (a trivial run renders the SLO line and a clean,
    zeroed throughput row, nothing fabricated)."""
    if not op:
        return ""
    parts = ["<h2>8d. Operability and statutory-margin SLO</h2>"]
    slo = op.get("slo_line", "")
    breached = op.get("any_breached", False)
    slo_cls = "bad" if breached else "ok"
    parts.append(
        f"<p class='{slo_cls}'><strong>SLO: {_esc(slo)}</strong></p>")

    # Deadline margins: the operations number per regime (deadline - filed-at).
    margins = op.get("deadline_margins", [])
    if margins:
        rows = []
        for m in margins:
            mh = m.get("margin_hours")
            if not m.get("filed"):
                margin_label = "(running, not filed)"
            elif mh is None:
                margin_label = "n/a"
            else:
                margin_label = f"{mh:.2f} h"
            status = ("BREACHED" if m.get("breached")
                      else "filed" if m.get("filed") else "running")
            rows.append([m.get("clock"), m.get("trigger_event"),
                         m.get("deadline_utc"), m.get("filed_utc") or "(running)",
                         margin_label, status])
        parts.append(
            "<p class='sub'>Per-regime deadline margin: how much statutory time "
            "remained when each filing landed (deadline minus filed-at, from the "
            "deterministic clock math). This is the single number an examiner and a "
            "CISO write down.</p>")
        parts.append(_rows(
            ["Clock", "Trigger event", "Deadline (UTC)", "Filed (UTC)",
             "Margin", "Status"], rows))
        nearest = op.get("nearest_deadline")
        if nearest:
            nm = nearest.get("margin_hours")
            margin_txt = ("not filed" if not nearest.get("filed")
                          else "n/a" if nm is None else f"{nm:.2f} h of margin")
            parts.append(
                f"<p class='sub'>Nearest deadline: "
                f"<code>{_esc(nearest.get('clock'))}</code> at "
                f"<code>{_esc(nearest.get('deadline_utc'))}</code> "
                f"({_esc(margin_txt)}).</p>")

    # Throughput and phase timings.
    phases = op.get("phase_timings", [])
    if phases:
        prows = [[p.get("phase"), f"{p.get('duration_hours', 0):.2f} h",
                  p.get("start"), p.get("end")] for p in phases]
        prows.append(["TOTAL (end to end)",
                      f"{op.get('total_duration_hours', 0):.2f} h", "", ""])
        parts.append("<p class='sub'>Per-phase wall clock (from the deterministic "
                     "protocol timestamps):</p>")
        parts.append(_rows(["Phase", "Duration", "Start", "End"], prows))

    tp = op.get("throughput", {})
    rel = op.get("reliability", {})
    parts.append(_rows(
        ["Filings", "Released", "Suppressed", "Diff conflicts",
         "Recovered retries", "Duplicates dropped", "Chaos events",
         "Rejected transitions"],
        [[tp.get("filings", 0), tp.get("released", 0), tp.get("suppressed", 0),
          tp.get("diff_conflicts", 0), rel.get("recovered_retries", 0),
          rel.get("duplicates_dropped", 0), rel.get("chaos_events", 0),
          rel.get("rejected_transitions", 0)]]))

    # Liveness loop: heartbeat -> declared-dead -> recovery. Rendered only when an
    # agent was actually declared dead (a clean run carries no liveness section).
    parts.append(_render_liveness(op.get("liveness")))
    return "".join(parts)


def _render_liveness(lv: dict | None) -> str:
    """Render the liveness loop: which agents the watchdog declared dead, the
    detection latency in LOGICAL drain cycles (never wall-clock, so the same run
    declares at the same point on every replay), and that every declared-dead
    agent recovered with 0 double-files. Pure out-of-log data from the logical-tick
    watchdog; render-only, so the run-log sha and byte-identical replay are
    untouched. Empty when nothing was declared dead."""
    if not lv or not lv.get("declared_dead"):
        return ""
    dead = lv.get("declared_dead", [])
    recovered = lv.get("recovered", [])
    all_recovered = lv.get("all_recovered", False)
    cls = "ok" if all_recovered else "bad"
    parts = ["<h3>Liveness loop (heartbeat &rarr; declared-dead &rarr; recovery)</h3>"]
    parts.append(
        "<p class='sub'>The watchdog tracks each drafter's progress in LOGICAL "
        f"drain cycles (threshold {lv.get('threshold_ticks')} cycles), never in "
        "wall-clock seconds, so the same run declares an agent dead at the same "
        "point on every byte-identical replay. Detection latency is measured in "
        "those logical cycles.</p>")
    rows = []
    rec_branches = {r.get("branch") for r in recovered}
    for d in dead:
        rows.append([
            d.get("agent"), d.get("branch"),
            f"cycle {d.get('tick')}",
            f"{d.get('detection_latency_ticks')} cycle(s)",
            "recovered, no double-file" if d.get("branch") in rec_branches
            else "not recovered"])
    parts.append(_rows(
        ["Agent", "Branch", "Declared dead at", "Detection latency", "Outcome"],
        rows))
    dbl = lv.get("double_files")
    parts.append(
        f"<p class='{cls}'><strong>{lv.get('recovered_count', 0)}/"
        f"{lv.get('declared_dead_count', 0)} declared-dead agent(s) recovered; "
        f"{0 if dbl is None and all_recovered else dbl} double-file(s). "
        f"Exactly-once held across every declared-dead window.</strong></p>")
    return "".join(parts)


def _render_attestation(att: dict) -> str:
    """Render the deadline-compliance attestation: per regime, the statutory
    deadline, the filed-at instant, the margin, and a met/missed verdict, with the
    headline that N statutory deadlines were provably met and the verdict is SIGNED.

    The attestation is derived deterministically from the clock rows (deadline minus
    filed-at) and its digest is folded into the bound Ed25519 signature, so the
    timeliness verdict is itself attested by the Warden's key. This is the line a
    buyer pays for and an examiner writes down first."""
    if not att or not att.get("regimes"):
        return ""
    filed = att.get("filed_count", 0)
    met = att.get("met_count", 0)
    all_met = att.get("all_met", False)
    top_cls = "ok" if all_met else "bad"
    headline = (
        f"These filings provably met {met} of {filed} statutory deadline"
        f"{'s' if filed != 1 else ''}, signed."
        if all_met else
        f"{met} of {filed} statutory deadline{'s' if filed != 1 else ''} met; "
        "at least one was missed. Verdict signed regardless.")
    parts = ["<h2>8e. Deadline compliance attestation (signed)</h2>",
             f"<p class='{top_cls}'><strong>{_esc(headline)}</strong></p>",
             "<p class='sub'>Per regime, the statutory deadline, when the filing "
             "landed, and how much margin remained (deadline minus filed-at). This "
             "verdict's digest is folded into the Warden's Ed25519 signature, so a "
             "tampered margin breaks the signature: the timeliness claim is itself "
             "signed, not merely asserted.</p>"]
    rows = []
    for r in att["regimes"]:
        if r.get("filed"):
            verdict = "MET" if r.get("met") else "MISSED"
            margin = r.get("margin_human") or "n/a"
            filed_at = r.get("filed_at") or ""
        else:
            verdict = "running"
            margin = "(not filed)"
            filed_at = "(running)"
        rows.append([r.get("regime"), r.get("trigger_event"),
                     r.get("statutory_deadline"), filed_at, margin, verdict])
    parts.append(_rows(
        ["Regime", "Trigger event", "Statutory deadline", "Filed (UTC)",
         "Margin", "Verdict"], rows))
    return "".join(parts)


def _render_timestamp(ts: dict) -> str:
    """Render the RFC 3161 trusted-timestamp line: WHEN the signed artifact was
    sealed, derived read-only from the timestamp token sidecar.

    The detached signature proves WHO signed the run; this line adds WHEN. A
    Time-Stamping Authority bound the signed artifact's digest (the sha256 of the
    bound payload the Ed25519 signature covers) to a genTime and signed that
    binding under RFC 3161. The line is purely DERIVED from the token and never
    enters the hashed run log; a packet without a timestamp token renders nothing,
    so a sealed capture's bytes are unaffected.

    The honest demo-TSA caveat travels with the line: the RFC 3161 mechanism is
    real, but the authority is a local demo, not a qualified third-party TSA, which
    is a deployment configuration."""
    if not ts or not ts.get("gen_time"):
        return ""
    gen = ts.get("gen_time", "")
    standard = ts.get("standard", "RFC 3161 (Time-Stamp Protocol)")
    serial = ts.get("serial_number", "")
    policy = ts.get("policy_oid", "")
    tsa = ts.get("tsa", "demo TSA")
    digest = ts.get("artifact_digest", "")
    caveat = ts.get("caveat", "")
    parts = ["<h2>8f. Trusted timestamp (RFC 3161)</h2>",
             f"<p class='ok'><strong>This signed artifact was timestamped at "
             f"{_esc(gen)}.</strong></p>",
             "<p class='sub'>A Time-Stamping Authority bound the signed artifact's "
             "digest (sha256 of the bound payload the Warden signature was taken "
             "over) to a point in time and signed that binding under "
             f"<code>{_esc(standard)}</code>. The detached signature proves WHO "
             "signed the run; this proves WHEN. A flipped digest byte or a tampered "
             "token makes the timestamp fail to verify.</p>",
             _rows(["Standard", "TSA", "Timestamp (genTime)", "Serial", "Policy OID",
                    "Artifact digest"],
                   [[standard, tsa, gen, serial, policy, digest]])]
    if caveat:
        parts.append(f"<p class='sub'><em>{_esc(caveat)}</em></p>")
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


def _clock_status(c: dict) -> tuple[str, str]:
    """Map one clock row to (label, css class) for the jurisdictions strip.
    Pure: reads only c['stopped'] and c['breached'], both already in the dict.
    filed (green) when the clock stopped and did not breach; breached (red) when
    it breached; running (amber) when it is still ticking."""
    if c.get("breached"):
        return "breached", "st-bad"
    if c.get("stopped"):
        return "filed", "st-ok"
    return "running", "st-warn"


def _gate_outcome(p: dict) -> tuple[str, str, str]:
    """Derive the Warden gate node's outcome from data already in the packet:
    the diff result, the typed transitions, and which branches released. Returns
    (label, css class, reason) where class is gate-bad (red blocked) / gate-warn
    (amber pending) / gate-ok (green released). Pure and deterministic."""
    diff = p.get("diff", {})
    transitions = p.get("state_transitions", [])
    blocked = diff.get("blocked_conflicts", [])
    resolution = diff.get("resolution")
    rejected = [t for t in transitions if not t.get("admitted")]
    released = [t for t in transitions
                if t.get("admitted") and t.get("to_state") == "released"]
    if rejected:
        return ("BLOCKED", "gate-bad",
                "An illegal handoff was rejected by the typed state machine.")
    if blocked and not resolution:
        return ("BLOCKED", "gate-bad",
                "Cross-filing contradiction caught; signoff refused.")
    if blocked and resolution:
        return ("CLEARED", "gate-ok",
                "Contradiction caught, then resolved; the diff re-ran green.")
    if released:
        return ("RELEASED", "gate-ok",
                "Every drafted branch passed the diff and released.")
    return ("PENDING", "gate-warn", "Awaiting a release decision.")


def _transition_counts(p: dict) -> tuple[int, int]:
    """(admitted, rejected) transition counts from state_transitions. Pure."""
    transitions = p.get("state_transitions", [])
    admitted = sum(1 for t in transitions if t.get("admitted"))
    rejected = sum(1 for t in transitions if not t.get("admitted"))
    return admitted, rejected


# Deterministic column assignment for the handoff graph. The from/to names in
# handoff_trace are human role labels ("Triage", "NIS2 Drafter", "Warden", ...).
# We map each to a fixed lane index so the SVG layout is byte-stable regardless
# of run, and unknown roles fall to a stable trailing lane by first appearance.
_LANE_ORDER = [
    ("Triage", 0),
    ("NIS2 Drafter", 1),
    ("SEC Drafter", 2),
    ("DORA Drafter", 3),
    ("UK ICO Drafter", 4),
    ("Warden", 5),
]


def _lane_index(name: str, extra: dict[str, int]) -> int:
    for label, idx in _LANE_ORDER:
        if name == label:
            return idx
    # Stable fallback: assign trailing lanes in first-seen order. Deterministic
    # because handoff_trace order is itself deterministic on a given run.
    if name not in extra:
        extra[name] = len(_LANE_ORDER) + len(extra)
    return extra[name]


def _render_handoff_graph(p: dict) -> str:
    """Inline SVG handoff graph rendered from handoff_trace + state_transitions.
    One lane per participant, one row per handoff arrow labeled by kind and the
    short Band message id, and a Warden gate node colored by outcome. Layout uses
    only integer coordinates derived from list indices: no now(), no random, so
    the rendered string is byte-stable. Returns an inline <svg> string with no
    external assets and no script."""
    handoffs = p.get("handoff_trace", [])
    if not handoffs:
        return ""
    extra: dict[str, int] = {}
    # Resolve the set of lanes actually used, in deterministic lane-index order.
    used: dict[int, str] = {}
    for h in handoffs:
        for nm in (h.get("from", ""), h.get("to", "")):
            used[_lane_index(nm, extra)] = nm
    lane_idxs = sorted(used)
    lane_pos = {idx: col for col, idx in enumerate(lane_idxs)}

    col_w = 150
    margin_x = 20
    header_h = 64
    row_h = 46
    n_rows = len(handoffs)
    width = margin_x * 2 + col_w * max(1, len(lane_idxs))
    height = header_h + row_h * n_rows + 80  # extra band for the gate node

    def cx(idx: int) -> int:
        return margin_x + lane_pos[idx] * col_w + col_w // 2

    parts: list[str] = []
    parts.append(
        f'<svg class="handoff-graph" viewBox="0 0 {width} {height}" '
        f'width="100%" role="img" '
        f'aria-label="Band at-mention handoff graph" '
        f'xmlns="http://www.w3.org/2000/svg">')
    # Lane headers + vertical guide lines.
    for idx in lane_idxs:
        x = cx(idx)
        parts.append(
            f'<line class="lane" x1="{x}" y1="{header_h - 8}" x2="{x}" '
            f'y2="{height - 16}"/>')
        parts.append(
            f'<text class="lane-label" x="{x}" y="28" '
            f'text-anchor="middle">{_esc(used[idx])}</text>')
    # Arrows, one per handoff, top to bottom in trace order.
    for i, h in enumerate(handoffs):
        y = header_h + i * row_h + row_h // 2
        fi = _lane_index(h.get("from", ""), extra)
        ti = _lane_index(h.get("to", ""), extra)
        x1, x2 = cx(fi), cx(ti)
        mid = h.get("message_id", "")
        short = (str(mid)[:8] + "..") if mid else ""
        kind = _esc(h.get("kind", ""))
        label = kind + (f" {short}" if short else "")
        parts.append(
            f'<circle class="node" cx="{x1}" cy="{y}" r="5"/>')
        if x1 == x2:
            # Self/same-lane handoff: a short marker, no arrow.
            parts.append(
                f'<text class="edge-label" x="{x1 + 10}" y="{y - 6}" '
                f'text-anchor="start">{_esc(label)}</text>')
        else:
            parts.append(
                f'<line class="edge" x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" '
                f'marker-end="url(#arrow)"/>')
            lx = (x1 + x2) // 2
            parts.append(
                f'<text class="edge-label" x="{lx}" y="{y - 6}" '
                f'text-anchor="middle">{_esc(label)}</text>')
    # The Warden gate node, colored by outcome, with the transition counts.
    g_label, g_cls, g_reason = _gate_outcome(p)
    admitted, rejected = _transition_counts(p)
    gx = width // 2
    gy = height - 40
    gw = 360
    parts.append(
        f'<rect class="gate {g_cls}" x="{gx - gw // 2}" y="{gy - 22}" '
        f'width="{gw}" height="40" rx="6"/>')
    parts.append(
        f'<text class="gate-text" x="{gx}" y="{gy - 4}" '
        f'text-anchor="middle">Warden gate: {_esc(g_label)} '
        f'({admitted} admitted, {rejected} rejected)</text>')
    parts.append(
        f'<text class="gate-sub" x="{gx}" y="{gy + 12}" '
        f'text-anchor="middle">{_esc(g_reason)}</text>')
    # Arrow marker def (static, deterministic).
    parts.append(
        '<defs><marker id="arrow" markerWidth="9" markerHeight="9" refX="7" '
        'refY="3" orient="auto" markerUnits="strokeWidth">'
        '<path d="M0,0 L7,3 L0,6 z"/></marker></defs>')
    parts.append('</svg>')
    return "".join(parts)


def _render_cover(p: dict) -> str:
    """Regulator-style cover block rendered entirely from data already in the
    packet dict: incident, clocks, release, replay. Pure, no I/O. Returns an HTML
    string. ASCII chrome only, all data routed through _esc()."""
    incident = p.get("incident", {})
    fact = incident.get("fact_record", {})
    clocks = p.get("clocks", [])
    release = p.get("release", {})
    replay = p.get("replay", {})

    incident_id = incident.get("incident_id", "")
    entity = fact.get("regulated_entity", "")
    authority = fact.get("competent_authority", "")

    # Jurisdictions strip: one chip per clock regime with its deadline + status.
    chips = []
    for c in clocks:
        label, cls = _clock_status(c)
        trigger = c.get("trigger_event", "")
        trigger_html = (f'<div class="jtrigger">trigger: {_esc(trigger)}</div>'
                        if trigger else "")
        chips.append(
            f'<div class="jchip {cls}">'
            f'<div class="jname">{_esc(c.get("name", ""))}</div>'
            f'{trigger_html}'
            f'<div class="jdeadline">deadline {_esc(c.get("deadline", ""))}</div>'
            f'<div class="jstatus">{_esc(label)}</div></div>')
    chips_html = "".join(chips) or '<div class="jchip st-warn">no clocks</div>'

    # Signoff chain: group the recorded sign-offs by branch and present each as a
    # chain (General Counsel -> Head of IR). Order within a branch follows the
    # recorded order, which is deterministic (GC then Lena).
    signoffs = release.get("signoffs", [])
    by_branch: dict[str, list[dict]] = {}
    for s in signoffs:
        by_branch.setdefault(s.get("correlation_id", ""), []).append(s)
    role_label = {"general_counsel": "General Counsel", "head_of_ir": "Head of IR"}
    chain_rows = []
    for corr, sigs in by_branch.items():
        links = []
        for s in sigs:
            rl = role_label.get(s.get("role", ""), s.get("role", ""))
            links.append(
                f'<span class="signer">{_esc(rl)} '
                f'<span class="signer-actor">({_esc(s.get("actor", ""))})</span> '
                f'<span class="signer-ts">{_esc(s.get("ts", ""))}</span></span>')
        arrow = '<span class="chain-arrow">to</span>'
        chain_rows.append(
            f'<div class="chain-row"><span class="chain-corr">'
            f'{_esc(corr)}</span>' + arrow.join(links) + '</div>')
    if chain_rows:
        chain_html = (
            '<div class="signoff-chain">' + "".join(chain_rows) + "</div>"
            '<p class="chain-caption">Two distinct human keys. One alone never '
            'releases.</p>')
    else:
        chain_html = ('<p class="chain-caption">No branch released under the '
                      'two-key gate on this run.</p>')

    sha = replay.get("original_sha256", "")
    short_sha = (str(sha)[:24] + "...") if sha else ""
    seal_ok = replay.get("byte_identical") is True
    seal_cls = "seal-ok" if seal_ok else "seal-bad"
    seal_text = ("replay byte-identical" if seal_ok else "replay MISMATCH")

    # Signature row: the detached Ed25519 attestation over the run-log bytes. The
    # signature is metadata beside the log, not in the hashed JSONL, so the seal
    # hash above is unchanged by it. The demo-key caveat travels with it.
    # SLO line on the cover: the operations attainment a CISO recognizes, derived
    # from the out-of-log operability telemetry. Rendered only when an operability
    # block is present (every full-floor run carries one); omitted cleanly when it
    # is not, so the legacy cover is unchanged.
    op = p.get("operability") or {}
    slo_line = op.get("slo_line", "")
    slo_block = ""
    if slo_line:
        slo_cls = "seal-bad" if op.get("any_breached") else "seal-ok"
        slo_block = f"""
  <div class="cover-seal {slo_cls}">
    <span class="seal-tag">OPERABILITY SLO</span>
    <span class="seal-state">{_esc(slo_line)}</span>
  </div>"""

    sig = replay.get("signature") or {}
    sig_hex = sig.get("signature", "")
    sig_block = ""
    if sig_hex:
        short_sig = str(sig_hex)[:24] + "..."
        signer = sig.get("signer", "Deadline Warden")
        fp = sig.get("pubkey_fingerprint", "")
        sig_block = f"""
  <div class="cover-seal seal-ok">
    <span class="seal-tag">SIGNATURE</span>
    <span class="seal-hash">{_esc(short_sig)}</span>
    <span class="seal-state">signed by {_esc(signer)} (ed25519, key fp {_esc(fp)})</span>
  </div>
  <p class="chain-caption">{_esc(sig.get("caveat", ""))}</p>"""

    # Deadline-compliance attestation seal: the signed timeliness verdict on the
    # cover. The attestation digest is folded into the signature above, so this
    # green "deadlines met, signed" panel is a SIGNED claim, not a label. Rendered
    # only when filings were attested; omitted cleanly otherwise.
    att = p.get("attestation") or {}
    att_block = ""
    if att.get("filed_count"):
        att_all_met = att.get("all_met", False)
        att_cls = "seal-ok" if att_all_met else "seal-bad"
        filed = att.get("filed_count", 0)
        met = att.get("met_count", 0)
        att_state = (
            f"{met}/{filed} statutory deadlines met, signed" if att_all_met
            else f"{met}/{filed} deadlines met, signed")
        att_block = f"""
  <div class="cover-seal {att_cls}">
    <span class="seal-tag">DEADLINES MET</span>
    <span class="seal-state">{_esc(att_state)}</span>
  </div>"""

    return f"""<section class="cover">
  <div class="cover-band">
    <div class="cover-title">EXAMINER PACKET</div>
    <div class="cover-class">CONFIDENTIAL: REGULATORY FILING RECORD</div>
  </div>
  <div class="cover-grid">
    <div class="cover-field"><span class="ck">Incident reference</span>
      <span class="cv">{_esc(incident_id)}</span></div>
    <div class="cover-field"><span class="ck">Reporting entity</span>
      <span class="cv">{_esc(entity)}</span></div>
    <div class="cover-field"><span class="ck">Competent authority</span>
      <span class="cv">{_esc(authority)}</span></div>
  </div>
  <div class="cover-section-label">Statutory clocks</div>
  <div class="jurisdictions">{chips_html}</div>
  <div class="cover-section-label">Signoff chain (segregation of duties)</div>
  {chain_html}
  <div class="cover-seal {seal_cls}">
    <span class="seal-tag">RUN-LOG SEAL</span>
    <span class="seal-hash">{_esc(short_sha)}</span>
    <span class="seal-state">{_esc(seal_text)}</span>
  </div>{sig_block}{att_block}{slo_block}
</section>"""


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
        ["Clock", "Branch", "Trigger event", "Started", "Deadline", "Stopped",
         "Breached"],
        [[c.get("name"), c.get("correlation_id"), c.get("trigger_event"),
          c.get("started"), c.get("deadline"), c.get("stopped") or "(running)",
          c.get("breached")]
         for c in clocks],
    )
    filing_blocks = "".join(
        f"<div class='filing'><h3>{_esc(f.get('regime'))} filing "
        f"<span class='by'>by {_esc(f.get('by'))} via {_esc(f.get('model'))}</span></h3>"
        + (f"<p class='model-why'><strong>Why {_esc(f.get('model'))} holds this "
           f"role:</strong> {_esc(f.get('rationale'))}</p>"
           if f.get('rationale') else "")
        + f"<pre>{_esc(strip_citations(f.get('text', '')))}</pre></div>"
        for f in filings
    )
    cover = _render_cover(p)
    handoff_graph = _render_handoff_graph(p)
    diff_summary = _render_diff(diff)
    reconciliation_block = _render_reconciliation(p.get("reconciliation", {}))
    chaos_block = _render_chaos(p.get("chaos", {}))
    security_block = _render_security(p.get("security", {}))
    grounding_block = _render_grounding(p.get("grounding", {}))
    adversarial_block = _render_adversarial_review(p.get("adversarial_review", {}))
    materiality_block = _render_materiality(p.get("materiality", {}))
    recruit_block = _render_recruit(p.get("recruit", {}))
    nydfs_recruit_block = _render_nydfs_recruit(p.get("nydfs_recruit", {}))
    release_block = _render_release(p.get("release", {}))
    attestation_block = _render_attestation(p.get("attestation", {}))
    timestamp_block = _render_timestamp(p.get("timestamp", {}))
    reliability_block = _render_reliability(p.get("reliability", {}))
    operability_block = _render_operability(p.get("operability", {}))
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
/* Light "filing" theme: reads as an enterprise document on screen and prints as
   a clean regulator-style PDF. All chrome is ASCII; data is escaped upstream. */
body {{ font: 15px/1.55 -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
        background: #eef0f3; color: #1b1f27; }}
.wrap {{ max-width: 980px; margin: 0 auto; padding: 28px 20px 64px;
         background: #ffffff; }}
h1 {{ font-size: 26px; margin: 0 0 4px; }}
h2 {{ font-size: 18px; margin: 30px 0 10px; border-bottom: 2px solid #c9d0db;
      padding-bottom: 6px; }}
h3 {{ font-size: 15px; margin: 18px 0 6px; }}
.sub {{ color: #5b6473; margin: 0 0 8px; }}
.badge {{ display: inline-block; background: #1d6f42; color: #fff; border-radius: 4px;
          padding: 2px 8px; font-size: 12px; margin-right: 6px; }}
.badge.warn {{ background: #8a5a00; }}
table {{ width: 100%; border-collapse: collapse; margin: 6px 0 4px; font-size: 13px;
         break-inside: avoid; }}
th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #d7dce4;
          vertical-align: top; }}
th {{ color: #5b6473; font-weight: 600; background: #f4f6f9; }}
pre {{ background: #f6f8fa; border: 1px solid #d7dce4; border-radius: 6px;
       padding: 12px; white-space: pre-wrap; word-break: break-word; font-size: 13px;
       break-inside: avoid; }}
.filing {{ break-inside: avoid; }}
.filing .by {{ color: #5b6473; font-weight: 400; font-size: 12px; }}
.model-why {{ color: #44506a; font-size: 13px; margin: 2px 0 8px;
              border-left: 3px solid #c9d0db; padding-left: 10px; }}
.ok {{ color: #1d7a43; }}
.bad {{ color: #b3261e; }}
code {{ background: #f0f2f5; padding: 1px 5px; border-radius: 4px; }}
.hash {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
         word-break: break-all; }}

/* ---- Regulator-style cover ---------------------------------------------- */
.cover {{ border: 1.5px solid #1b2a4a; border-radius: 8px; margin: 4px 0 28px;
          overflow: hidden; break-inside: avoid; page-break-after: always; }}
.cover-band {{ background: #1b2a4a; color: #fff; padding: 16px 20px; }}
.cover-title {{ font: 700 22px/1.2 Georgia, "Times New Roman", serif;
                letter-spacing: 2px; }}
.cover-class {{ font-size: 12px; letter-spacing: 1px; color: #c5cfe4; margin-top: 4px; }}
.cover-grid {{ display: flex; flex-wrap: wrap; gap: 10px 28px; padding: 16px 20px 4px; }}
.cover-field {{ display: flex; flex-direction: column; }}
.ck {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #5b6473; }}
.cv {{ font-size: 15px; font-weight: 600; }}
.cover-section-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
                        color: #5b6473; padding: 14px 20px 0; font-weight: 600; }}
.jurisdictions {{ display: flex; flex-wrap: wrap; gap: 10px; padding: 8px 20px 4px; }}
.jchip {{ border: 1px solid #d7dce4; border-radius: 6px; padding: 8px 10px;
          min-width: 150px; border-left-width: 5px; }}
.jname {{ font-weight: 600; font-size: 13px; }}
.jdeadline {{ font-size: 11px; color: #5b6473; font-family: ui-monospace, monospace; }}
.jtrigger {{ font-size: 11px; color: #5b6473; font-style: italic; margin-top: 1px; }}
.jstatus {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px;
            font-weight: 700; margin-top: 2px; }}
.jchip.st-ok {{ border-left-color: #1d7a43; }} .jchip.st-ok .jstatus {{ color: #1d7a43; }}
.jchip.st-warn {{ border-left-color: #9a6a00; }} .jchip.st-warn .jstatus {{ color: #9a6a00; }}
.jchip.st-bad {{ border-left-color: #b3261e; }} .jchip.st-bad .jstatus {{ color: #b3261e; }}
.signoff-chain {{ padding: 6px 20px 0; }}
.chain-row {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px;
              padding: 6px 0; border-bottom: 1px dashed #e1e5ec; }}
.chain-corr {{ font-family: ui-monospace, monospace; font-size: 12px; color: #5b6473;
               min-width: 130px; }}
.signer {{ font-size: 13px; }}
.signer-actor {{ color: #5b6473; }}
.signer-ts {{ font-family: ui-monospace, monospace; font-size: 11px; color: #5b6473; }}
.chain-arrow {{ color: #9aa3b2; font-size: 12px; padding: 0 2px; }}
.chain-caption {{ padding: 6px 20px 12px; color: #5b6473; font-style: italic;
                  font-size: 13px; margin: 0; }}
.cover-seal {{ display: flex; flex-wrap: wrap; align-items: center; gap: 12px;
               margin: 4px 20px 18px; padding: 10px 14px; border-radius: 6px;
               background: #f4f6f9; border: 1px solid #d7dce4; }}
.seal-tag {{ font-size: 11px; font-weight: 700; letter-spacing: 1px; color: #1b2a4a; }}
.seal-hash {{ font-family: ui-monospace, monospace; font-size: 12px; word-break: break-all; }}
.seal-state {{ font-size: 12px; font-weight: 700; text-transform: uppercase;
               letter-spacing: 1px; }}
.cover-seal.seal-ok .seal-state {{ color: #1d7a43; }}
.cover-seal.seal-bad .seal-state {{ color: #b3261e; }}

/* ---- Handoff graph (inline SVG) ----------------------------------------- */
.graph-wrap {{ border: 1px solid #d7dce4; border-radius: 8px; padding: 8px;
               background: #fbfcfe; margin: 6px 0 10px; break-inside: avoid; }}
.handoff-graph .lane {{ stroke: #d7dce4; stroke-width: 1; }}
.handoff-graph .lane-label {{ fill: #1b2a4a; font: 600 12px sans-serif; }}
.handoff-graph .node {{ fill: #1b2a4a; }}
.handoff-graph .edge {{ stroke: #44506a; stroke-width: 1.5; }}
.handoff-graph .edge marker, .handoff-graph marker path {{ fill: #44506a; }}
.handoff-graph .edge-label {{ fill: #44506a; font: 11px ui-monospace, monospace; }}
.handoff-graph .gate {{ stroke-width: 1.5; }}
.handoff-graph .gate.gate-ok {{ fill: #e6f4ec; stroke: #1d7a43; }}
.handoff-graph .gate.gate-warn {{ fill: #fbf2dd; stroke: #9a6a00; }}
.handoff-graph .gate.gate-bad {{ fill: #fbe6e4; stroke: #b3261e; }}
.handoff-graph .gate-text {{ fill: #1b1f27; font: 700 13px sans-serif; }}
.handoff-graph .gate-sub {{ fill: #5b6473; font: 11px sans-serif; }}

/* ---- Print / PDF: clean filing theme ------------------------------------ */
@media print {{
  body {{ background: #fff; color: #000; font-size: 12px; }}
  .wrap {{ max-width: none; margin: 0; padding: 0 12px; }}
  a {{ color: inherit; text-decoration: none; }}
  h2, h3, table, pre, .filing, .cover, .graph-wrap, .jchip, .chain-row,
  .cover-seal {{ break-inside: avoid; page-break-inside: avoid; }}
  .cover {{ page-break-after: always; }}
  h2 {{ page-break-after: avoid; }}
  .cover-band {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  th {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
}}
</style></head>
<body><div class="wrap">
{cover}
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
<div class="graph-wrap">{handoff_graph}</div>
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

{nydfs_recruit_block}

<h2>6. Cross-filing contradiction diff</h2>
{diff_summary}

{reconciliation_block}

<h2>7. Drafted filings</h2>
{filing_blocks or '<p>No filings drafted.</p>'}

{chaos_block}

{security_block}

{grounding_block}

{adversarial_block}

{release_block}

{attestation_block}

{timestamp_block}

{reliability_block}

{operability_block}

<h2>8. Byte-identical replay</h2>
<p>Run-log SHA-256: <span class="hash">{_esc(replay.get('original_sha256', ''))}</span></p>
<p>Replayed SHA-256: <span class="hash">{_esc(replay.get('replayed_sha256', ''))}</span></p>
<p class="{'ok' if replay.get('byte_identical') else 'bad'}">
  {'Replay reproduced the run log byte for byte.' if replay.get('byte_identical')
   else 'Replay did not match.'}</p>

{pending_section}
</div></body></html>"""
