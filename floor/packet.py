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


def _render_deficiency(d: dict) -> str:
    """Render the deficiency / rejection loop (E3.9), if the deficiency beat ran:
    the modeled regulator's typed DEFICIENCY NOTICE on the released filing, the
    cure roundtrip on the corrected-resubmission seam, and the final ACCEPTED FOR
    FILING stamp.

    The modeled regulator is an HONEST stub: a per-regime mandated-field
    completeness screen, not a real government endpoint, and it assigns no
    accession or receipt number. The notice names the exact mandated field that was
    missing; the cure re-files it; the re-review accepts. The detection is
    deterministic Python and the review never gates a Warden transition, so this is
    an examiner-side read rendered from the packet, outside the hashed run-log."""
    if not d:
        return ""
    initial = d.get("initial_review", {})
    final = d.get("final_review", {})
    omitted = d.get("omitted_field", "")
    regime = d.get("regime", "")
    parts = ["<h2>6c. Deficiency / rejection loop (modeled regulator intake)</h2>",
             "<p class='sub'>A real filing does not vanish into the regulator on "
             "release: an intake desk reviews it and, if a mandated field is "
             "missing, issues a DEFICIENCY NOTICE that the filer must cure and "
             "resubmit. Here a MODELED regulator (an honest stub: a per-regime "
             "mandated-field completeness screen, not a real government endpoint, "
             "and no accession or receipt number is invented) reviews the released "
             f"{_esc(regime)} filing, the room cures the cited defect on the "
             "existing corrected-resubmission seam, and the modeled regulator "
             "re-reviews. The deficiency detection and every Warden transition are "
             "deterministic Python; only the re-draft prose is the model's.</p>"]
    # The typed deficiency notice the screen returned on the initial release.
    parts.append(
        f"<p class='bad'><strong>{_esc(regime)} initial release: "
        f"{_esc(initial.get('stamp'))}.</strong> The modeled regulator rejected the "
        f"filing for a corrected resubmission.</p>")
    notice_rows = [
        [df.get("code"), df.get("deficient_field"), df.get("severity"),
         df.get("reason")]
        for df in initial.get("deficiencies", [])
    ]
    parts.append("<p class='sub'>Deficiency notice (each row a typed defect the "
                 "completeness screen named):</p>")
    parts.append(_rows(
        ["Code", "Deficient field", "Severity", "Reason"], notice_rows))
    # The cure roundtrip.
    parts.append(
        "<p class='sub'>Cure roundtrip: the Warden reopened the "
        f"{_esc(regime)} branch (FACT_AMENDED, released -&gt; amending, Band message "
        f"{_esc(d.get('notice_message_id'))}); the drafter re-drafted the "
        f"<code>{_esc(omitted)}</code> field and re-filed (Band message "
        f"{_esc(d.get('cure_message_id'))}); the cured filing re-released under the "
        "same two-key gate.</p>")
    # The final accepted stamp, with the honest modeled-stub caveat.
    parts.append(
        f"<p class='ok'><strong>{_esc(regime)} corrected resubmission: "
        f"{_esc(final.get('stamp'))}.</strong> The completeness screen now finds "
        "every mandated field present. The rejection-then-cure loop closed.</p>")
    parts.append(
        f"<p class='sub'><em>{_esc(final.get('caveat'))}</em></p>")
    return "".join(parts)


def _render_submission(s: dict) -> str:
    """Render the end-to-end submission pipeline (E4.1), if the submit beat ran: per
    regime, the machine-readable submission artifact that was exported, the modeled
    filed receipt the stubbed endpoint returned, and the honest modeled-channel
    caveat.

    The submission FORMAT (the EDGAR-shaped 8-K for SEC, the structured per-regime
    payloads for the others) and the required-field contract VALIDATION are real; the
    network hop to the actual regulator is MODELED, the filing id is a modeled
    accession-style id derived from the artifact bytes (never a real EDGAR accession
    number), and no government acknowledgement is fabricated. The receipt is the one
    piece sealed INTO the hashed run-log (so the chain head and the signature attest
    the filed outcome), and its artifact_sha256 binds it to THIS exact artifact: a
    judge re-runs scripts/verify_submission.py to confirm the sha matches the
    artifact and the contract was validated."""
    if not s or not s.get("submissions"):
        return ""
    parts = [
        "<h2>10. Submission pipeline (filed-receipt loop)</h2>",
        "<p class='sub'>A deployable system does not stop at a drafted filing: it "
        "produces the regulator's machine-readable submission format, pushes it "
        "through a submission channel, and captures the regulator's filed-receipt "
        "back into the same signed evidence chain. After the two-key release, each "
        "in-scope regime's filing is EXPORTED to its submission format (the "
        "EDGAR-shaped Form 8-K Item 1.05 for SEC; structured per-regime payloads "
        "keyed by the real mandated field labels for the others), SUBMITTED to an "
        "honestly-stubbed regulator endpoint that runs a real required-field "
        "contract validation, and the modeled filed receipt is SEALED into the "
        "hashed run-log as a <code>submission_receipt</code> event, so the chain "
        "head and the Ed25519 signature now attest the FILED outcome, not just the "
        "draft.</p>",
        "<p class='sub'><strong>Honest modeled channel:</strong> the submission "
        "format and the field-contract validation are real; the network hop to the "
        "actual regulator is modeled (a local stub). The filing id is a modeled "
        "accession-style id derived from the artifact bytes, not a real EDGAR "
        "accession number, and no government acknowledgement is fabricated. A "
        "production deployment swaps the stub for an authenticated EDGAR / "
        "CSIRT-portal / ICO connector behind the same interface.</p>",
    ]
    rows = []
    for sub in s.get("submissions", []):
        receipt = sub.get("receipt", {})
        artifact = sub.get("artifact", {})
        rows.append([
            sub.get("regime"),
            receipt.get("channel"),
            receipt.get("modeled_filing_id"),
            receipt.get("accepted_at"),
            (receipt.get("artifact_sha256", "") or "")[:16] + "...",
            str(len(receipt.get("validated_fields", []) or artifact.get("fields", []))),
        ])
    parts.append("<p class='sub'>Filed receipts (one row per regime; each receipt "
                 "is sealed into the signed chain):</p>")
    parts.append(_rows(
        ["Regime", "Modeled channel", "Modeled filing id", "Accepted at (modeled)",
         "Artifact sha256", "Fields validated"], rows))
    parts.append(
        "<p class='ok'><strong>FILED (modeled): each released filing was exported, "
        "submitted, contract-validated, and its receipt sealed into the signed "
        "chain.</strong> The signature attests this exact ordered run produced "
        "these exact artifacts and received these modeled receipts.</p>")
    parts.append(
        f"<p class='sub'><em>{_esc(s.get('caveat'))}</em></p>")
    return "".join(parts)


def _render_completeness(c: dict) -> str:
    """Render the per-regime submission COMPLETENESS SHEET (E4.2): the examiner's
    first auto-screen. Per regime, a green/amber matrix over the EXACT mandated field
    labels the form requires, each marked PRESENT / EMPTY / NOT-APPLICABLE, with an
    overall complete/incomplete verdict per regime and across the submission.

    This is what an examiner's intake system shows FIRST: before any human reads the
    prose, the structured submission is auto-screened for completeness against the
    form's mandated fields. The matrix is a PURE DERIVED RENDER read from the labelled
    sections of the filing prose (the same labels that drive the deficiency screen and
    the submission export, drawn from the same regime catalog that drives the clocks).
    Zero LLM, no now(); it never enters the hashed run-log and gates nothing."""
    if not c or not c.get("sheets"):
        return ""
    all_complete = c.get("all_complete", False)
    top_cls = "ok" if all_complete else "bad"
    headline = (
        "Submission completeness screen PASSED: every mandated field of every owed "
        "regime is present. The structured submission clears automated intake."
        if all_complete else
        "Submission completeness screen INCOMPLETE: at least one mandated field is "
        "empty. A real intake desk would return a deficiency notice (see below).")
    parts = [
        "<h2>0. Submission completeness screen (the examiner's first auto-screen)</h2>",
        f"<p class='{top_cls}'><strong>{_esc(headline)}</strong></p>",
        "<p class='sub'>An examiner does not read the prose first. The intake system "
        "auto-screens the STRUCTURED submission before any human looks at it: for "
        "each regime, every mandated field the form requires is checked against the "
        "EXACT field labels the form defines, and marked PRESENT, EMPTY, or "
        "NOT-APPLICABLE. A single empty mandated field is a guaranteed deficiency "
        "notice. This matrix is generated from the SAME per-regime field catalog that "
        "drives the statutory clocks (regulation as config): the mandated-field "
        "labels here are the labels the drafter filled. It is a pure derived read "
        "over the filing prose, never a gate.</p>",
    ]
    for sheet in c.get("sheets", []):
        applicable = sheet.get("applicable", True)
        complete = sheet.get("complete", False)
        verdict = sheet.get("verdict", "")
        v_cls = "ok" if complete else ("sub" if not applicable else "bad")
        parts.append(
            f"<h3>{_esc(sheet.get('regime'))} &mdash; {_esc(sheet.get('form_title'))}</h3>"
            .replace("&mdash;", ":"))
        parts.append(
            f"<p class='{v_cls}'><strong>{_esc(verdict)}</strong> "
            f"<span class='sub'>({_esc(sheet.get('cover_tag'))})</span></p>")
        rows = []
        for fld in sheet.get("fields", []):
            status = fld.get("status", "")
            if status == "PRESENT":
                badge = "<span class='cstat cstat-ok'>PRESENT</span>"
            elif status == "NA":
                badge = "<span class='cstat cstat-na'>N/A</span>"
            else:
                badge = "<span class='cstat cstat-bad'>EMPTY</span>"
            rows.append(
                "<tr><td><strong>" + _esc(fld.get("label")) + "</strong></td>"
                "<td>" + badge + "</td>"
                "<td>" + _esc(fld.get("evidence")) + "</td></tr>")
        parts.append(
            "<table><thead><tr><th>Mandated field</th><th>Status</th>"
            "<th>Evidence</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")
    return "".join(parts)


def _render_consistency(c: dict) -> str:
    """Render the cross-filing CONSISTENCY ASSERTION SHEET (E4.3): the affirmative,
    examiner-facing attestation that all N filings AGREE on the load-bearing facts.
    The inverse face of the contradiction veto: instead of only BLOCKING on a
    conflict, it affirmatively ATTESTS that every filing reports the same
    incident_start_utc, records_affected, attacker, and containment, with each shared
    value shown ONCE, a per-fact CONSISTENT / CONFLICT status, the list of filings
    asserting it, and an overall "all N filings consistent across M load-bearing
    facts" verdict.

    This is the cross-filing consistency a regulator checks across a multi-jurisdiction
    filing set: when the same incident is filed to SEC, ICO, NIS2, DORA, and NYDFS the
    examiner cross-reads them, and a mismatched records count or incident_start across
    filings is a referral. The sheet is a PURE DERIVED render over the already-
    reconciled per-branch claims the packet carries (diff.final_claims), with the
    CONSISTENT / CONFLICT decision computed through the SAME warden/diff.py
    canonicalization the veto uses (so a timezone-equivalent value is still
    CONSISTENT). Zero LLM, no now(); it never enters the hashed run-log and gates
    nothing."""
    if not c or not c.get("facts"):
        return ""
    consistent = c.get("consistent", False)
    filing_count = c.get("filing_count", 0)
    fact_count = c.get("fact_count", 0)
    top_cls = "ok" if consistent else "bad"
    headline = (
        f"Cross-filing consistency ATTESTED: all {filing_count} filings report the "
        f"same value on every one of the {fact_count} load-bearing facts. An examiner "
        "cross-reading the filing set finds no mismatch."
        if consistent else
        "Cross-filing consistency CONFLICT: the filings disagree on a load-bearing "
        "fact. An examiner cross-reading the set would refer this (see the conflict "
        "below); the contradiction veto blocks release on the same conflict.")
    filings = ", ".join(c.get("filings", []))
    parts = [
        "<h2>6a. Cross-filing consistency assertion (the examiner's cross-read)</h2>",
        f"<p class='{top_cls}'><strong>{_esc(headline)}</strong></p>",
        "<p class='sub'>When the same incident is filed to several regulators, the "
        "examiner CROSS-READS the filings: a records count or incident_start that "
        "differs across filings is a referral. The contradiction veto catches the "
        "BLOCKING conflicts internally; this is the affirmative attestation the "
        "examiner wants, that the load-bearing facts are IDENTICAL across all filings, "
        "with each shared value shown once. It is a pure derived read over the "
        "already-reconciled claims, computed through the SAME UTC canonicalization the "
        "veto uses, so a timezone-equivalent value is still consistent. It is a sheet, "
        "never a gate.</p>",
        f"<p class='sub'>Filings cross-read: <code>{_esc(filings)}</code>.</p>",
    ]
    rows = []
    for fact in c.get("facts", []):
        status = fact.get("status", "")
        if status == "CONSISTENT":
            badge = "<span class='cstat cstat-ok'>CONSISTENT</span>"
            value_cell = "<code>" + _esc(fact.get("agreed_value")) + "</code>"
            asserting = _esc(", ".join(fact.get("filings", [])))
        else:
            badge = "<span class='cstat cstat-bad'>CONFLICT</span>"
            conflict = fact.get("conflict", [])
            value_cell = "; ".join(
                "<strong>" + _esc(p.get("filing")) + "</strong>: <code>"
                + _esc(p.get("value")) + "</code>" for p in conflict)
            asserting = "(disagreement, see value column)"
        rows.append(
            "<tr><td><strong>" + _esc(fact.get("label")) + "</strong></td>"
            "<td>" + value_cell + "</td>"
            "<td>" + asserting + "</td>"
            "<td>" + badge + "</td></tr>")
    parts.append(
        "<table><thead><tr><th>Load-bearing fact</th><th>Agreed value</th>"
        "<th>Filings asserting it</th><th>Status</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>")
    parts.append(
        f"<p class='{top_cls}'><strong>{_esc(c.get('verdict', ''))}.</strong></p>")
    return "".join(parts)


def _render_controls(c: dict) -> str:
    """Render the CONTROL-EVIDENCE REGISTER (E4.4): the named-framework control
    mapping an audit committee reads. Per control, the Warden mechanism, the
    SPECIFIC named controls it satisfies across SOC 2, ISO/IEC 27001:2022, and
    NIST CSF 2.0 (plus the relevant regulation article), the EVIDENCE that the
    control OPERATED in THIS run (the exact run-log event type(s) found and the
    chain head that seals them), and an OPERATED / NOT-EXERCISED status.

    This is the artifact that reframes the product from "a fast filing engine"
    into "a tool an audit committee can buy". An auditor does not ask "did it
    file on time"; they ask which named control framework each mechanism
    satisfies and where the evidence is. The register answers both, mapping each
    existing Warden mechanism (two-key release, contradiction veto, exactly-once
    ledger, signed hash-chained provenance, statutory clocks, the reportability
    decision gate) to its real control ids and pointing the evidence at the
    run-log event(s) and the run's chain head. It is a PURE DERIVED render over
    the assembled packet (floor/controls.py + the declarative floor/controls.yaml
    catalog): zero LLM, no now(); it never enters the hashed run-log and gates
    nothing. NOT-EXERCISED is honest, not a failure: it states this run did not
    exercise that control path (e.g. the veto on a clean run)."""
    if not c or not c.get("controls"):
        return ""
    operated = c.get("operated_count", 0)
    total = c.get("total", 0)
    chain_head = ""
    for ctrl in c.get("controls", []):
        head = (ctrl.get("evidence", {}) or {}).get("chain_head")
        if head:
            chain_head = head
            break
    parts = [
        "<h2>11. Control-evidence register (named-framework control mapping)</h2>",
        f"<p class='ok'><strong>{_esc(operated)} of {_esc(total)} catalogued "
        "controls OPERATED and are evidenced in this run.</strong> Each row maps a "
        "Warden mechanism to a specific named control across SOC 2, ISO/IEC "
        "27001:2022, and NIST CSF 2.0, and points the evidence at the run-log "
        "event(s) that prove the control operated and the chain head that seals "
        "them.</p>",
        "<p class='sub'>An auditor does not accept &quot;two-key release&quot; as a "
        "control statement; they accept &quot;Control SOD-01 (SOC 2 CC1.3; ISO/IEC "
        "27001 A.5.3; NIST CSF PR.AA-05): two distinct human roles signed before "
        "HUMAN_RELEASED, evidenced by the run-log release_signoff events and sealed "
        "at the chain head&quot;. This register is that statement for every "
        "mechanism. It is a pure derived read over the assembled packet (the "
        "structured mirror of the sealed run-log), generated from a declarative "
        "control catalog; it never enters the hashed run-log and gates nothing. "
        "NOT-EXERCISED states honestly that this run's scenario did not exercise "
        "that control path (for example the contradiction veto on a run with no "
        "planted contradiction).</p>",
    ]
    if chain_head:
        parts.append(
            f"<p class='sub'>Evidence seal for this run (per-entry hash chain "
            f"head): <span class='hash'>{_esc(chain_head)}</span>. Every OPERATED "
            "control's evidence is bound to this head, so a field edit or a "
            "reorder/omission moves the head and the detached Ed25519 signature "
            "over it turns INVALID.</p>")
    rows = []
    for ctrl in c.get("controls", []):
        status = ctrl.get("status", "")
        if status == "OPERATED":
            badge = "<span class='cstat cstat-ok'>OPERATED</span>"
        else:
            badge = "<span class='cstat cstat-na'>NOT-EXERCISED</span>"
        ev = ctrl.get("evidence", {}) or {}
        found = ev.get("found_events", []) or []
        evidence_cell = (
            "<code>" + _esc(", ".join(found)) + "</code><br>"
            + "<span class='sub'>" + _esc(ev.get("detail", "")) + "</span>"
            if found else
            "<span class='sub'>" + _esc(ev.get("detail", "")) + "</span>")
        framework_cell = "<br>".join(
            "<strong>" + _esc(fw.get("standard")) + " " + _esc(fw.get("ref"))
            + "</strong>: " + _esc(fw.get("criterion"))
            for fw in ctrl.get("frameworks", []))
        rows.append(
            "<tr><td><strong>" + _esc(ctrl.get("id")) + "</strong><br>"
            + _esc(ctrl.get("title")) + "<br><span class='sub'>"
            + _esc(ctrl.get("mechanism")) + "</span></td>"
            "<td>" + framework_cell + "</td>"
            "<td>" + evidence_cell + "</td>"
            "<td>" + badge + "</td></tr>")
    parts.append(
        "<table><thead><tr><th>Control / mechanism</th>"
        "<th>Named-framework controls satisfied</th>"
        "<th>Run-log evidence (sealed at chain head)</th>"
        "<th>Status</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>")
    parts.append(
        f"<p class='sub'><strong>{_esc(c.get('verdict', ''))}</strong></p>")
    return "".join(parts)


def _render_assertion(a: dict) -> str:
    """Render the signed MANAGEMENT ASSERTION (E4.8): the SOC-2-style attestation
    letter that sits on top of the control-evidence register.

    An audit engagement is anchored on a management assertion plus supporting
    evidence. The control-evidence register (E4.4) is the evidence; this is the
    one-page letter in which management asserts the relevant controls operated
    effectively over the reporting period, enumerates them with their named
    framework references and the sealed run-log evidence, and is signed. It is a
    PURE DERIVED summary over the SAME register the controls block is built from
    (floor/assertion.py): zero LLM, no now(); it never enters the hashed run-log
    and gates nothing.

    The letter's digest is signed by a SEPARATE, DETACHED Ed25519 signature held
    in the assertion sidecar (web/data/assertion-<scenario>.json), NOT folded into
    the run-log bound payload, so the run-log sha, the chain head, and
    byte-identical replay are untouched. The honest demo-key caveat travels with
    the signature. A reader re-derives the assertion, recomputes the digest, and
    verifies the signature with scripts/verify_assertion.py."""
    if not a or not a.get("document"):
        return ""
    doc = a.get("document", {}) or {}
    operated = a.get("operated_count", 0)
    total = a.get("total", 0)
    digest = a.get("digest", "")
    period = doc.get("period", {}) or {}
    parts = [
        "<h2>13. Management assertion (SOC-2-style attestation letter, signed)</h2>",
        f"<p class='ok'><strong>Management asserts {_esc(operated)} of "
        f"{_esc(total)} catalogued controls OPERATED and are evidenced over the "
        "reporting period.</strong> This is the one-page assertion an audit "
        "engagement anchors on: management asserts the relevant controls operated "
        "effectively, the control-evidence register above is the supporting "
        "evidence, and the assertion is signed.</p>",
        "<p class='sub'>An auditor tests a management assertion against its "
        "evidence. The assertion below is a pure derived summary of the "
        "control-evidence register (E4.4): the same controls, the same named "
        "framework references, the same OPERATED / NOT-EXERCISED status, and the "
        "same run-log evidence sealed at the chain head. Its digest is signed by a "
        "SEPARATE, DETACHED Ed25519 signature held in the assertion sidecar; the "
        "signature is NOT folded into the run-log payload, so the run-log seal and "
        "byte-identical replay are untouched. A reader re-derives the assertion, "
        "recomputes the digest, and verifies the signature with "
        "<code>scripts/verify_assertion.py</code>.</p>",
    ]
    start = period.get("start", "")
    end = period.get("end", "")
    if start or end:
        parts.append(
            f"<p class='sub'>Period asserted: "
            f"<code>{_esc(start or '(open)')}</code> through "
            f"<code>{_esc(end or '(open)')}</code> (UTC), the run window from the "
            "earliest statutory clock start to the furthest deadline.</p>")
    if digest:
        parts.append(
            f"<p class='sub'>Assertion digest (the signed value): "
            f"<span class='hash'>{_esc(digest)}</span>. A single edited field in "
            "the assertion moves this digest and the detached Ed25519 signature "
            "over it turns INVALID.</p>")
    # The formal attestation letter, verbatim, as the audit committee reads it.
    letter = a.get("letter", "")
    if letter:
        parts.append("<p class='sub'>The attestation letter:</p>")
        parts.append(f"<pre>{_esc(letter)}</pre>")
    return "".join(parts)


def _render_egress(e: dict) -> str:
    """Render the signed EGRESS ATTESTATION (E5.8): zero breach facts left the
    perimeter.

    A regulated bank can require that no breach fact be handed to a closed,
    third-party hosted model. A --sovereign run is one in which EVERY drafting role
    resolves to an open, self-hostable model (floor/roster.resolve), so no incident
    detail leaves the bank's perimeter. This block states that property, enumerates
    each role with its resolved provider and model and its open/closed posture, and
    carries the SEPARATE, DETACHED Ed25519 signature over the egress record.

    It is a PURE DERIVED summary of the roster under the active provider set
    (floor/egress_attestation.py): zero LLM, no now(); it never enters the hashed
    run-log and gates nothing. The egress digest is signed under a DISTINCT label
    in its OWN sidecar, NOT folded into the run-log bound payload, so the run-log
    seal, the four sealed .sig.json signatures, and byte-identical replay are
    untouched. The honest demo-key caveat travels with the signature. A reader
    re-derives the attestation, recomputes the digest, and verifies the signature
    with scripts/verify_egress.py. Rendered ONLY when present (a --sovereign run);
    omitted entirely otherwise."""
    if not e or not e.get("document"):
        return ""
    doc = e.get("document", {}) or {}
    sovereign = e.get("sovereign", False)
    self_hosted = e.get("self_hosted_count", 0)
    total = e.get("total", 0)
    digest = e.get("digest", "")
    provider_set = doc.get("provider_set", "")
    top_cls = "ok" if sovereign else "bad"
    headline = (
        f"Sovereign: all {_esc(total)} drafting roles resolve to a self-hosted "
        "open model, so ZERO breach facts left the perimeter."
        if sovereign else
        f"NOT sovereign: only {_esc(self_hosted)} of {_esc(total)} roles are "
        "self-hosted; the others route breach facts to a closed hosted model.")
    parts = [
        "<h2>14. Egress attestation (air-gapped / data-sovereignty, signed)</h2>",
        f"<p class='{top_cls}'><strong>{headline}</strong></p>",
        "<p class='sub'>A regulated bank may require that no breach fact leave its "
        "perimeter. In <code>--sovereign</code> mode the run REFUSES to start if "
        "any role would route to a closed hosted model, and emits this signed "
        "attestation that every drafting role resolves to an open, self-hostable "
        f"model under provider set <code>{_esc(provider_set)}</code>. The egress "
        "digest is signed by a SEPARATE, DETACHED Ed25519 signature under a "
        "DISTINCT label in its own sidecar; it is NOT folded into the run-log "
        "payload, so the run-log seal and byte-identical replay are untouched. A "
        "reader re-derives the attestation, recomputes the digest, and verifies "
        "the signature with <code>scripts/verify_egress.py</code>.</p>",
    ]
    roles = doc.get("roles", []) or []
    if roles:
        rows = ["<table><tr><th>Role</th><th>Provider</th><th>Model</th>"
                "<th>Posture</th></tr>"]
        for r in roles:
            posture = ("self-hosted (open)" if r.get("self_hosted")
                       else "hosted (closed)")
            cls = "ok" if r.get("self_hosted") else "bad"
            rows.append(
                f"<tr><td>{_esc(r.get('role_label', ''))}</td>"
                f"<td>{_esc(r.get('provider', ''))}</td>"
                f"<td><code>{_esc(r.get('model', ''))}</code></td>"
                f"<td class='{cls}'>{_esc(posture)}</td></tr>")
        rows.append("</table>")
        parts.append("".join(rows))
    if digest:
        parts.append(
            f"<p class='sub'>Egress digest (the signed value): "
            f"<span class='hash'>{_esc(digest)}</span>. A single edited field in "
            "the egress record moves this digest and the detached Ed25519 "
            "signature over it turns INVALID.</p>")
    sig = e.get("signature", {}) or {}
    fp = sig.get("pubkey_fingerprint", "")
    if fp:
        parts.append(
            f"<p class='sub'>Signed by {_esc(sig.get('signer', 'Deadline Warden'))} "
            f"(key fp <code>{_esc(fp)}</code>), detached under label "
            f"<code>{_esc(sig.get('signed_payload', ''))}</code>.</p>")
    return "".join(parts)


def _render_sod(s: dict) -> str:
    """Render the SEPARATION-OF-DUTIES MATRIX (E4.5): the segregation of duties proven
    across the WHOLE run, not only at the two-key release gate.

    The two-key gate proves SoD on ONE action (release). An auditor's SoD question is
    broader: prove no single identity ever spanned a pair of duties that must stay
    separated (author a filing AND release it; gate a filing AND author it). This
    matrix answers it from the run's own events: per identity, the role(s) it acted as
    and every protocol action it performed, plus the named SoD invariants (distinct
    release keys, no draft-and-release by one actor, the Warden never authors what it
    gates, release roles disjoint from drafter roles), each PASS / FAIL with the
    evidence events. It is a PURE DERIVED render over the assembled packet
    (floor/sod.py over packet["state_transitions"] + packet["release"]["signoffs"]):
    zero LLM, no now(); it never enters the hashed run-log and gates nothing. A FAIL
    is not green-washed: a genuine SoD violation names the violating actor."""
    if not s or not s.get("invariants"):
        return ""
    all_hold = s.get("all_hold", False)
    top_cls = "ok" if all_hold else "bad"
    total = s.get("total_invariants", 0)
    headline = (
        f"Separation of duties PROVEN across the whole run: all {total} SoD invariants "
        "hold; no identity spanned a conflicting pair of duties."
        if all_hold else
        f"Separation of duties VIOLATION: {s.get('failed_count', 0)} of {total} SoD "
        "invariants FAILED. An identity spanned a conflicting pair of duties (named "
        "below).")
    parts = [
        "<h2>12. Separation-of-duties matrix (proven across the whole run)</h2>",
        f"<p class='{top_cls}'><strong>{_esc(headline)}</strong></p>",
        "<p class='sub'>The two-key release gate proves segregation of duties on ONE "
        "action: a filing cannot release without two distinct human keys. An auditor's "
        "SoD question is broader: prove that across the ENTIRE run no single identity "
        "ever spanned a pair of duties that must stay separated, authoring a filing AND "
        "releasing it, or gating a filing AND authoring it. This matrix proves it from "
        "the run's own events: every state-machine transition carries the actor and the "
        "role it acted as, and every two-key release records its keys. It is a pure "
        "derived read over the assembled packet (the same role vocabulary the Warden's "
        "authority table defines); it never enters the hashed run-log and gates "
        "nothing. A failing invariant names the violating actor: it is the real check, "
        "not a decoration.</p>",
        f"<p class='{top_cls}'><strong>{_esc(s.get('verdict', ''))}.</strong></p>",
    ]
    # The named SoD invariants, each PASS / FAIL with its basis.
    inv_rows = []
    for inv in s.get("invariants", []):
        if inv.get("status") == "PASS":
            badge = "<span class='cstat cstat-ok'>PASS</span>"
        else:
            badge = "<span class='cstat cstat-bad'>FAIL</span>"
        inv_rows.append(
            "<tr><td><strong>" + _esc(inv.get("id")) + "</strong></td>"
            "<td>" + _esc(inv.get("title")) + "</td>"
            "<td>" + _esc(inv.get("detail")) + "</td>"
            "<td>" + badge + "</td></tr>")
    parts.append("<p class='sub'>The named segregation invariants, each asserted on "
                 "every path through the run:</p>")
    parts.append(
        "<table><thead><tr><th>Invariant</th><th>Segregation property</th>"
        "<th>Basis</th><th>Status</th></tr></thead><tbody>"
        + "".join(inv_rows) + "</tbody></table>")
    # The observed actor x action matrix: per identity, its role(s), duty class(es),
    # and the protocol actions it performed.
    actor_rows = []
    for a in s.get("actors", []):
        actor_rows.append(
            "<tr><td><strong>" + _esc(a.get("actor")) + "</strong></td>"
            "<td>" + _esc(", ".join(a.get("roles", []))) + "</td>"
            "<td>" + _esc(", ".join(a.get("duties", []))) + "</td>"
            "<td><code>" + _esc(", ".join(a.get("actions", []))) + "</code></td></tr>")
    parts.append("<p class='sub'>The observed actor x action matrix (each identity, the "
                 "role(s) it acted as, the duty class it performed, and its protocol "
                 "actions):</p>")
    parts.append(
        "<table><thead><tr><th>Actor (identity)</th><th>Role(s)</th>"
        "<th>Duty class</th><th>Protocol actions performed</th>"
        "</tr></thead><tbody>"
        + "".join(actor_rows) + "</tbody></table>")
    return "".join(parts)


def _render_legal_hold(h: dict) -> str:
    """Render the legal-hold / preservation obligation (E3.10), if the legal-hold
    beat ran: the trigger (incident detection) and the attached-at timestamp, the
    preservation scope where each item is bound to the EXACT canonical fact-record
    FIELD it rests on (the affected systems and data categories), the FRCP 37(e)
    preservation / spoliation basis, the active/released state, and the human
    release record.

    The hold attaches BY RULE at incident detection and is RELEASED only by an
    explicit human signoff (counsel); it is never auto-released by a clock, a
    filing, or any rule, and it GATES NOTHING. The scope->fact binding and the
    record are deterministic Python; the validator gates nothing. Rendered from the
    packet, this is the preservation obligation a litigator checks was tracked, not
    missed."""
    if not h or not h.get("scope"):
        return ""
    state = (h.get("state") or "").upper()
    active = h.get("active")
    state_badge = "badge warn" if active else "badge"
    scope_check = h.get("preservation_scope") or {}
    complete = scope_check.get("complete", True)
    basis_cls = "ok" if complete else "bad"
    basis_line = (
        "Preservation scope COMPLETE: every scope item is bound to a field the "
        "canonical fact-record carries." if complete else
        "Preservation scope INCOMPLETE: a scope item cites a field not present in "
        "the fact-record (flagged below).")
    parts = [
        "<h2>5g. Legal hold / preservation obligation (FRCP 37(e))</h2>",
        "<p class='sub'>The instant a breach is reasonably anticipated to lead to "
        "litigation or a regulatory inquiry (which is when this war room convenes), "
        "the duty to PRESERVE evidence attaches: preserve the affected systems and "
        "data, suspend routine deletion. Failure to issue the hold is independent "
        "spoliation liability under FRCP 37(e), separate from the breach. The hold "
        "attaches BY RULE at incident detection, its scope bound to the real "
        "affected-systems and affected-data-categories fields; it is a STANDING "
        "obligation that stays active until counsel explicitly releases it (a human "
        "signoff), never auto-released. It is a PARALLEL preservation duty: it "
        "gates no filing, stops no statutory clock, moves no transition. Zero LLM: "
        "the hold attaches by rule and releases by a human.</p>",
        f"<p class='sub'>Trigger: <strong>{_esc(h.get('trigger_event'))}</strong>; "
        f"attached at <code>{_esc(h.get('attached_at'))}</code> "
        "(incident detection, the moment the statutory clocks also start).</p>",
        f"<p><span class='{state_badge}'>State: {_esc(state)}</span></p>",
        f"<p class='sub'>Basis: <em>{_esc(h.get('basis'))}</em></p>",
        f"<p class='{basis_cls}'><strong>{_esc(basis_line)}</strong></p>",
    ]
    rows = [
        [item.get("category"), item.get("value"), item.get("fact_field")]
        for item in h.get("scope", [])
    ]
    parts.append("<p class='sub'>Preservation scope (each item bound to the exact "
                 "canonical fact-record field it rests on):</p>")
    parts.append(_rows(
        ["Preservation item", "Value", "Bound to fact-record field"], rows))
    missing = scope_check.get("missing_items") or []
    if missing:
        items = "".join(
            f"<li>{_esc(m.get('category'))} cites missing field "
            f"<code>{_esc(m.get('fact_field'))}</code></li>" for m in missing)
        parts.append(f"<p class='bad'>Scope items citing a nonexistent fact-record "
                     f"field:</p><ul>{items}</ul>")
    release = h.get("release")
    if release:
        parts.append(
            "<p class='ok'><strong>Released by an explicit human signoff:</strong> "
            f"{_esc(release.get('actor'))} ({_esc(release.get('released_by'))}) at "
            f"<code>{_esc(release.get('ts'))}</code>. The hold was never "
            "auto-released; only this human signoff lifted it.</p>"
            f"<p class='sub'><em>{_esc(release.get('reason'))}</em></p>")
    else:
        parts.append(
            "<p class='bad'><strong>Hold is ACTIVE.</strong> It stays active until "
            "counsel explicitly releases it; no clock, filing, or rule lifts it.</p>")
    return "".join(parts)


def _render_reportability(r: dict) -> str:
    """Render the per-regime reportability / duty-to-notify gate (E3.1), if the
    reportability beat ran. Per regime: the statutory trigger standard, the
    reportable/not-reportable verdict, the file/suppress disposition, and the
    named rule for a suppressed regime. The qualitative call per regime is the
    LLM's; the gating is deterministic Python, exactly like the SEC materiality
    seam this generalizes."""
    if not r or not r.get("regimes"):
        return ""
    filed = r.get("filed", [])
    suppressed = r.get("suppressed", [])
    all_filed = not suppressed
    top_cls = "ok" if all_filed else "bad"
    headline = (
        f"Reportability assessed across {len(r['regimes'])} regime(s): "
        f"{len(filed)} crossed the threshold and file, {len(suppressed)} did "
        f"not and were suppressed.")
    parts = ["<h2>5a. Per-regime reportability (does the duty even attach?)</h2>",
             f"<p class='{top_cls}'><strong>{_esc(headline)}</strong></p>",
             "<p class='sub'>The first real incident-commander / counsel decision: "
             "per regime, does this incident cross that regulator's reporting "
             "THRESHOLD? An LLM applies each regime's statutory trigger standard to "
             "the fact-record and returns a typed reportable yes/no verdict; the "
             "verdict crosses into the deterministic Warden gate as data. A regime "
             "BELOW its threshold is driven to the terminal SUPPRESSED state with "
             "the rule shown, a regime ABOVE it files. The judgment is the LLM's; "
             "the gating is pure Python, replay-verifiable.</p>"]
    rows = []
    for reg in r["regimes"]:
        reportable = reg.get("reportable")
        disposition = "FILE" if reportable else "SUPPRESS"
        cls = "ok" if reportable else "bad"
        rule = reg.get("rule") if not reportable else ""
        rows.append(
            "<tr><td><strong>" + _esc(reg.get("regime")) + "</strong></td>"
            "<td>" + _esc(reg.get("standard")) + "</td>"
            f"<td class='{cls}'>" + ("REPORTABLE" if reportable
                                     else "NOT REPORTABLE") + "</td>"
            f"<td class='{cls}'>" + disposition + "</td>"
            "<td>" + _esc(rule) + "</td>"
            "<td><code>" + _esc(reg.get("source")) + "</code></td></tr>")
    parts.append(
        "<table><thead><tr><th>Regime</th><th>Statutory trigger standard</th>"
        "<th>Verdict</th><th>Decision</th><th>Rule (if suppressed)</th>"
        "<th>Decision source (LLM)</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>")
    # The per-regime rationale memos (the LLM's basis, never gated on) followed by
    # that regime's reasonable-basis determination record (the factor table, each
    # factor bound to a canonical fact-record field): the artifact a litigator
    # subpoenas, documented and signed per reportable judgment.
    for reg in r["regimes"]:
        if reg.get("rationale"):
            parts.append(
                f"<p class='sub'>{_esc(reg.get('regime'))} reportability "
                f"rationale:</p>")
            parts.append(f"<pre>{_esc(reg.get('rationale'))}</pre>")
        parts.append(_render_determination(reg.get("determination", {})))
    return "".join(parts)


def _render_affected_party(ap: dict) -> str:
    """Render the affected-party / GDPR Art 34 communication-to-data-subject track
    (E3.4), if the affected-party beat ran. The regulator clocks point at a
    government recipient; this track points at the affected INDIVIDUALS whose data
    leaked. It is a SEPARATE obligation, NOT a regulator filing, gated on the
    regulator release, and it attaches only on a HIGH RISK to the rights and
    freedoms of natural persons (a higher bar than the Art 33 regulator trigger).
    The high-risk judgment is the LLM's; whether the communication is required is a
    deterministic Python gate. When required, the count jump cascades into the
    affected-party SCOPE (the number of individuals owed a communication)."""
    if not ap:
        return ""
    required = ap.get("required")
    scope = ap.get("scope_individuals")
    grew = ap.get("scope_grew_from_amendment")
    old_scope = ap.get("scope_old")
    cls = "ok" if required else "bad"
    decision = ("COMMUNICATION TO DATA SUBJECTS REQUIRED" if required
                else "NO COMMUNICATION REQUIRED")
    parts = ["<h2>5f. Affected-party notification (GDPR Art 34 communication to "
             "data subjects)</h2>",
             "<p class='sub'>The regulator clocks point at a government recipient; "
             "this track points at the affected INDIVIDUALS whose data leaked. It "
             "is a separate obligation, NOT a regulator filing, GATED ON the "
             "regulator release (you tell the regulator, and you separately must "
             "communicate to the people). It attaches only when the breach is "
             "likely to result in a HIGH RISK to the rights and freedoms of natural "
             "persons (GDPR Art 34), a higher bar than the Art 33 regulator "
             "trigger. An LLM applies the Art 34 high-risk standard and returns a "
             "typed verdict; the verdict crosses into the deterministic Warden gate "
             "as data. The judgment is the LLM's; whether the communication is "
             "required is pure Python.</p>"]
    parts.append(
        f"<p class='{cls}'><strong>High-risk assessment: "
        f"{'HIGH RISK' if required else 'NOT high risk'} to data subjects. "
        f"{decision}.</strong></p>")
    rows = [
        ["Standard applied", ap.get("standard")],
        ["Verdict", "HIGH RISK" if required else "NOT high risk"],
        ["Disposition",
         "notify data subjects" if required else "no communication required"],
        ["Gated on regulator release",
         "yes (clock anchors at the release moment)" if required
         else "yes (assessed after release)"],
        ["Decision source (LLM)", ap.get("source")],
    ]
    if not required and ap.get("rule"):
        rows.append(["Rule", ap.get("rule")])
    if required:
        rows.append(["Without-undue-delay clock", ap.get("clock_name")])
        rows.append(["Clock anchored at (regulator release)",
                     ap.get("release_anchor_ts")])
    parts.append(_rows(["Field", "Value"], rows))
    # The SCOPE: the number of individuals owed a communication, and how the
    # amendment cascade grew it. This is the CISO's point made on camera.
    if grew and isinstance(scope, int) and isinstance(old_scope, int):
        parts.append(
            f"<p class='bad'><strong>Affected-party scope grew with the "
            f"amendment: {old_scope:,} -> {scope:,} individuals owed a "
            f"communication.</strong> The forensic revision did not just change a "
            f"regulator filing, it expanded the customer-notification scope by "
            f"{scope - old_scope:,} people.</p>")
    elif isinstance(scope, int):
        parts.append(
            f"<p class='sub'>Affected-party scope: {scope:,} individuals "
            f"{'owed a communication' if required else 'assessed'}.</p>")
    if ap.get("rationale"):
        parts.append("<p class='sub'>Art 34 high-risk rationale:</p>")
        parts.append(f"<pre>{_esc(ap.get('rationale'))}</pre>")
    if required and ap.get("released"):
        parts.append(
            "<p class='ok'>The Art 34 communication passed the SAME two-key release "
            "gate (GC + Lena) as every regulator filing, on its own "
            "without-undue-delay clock anchored at the release moment, then "
            "released. Legal sign-off on customer comms is real.</p>")
    return "".join(parts)


def _render_lead_authority(la: dict | None) -> str:
    """Render the GDPR Art 56 lead-supervisory-authority (one-stop-shop) routing
    (E3.6): the controller's main establishment, the single LEAD authority that
    receives the primary Art 33 notification, and the concerned authorities reached
    THROUGH the lead rather than filed to independently.

    The win this section makes visible: a sophisticated cross-border filer does NOT
    send N independent EU notices. Under GDPR Art 56(1) the authority of the
    controller's main establishment is the single lead; the others are concerned
    authorities (Art 4(22)) coordinated through it (Art 60). The room resolves this
    deterministically from declared data, the same no-LLM routing the Warden does.
    Rendered only when the cross-border beat resolved a routing."""
    if not la:
        return ""
    lead = la.get("lead") or {}
    concerned = la.get("concerned") or []
    parts = ["<h3>GDPR Art 56 one-stop-shop routing (lead + concerned authorities)</h3>"]
    parts.append(
        "<p class='sub'>Cross-border GDPR is not N independent notices to N "
        "authorities. Under <strong>GDPR Article 56(1)</strong> the supervisory "
        "authority of the controller's MAIN ESTABLISHMENT is the single LEAD "
        "authority; the other in-scope member states' authorities are "
        "<em>concerned</em> authorities (Art 4(22)) reached THROUGH the lead under "
        "the Art 60 cooperation procedure. The primary Art 33 notification is filed "
        "to the lead. This is a pure deterministic ROUTING decision (no LLM, no "
        "judgment), resolved from declared data.</p>")
    parts.append(
        f"<p class='sub'>Controller: <strong>{_esc(la.get('controller'))}</strong>; "
        f"main establishment: <code>{_esc(la.get('main_establishment'))}</code> "
        f"({_esc(lead.get('country'))}).</p>")
    if not la.get("cross_border"):
        parts.append(
            f"<p class='ok'>Single EU member state in scope: the "
            f"<strong>{_esc(lead.get('authority'))}</strong> "
            f"({_esc(lead.get('country'))}) receives the Art 33 notification "
            f"directly. No one-stop-shop split (no concerned authorities).</p>")
        return "".join(parts)
    rows = [
        "<tr><td><strong>LEAD</strong></td>"
        "<td><strong>" + _esc(lead.get("authority")) + "</strong></td>"
        "<td>" + _esc(lead.get("country")) + "</td>"
        "<td>primary Art 33 notification (Art 56(1) main-establishment lead)</td></tr>"]
    for a in concerned:
        rows.append(
            "<tr><td>concerned</td>"
            "<td>" + _esc(a.get("authority")) + "</td>"
            "<td>" + _esc(a.get("country")) + "</td>"
            "<td>copied through the lead (Art 4(22) concerned authority, Art 60)</td>"
            "</tr>")
    parts.append(
        "<table><thead><tr><th>Role</th><th>Supervisory authority</th>"
        "<th>Member state</th><th>How it is reached</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>")
    parts.append(
        f"<p class='ok'><strong>One lead, "
        f"{len(concerned)} concerned authorit{'y' if len(concerned) == 1 else 'ies'}: "
        f"the GDPR notification routes through the "
        f"{_esc(lead.get('authority'))}, not as {1 + len(concerned)} independent "
        f"filings.</strong></p>")
    return "".join(parts)


def _render_cross_border(cb: dict) -> str:
    """Render the cross-border obligation-conflict beat (E3.4): the in-scope
    regimes, the mutually exclusive obligations the deterministic detector caught,
    the Warden's BLOCK, and the human two-key decision that resolved it. The defense
    a litigator wants: the conflict was surfaced deterministically, both regulators
    and both opposed obligations are named, and a HUMAN, not the system, chose.

    The win this section makes visible: the contradiction veto did not just catch
    two drafters disagreeing on a FACT, it caught two GOVERNMENTS demanding OPPOSITE
    things, and the Warden refused to let an agent silently pick one regulator over
    another. The detector NEVER decides which law prevails; it detects, halts, and
    routes to the human. Rendered only when the cross-border beat ran."""
    if not cb:
        return ""
    in_scope = ", ".join(cb.get("in_scope_regimes", []))
    conflicts = cb.get("conflicts", [])
    parts = ["<h2>5e. Cross-border obligation conflict "
             "(detected, halted, human-routed)</h2>"]
    parts.append(
        "<p class='sub'>The cross-filing contradiction veto catches two drafters "
        "disagreeing on a FACT. This is the cross-border analogue: two REGULATORS "
        "imposing mutually exclusive OBLIGATIONS on the same true facts. A pure, "
        "no-LLM detector reads each in-scope regime's DECLARED obligation data and "
        "reports any conflicting pair; the Warden HALTS and routes the decision to "
        "the human two-key gate. The Warden NEVER decides which law prevails (that "
        "would be the conflict-of-laws resolver, which is deliberately out of "
        "scope). It detects, halts, and routes.</p>")
    parts.append(
        f"<p class='sub'>Regimes in scope for this incident: "
        f"<code>{_esc(in_scope)}</code>.</p>")
    # GDPR Art 56 one-stop-shop routing (E3.6): the lead supervisory authority and
    # the concerned authorities, rendered whenever the cross-border beat resolved a
    # routing. It is a pure deterministic ROUTING decision, not a judgment.
    parts.append(_render_lead_authority(cb.get("lead_authority")))
    if not conflicts:
        parts.append(
            "<p class='ok'>No cross-border obligation conflict: the in-scope "
            "regimes' declared obligations are compatible.</p>")
        return "".join(parts)
    parts.append(
        "<p class='bad'><strong>Cross-border obligation conflict caught. The "
        "Warden HALTED and routed the decision to the human two-key gate.</strong></p>")
    rows = []
    for c in conflicts:
        kind = ("data-content (a disclosed element another jurisdiction forbids)"
                if c.get("kind") == "data_content"
                else "mandate (two declared-opposite obligations)")
        rows.append(
            "<tr><td>" + _esc(kind) + "</td>"
            "<td><strong>" + _esc(c.get("regime_a")) + "</strong>: "
            + _esc(c.get("obligation_a")) + "</td>"
            "<td><strong>" + _esc(c.get("regime_b")) + "</strong>: "
            + _esc(c.get("obligation_b")) + "</td>"
            "<td>" + _esc(c.get("element") or "(n/a)") + "</td></tr>")
    parts.append(
        "<table><thead><tr><th>Conflict kind</th><th>Regulator A obligation</th>"
        "<th>Regulator B obligation</th><th>Data element</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>")
    # The cited statutory bases for the first conflict (the defensibility record).
    c0 = conflicts[0]
    if c0.get("basis_a") or c0.get("basis_b"):
        parts.append(
            f"<p class='sub'>Statutory basis: <strong>{_esc(c0.get('regime_a'))}</strong> "
            f"{_esc(c0.get('basis_a'))}; <strong>{_esc(c0.get('regime_b'))}</strong> "
            f"{_esc(c0.get('basis_b'))}.</p>")
    # The human two-key resolution: who decided, and the recorded direction.
    res = cb.get("resolution") or {}
    if res:
        decided_by = ", ".join(res.get("decided_by", []))
        parts.append(
            "<h3>Human two-key resolution (the Warden did not choose)</h3>")
        parts.append(
            f"<p class='ok'><strong>Resolved by two distinct human keys: "
            f"<code>{_esc(decided_by)}</code>.</strong> The conflict was routed to "
            f"the human two-key gate; the humans, not the system, made the call. "
            f"This recorded decision is the only thing that let the run proceed.</p>")
        parts.append(f"<p class='sub'>Recorded human decision: "
                     f"{_esc(res.get('decision'))}</p>")
    return "".join(parts)


def _render_determination(d: dict) -> str:
    """Render the reasonable-basis determination record (E3.2): the named legal
    standard, the factor table where each factor is bound to the exact canonical
    fact-record FIELD it rests on, the disposition, and the reasonable-basis
    validation (every cited field exists). This is the artifact a litigator
    subpoenas: a documented, signed, replayable reasonable basis, not "an AI said
    no". The factor->fact binding and the record are deterministic Python; the
    validator gates nothing."""
    if not d or not d.get("factors"):
        return ""
    standard = d.get("standard", "")
    disposition = (d.get("disposition") or "").upper()
    basis = d.get("reasonable_basis") or {}
    complete = basis.get("complete", True)
    basis_cls = "ok" if complete else "bad"
    basis_line = (
        "Reasonable basis COMPLETE: every weighed factor is bound to a field the "
        "canonical fact-record carries." if complete else
        "Reasonable basis INCOMPLETE: a weighed factor cites a field not present "
        "in the fact-record (flagged below).")
    parts = [
        "<h3>Reasonable-basis determination record</h3>",
        f"<p class='sub'>Standard applied: <strong>{_esc(standard)}</strong></p>",
        f"<p class='sub'>Disposition: <strong>{_esc(disposition)}</strong> "
        f"(carried verbatim from the verdict the deterministic gate consumed; the "
        f"record documents the basis, it does not re-decide). Decision source: "
        f"<code>{_esc(d.get('source'))}</code>.</p>",
        f"<p class='{basis_cls}'><strong>{_esc(basis_line)}</strong></p>",
    ]
    rows = []
    for f in d["factors"]:
        kind = "qualitative" if f.get("qualitative") else "quantitative"
        rows.append(
            "<tr><td>" + _esc(f.get("name")) + "</td>"
            "<td>" + _esc(kind) + "</td>"
            "<td>" + _esc(f.get("value")) + "</td>"
            "<td><code>" + _esc(f.get("fact_field")) + "</code></td></tr>")
    parts.append(
        "<table><thead><tr><th>Factor weighed by the standard</th><th>Kind</th>"
        "<th>Value</th><th>Bound to fact-record field</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>")
    missing = basis.get("missing_factors") or []
    if missing:
        items = "".join(
            f"<li>{_esc(m.get('factor'))} cites missing field "
            f"<code>{_esc(m.get('fact_field'))}</code></li>" for m in missing)
        parts.append(f"<p class='bad'>Factors citing a nonexistent fact-record "
                     f"field:</p><ul>{items}</ul>")
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
    parts.append(_render_determination(m.get("determination", {})))
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


def _render_rag_grounding(r: dict) -> str:
    """Render the RAG-grounding section (E5.9): per filing, the REAL regulation
    passages a pure deterministic retriever fetched to ground the drafting, and which
    of them the drafter actually cited with a [cite: <id>] tag.

    This is a derive-at-render-time receipt over the OUT-OF-LOG retrieval trace, the
    same posture as the grounding receipt. The retriever is pure and deterministic
    (hand-rolled BM25 over the committed corpus index); nothing it produced reached a
    gate, a clock, the diff, or the hashed run-log, so byte-identical replay is
    untouched. It makes visible that each filing was drafted against the real
    statutory text, not the model's memory of it, and that an examiner can trace a
    cited sentence to the clause id."""
    if not r or not r.get("retrievals"):
        return ""
    retriever = r.get("retriever", "bm25")
    retrieved = r.get("passages_retrieved", 0)
    cited = r.get("passages_cited", 0)
    parts = [
        "<h2>7e. Regulation passages that grounded each filing (RAG)</h2>",
        "<p class='sub'>Before drafting, a pure deterministic retriever "
        f"(<code>{_esc(retriever)}</code> over the committed regulation corpus) "
        "fetched the real statutory passages that ground each regime, and the "
        "drafter wrote against them and cited them inline with [cite: id] tags. The "
        "retriever is a pure function of (corpus, regime, fact-record): no network, "
        "no clock, no randomness. It feeds only the drafting prompt and this "
        "receipt, never a gate or the hashed run-log, so replay stays "
        "byte-identical.</p>",
        f"<p class='ok'><strong>Retrieved {_esc(retrieved)} passage(s) across "
        f"{_esc(len(r['retrievals']))} filing(s); the drafters cited "
        f"{_esc(cited)} of them.</strong></p>",
    ]
    for rec in r["retrievals"]:
        regime = rec.get("regime") or rec.get("branch")
        parts.append(f"<h3>{_esc(regime)} filing</h3>")
        rows = []
        for p in rec.get("passages", []):
            was_cited = p.get("cited")
            badge_cls = "ok" if was_cited else "na"
            badge = "CITED" if was_cited else "retrieved"
            rows.append(
                "<tr><td><code>" + _esc(p.get("id")) + "</code></td>"
                "<td>" + _esc(p.get("citation")) + "</td>"
                "<td>" + _esc(p.get("title")) + "</td>"
                "<td>" + _esc(f"{p.get('score', 0.0):.3f}") + "</td>"
                f"<td class='{badge_cls}'>" + badge + "</td></tr>")
        parts.append(
            "<table><thead><tr><th>Citation id</th><th>Citation</th>"
            "<th>Title</th><th>BM25 score</th><th>Drafter</th></tr></thead>"
            "<tbody>" + "".join(rows) + "</tbody></table>")
    return "".join(parts)


def _render_calibration(c: dict) -> str:
    """Render the per-claim confidence + calibration receipt (E5.5): per filing,
    each load-bearing claim the drafter self-reported a CONFIDENCE on (low / medium
    / high), placed NEXT TO the deterministic grounding scorer's grounded /
    ungrounded verdict for the same claim, with a calibration status. A HIGH-
    confidence claim the scorer flagged as UNGROUNDED is a loud calibration MISS
    (the drafter was sure of a fact the scorer could not trace to the record); a
    LOW-confidence claim the scorer found grounded is UNDER-CONFIDENT.

    This is a printed receipt only. The confidence is the drafter's self-report
    (model output), the verdict is the deterministic grounding scorer's, and the
    pairing is pure Python: zero LLM, no now(). It never gates a filing, moves a
    transition, or conditions a release; a MISS surfaces an over-confident
    unsupported claim loudly for a human. It is rendered ONLY when a calibration
    block is present (a drafter emitted a confidence self-report), so the sealed
    captures, which carry no calibration block, render unchanged."""
    if not c or not c.get("filings"):
        return ""
    any_miss = c.get("any_miss", False)
    top_cls = "bad" if any_miss else "ok"
    headline = (
        "Calibration MISS: a drafter self-reported HIGH confidence on a claim the "
        "grounding scorer flagged as ungrounded. Surfaced loudly below for human "
        "review (no filing was blocked)."
        if any_miss else
        "Calibration clean: every high-confidence claim traces to the fact-record. "
        "No drafter was over-confident on an unsupported claim.")
    parts = [
        "<h2>7e. Per-claim confidence calibration (self-report vs the grounding "
        "scorer)</h2>",
        f"<p class='{top_cls}'><strong>{_esc(headline)}</strong></p>",
        "<p class='sub'>Each drafter self-reports a CONFIDENCE (low / medium / high) "
        "on each load-bearing fact it asserted. A pure deterministic step CALIBRATES "
        "that self-report against the grounding scorer above: the self-reported "
        "level sits next to the scorer's grounded / ungrounded verdict for the same "
        "claim. A HIGH-confidence claim the scorer flagged as UNGROUNDED is a loud "
        "calibration MISS; a LOW-confidence claim the scorer found grounded is "
        "UNDER-CONFIDENT. The confidence is the model's self-report; the verdict is "
        "the deterministic scorer's; the pairing is pure Python (no LLM, no clock) "
        "and is out-of-log, so the sealed run-log shas and byte-identical replay are "
        "unaffected. It is a receipt, never a gate.</p>",
    ]
    rows = []
    for f in c.get("filings", []):
        filing_label = _esc(f.get("regime") or f.get("branch") or "")
        pairs = f.get("pairs", [])
        if not pairs:
            rows.append(
                "<tr><td>" + filing_label + "</td>"
                "<td colspan='4'><span class='sub'>no self-reported claim the "
                "scorer also evaluated</span></td></tr>")
            continue
        for p in pairs:
            status = p.get("status", "")
            if status == "miss":
                badge = "<span class='cstat cstat-bad'>MISS</span>"
            elif status == "under_confident":
                badge = "<span class='cstat cstat-na'>UNDER-CONFIDENT</span>"
            else:
                badge = "<span class='cstat cstat-ok'>HIT</span>"
            verdict = "grounded" if p.get("grounded") else "UNGROUNDED"
            rows.append(
                "<tr><td>" + filing_label + "</td>"
                "<td><code>" + _esc(p.get("field")) + "</code></td>"
                "<td>" + _esc(str(p.get("level", "")).upper()) + "</td>"
                "<td class='" + ("ok" if p.get("grounded") else "bad") + "'>"
                + _esc(verdict) + "</td>"
                "<td>" + badge + "</td></tr>")
    parts.append(
        "<table><thead><tr><th>Filing</th><th>Claim (field)</th>"
        "<th>Self-reported confidence</th><th>Grounding scorer verdict</th>"
        "<th>Calibration</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>")
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
    missed_total = ar.get("missed_defects", 0)
    any_red = ar.get("any_red", False)
    parts = ["<h2>7d. Adversarial review (Challenger, deterministically "
             "adjudicated)</h2>",
             "<p class='sub'>Before the Warden gates each filing, an independent "
             "Challenger agent (a different open model from the drafters) "
             "critiques it and posts a structured challenge into the room; the "
             "drafter then revises or rebuts. Each objection is then cross-checked "
             "by the EXISTING deterministic grounding oracle: the LLM critiques, "
             "Python adjudicates which critiques are real. The Challenger is itself "
             "an LLM and is gameable, so the adjudicator ALSO sweeps the oracle's "
             "own flagged spans directly: a provable hallucination the Challenger "
             "did not object to (silenced by a prompt-injection, a malformed "
             "challenge block, or an out-of-field target) is a MISSED defect and "
             "the review goes RED. The Challenger never gates; the Warden consumes "
             "only the unchanged typed claims.</p>",
             f"<p class='ok'><strong>Adversarial review: {_esc(raised)} "
             f"objection(s) raised, {_esc(confirmed)} confirmed by the "
             f"deterministic grounding oracle, {_esc(overturned)} overturned.</strong></p>"]
    if any_red:
        parts.append(
            f"<p class='bad'><strong>RED: the Challenger missed "
            f"{_esc(missed_total)} deterministically-provable hallucination(s)</strong> "
            "that the grounding oracle independently flagged. A missed provable "
            "defect is treated as a RED outcome: an LLM Challenger cannot be "
            "trusted to mark its own homework, so the oracle's direct sweep is the "
            "backstop.</p>")
    else:
        parts.append(
            "<p class='ok'>No missed defects: every span the grounding oracle "
            "independently flagged was covered by a confirmed Challenger "
            "objection.</p>")
    for rev in ar["reviews"]:
        regime = rev.get("regime") or rev.get("branch")
        disp = rev.get("disposition", "")
        src = rev.get("source", "")
        parts.append(
            f"<h3>{_esc(regime)} filing, challenged by <code>{_esc(src)}</code> "
            f"-&gt; drafter {_esc(disp)}</h3>")
        missed_defects = rev.get("missed_defects", [])
        if missed_defects:
            rows = []
            for d in missed_defects:
                rows.append(
                    "<tr><td>" + _esc(d.get("kind")) + "</td>"
                    "<td>" + _esc(d.get("span")) + "</td>"
                    "<td>" + _esc(d.get("reason")) + "</td></tr>")
            parts.append(
                "<p class='bad'><strong>Challenger missed a "
                "deterministically-provable hallucination.</strong> The grounding "
                "oracle flagged the span(s) below; the Challenger raised no "
                "confirmed objection covering them.</p>"
                "<table><thead><tr><th>Kind</th><th>Ungrounded span</th>"
                "<th>Oracle reason</th></tr></thead><tbody>"
                + "".join(rows) + "</tbody></table>")
        objs = rev.get("objections", [])
        if not objs:
            if not missed_defects:
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


def _render_routing(gw: dict) -> str:
    """Render the E5.7 multi-model gateway receipt: the tiered-routing ledger (per
    filing complexity tier + RELATIVE-cost estimate), the cross-family failover
    record (which model served each filing and which it fell back from), and the
    advisory vision triage (validated and grounding-scored).

    Every number here is derived OUT-OF-LOG from the drafting trace; it is
    render-only and never enters the hashed run-log, so the run-log sha and
    byte-identical replay are untouched. Empty unless a gateway feature was
    exercised, so the default packet is unchanged. The cost figures are RELATIVE
    weights (unitless), never a currency amount, so this is a relative-cost
    estimate, never a fabricated invoice."""
    if not gw:
        return ""
    parts = ["<h2>8e. Multi-model gateway (routing, failover, vision triage)</h2>"]

    failover = gw.get("failover", {})
    if failover.get("rows"):
        any_fo = failover.get("any_failed_over", False)
        cls = "bad" if any_fo else "ok"
        msg = ("A primary model was down: the filing FAILED OVER to the next "
               "model in its cross-family chain and served from there."
               if any_fo else
               "Every filing was served by its primary model; the failover chain "
               "was ready but not needed.")
        parts.append(f"<p class='{cls}'><strong>{msg}</strong></p>")
        rows = []
        for r in failover["rows"]:
            fell = r.get("fell_back_from", [])
            fell_txt = (", ".join(f"{f['provider']}:{f['model']}" for f in fell)
                        if fell else "(none, primary served)")
            rows.append([
                r.get("regime") or r.get("branch"),
                f"{r.get('served_by_provider')}:{r.get('served_by_model')}",
                fell_txt,
                "yes" if r.get("did_fail_over") else "no",
            ])
        parts.append("<p class='sub'>Cross-family failover: the model that served "
                     "each filing and the models it fell back from. The served_by / "
                     "fell_back_from record is OUT-OF-LOG, never in the hashed "
                     "[CLAIMS], so replay stays byte-identical.</p>")
        parts.append(_rows(
            ["Filing", "Served by", "Fell back from", "Failed over"], rows))

    routing = gw.get("routing", {})
    if routing.get("rows"):
        rows = []
        for r in routing["rows"]:
            rows.append([
                r.get("regime") or r.get("branch"),
                r.get("complexity"),
                r.get("tier"),
                f"{r.get('provider')}:{r.get('model')}",
                f"{r.get('cost_weight')}x",
                r.get("score"),
            ])
        parts.append("<p class='sub'>Deterministic complexity routing: each filing "
                     "is scored from declared signals (regime weight, regulator "
                     "factor count, record magnitude, grounding) and banded into a "
                     "cost tier. The decision is OUT-OF-LOG and gates nothing.</p>")
        parts.append(_rows(
            ["Filing", "Complexity", "Tier", "Model", "Relative cost", "Score"],
            rows))
        ledger = routing.get("cost_ledger", {})
        if ledger:
            saving = ledger.get("relative_saving_fraction", 0.0)
            parts.append(
                "<p class='sub'>Relative-cost estimate (unitless weights, NOT a "
                "currency amount, never an invoice): routing this run cost "
                f"<code>{_esc(ledger.get('relative_cost_total'))}</code> relative "
                "weight versus "
                f"<code>{_esc(ledger.get('all_premium_relative_cost'))}</code> had "
                "every filing gone premium, a relative saving of "
                f"<strong>{_esc(round(saving * 100, 1))}%</strong>.</p>")

    vision = gw.get("vision", {})
    triages = vision.get("triages", [])
    if triages:
        parts.append("<h3>Advisory vision triage (breach screenshot)</h3>")
        for t in triages:
            cleared = t.get("cleared", False)
            cls = "ok" if cleared else "bad"
            badge = "CLEARED" if cleared else "HELD FOR REVIEW"
            src = t.get("source", "")
            parts.append(
                f"<p class='{cls}'><strong>{badge}</strong> "
                f"(source: {_esc(src)}, model: {_esc(t.get('model'))}). "
                "Vision output is ADVISORY: it gates nothing, never enters the "
                "canonical fact-record or the [CLAIMS] block, and must clear the "
                "deterministic validator AND the grounding scorer before it is "
                "shown.</p>")
            parts.append(f"<p class='sub'>{_esc(t.get('advisory_prose'))}</p>")
            fields = t.get("fields", {})
            if fields:
                frows = [[k, v] for k, v in fields.items()]
                parts.append(_rows(["Extracted field (advisory)", "Value"], frows))
            rejected = t.get("rejected_lines", [])
            if rejected:
                parts.append(
                    "<p class='sub'>Validator REJECTED (out-of-schema or bad type, "
                    "dropped before it could be surfaced as a fact): "
                    + "; ".join(f"<code>{_esc(x)}</code>" for x in rejected)
                    + "</p>")
            g = t.get("grounding", {})
            spans = g.get("ungrounded", [])
            if spans:
                parts.append(
                    "<p class='bad'>Grounding scorer flagged an extracted value as "
                    "UNGROUNDED against the fact-record (this is why it was held): "
                    + "; ".join(
                        f"{_esc(s.get('kind'))}: <code>{_esc(s.get('span'))}</code>"
                        for s in spans)
                    + ".</p>")
    return "".join(parts)


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


def _render_edgar_export(ex: dict) -> str:
    """Render the EDGAR-shaped Form 8-K Item 1.05 + Inline-XBRL export sidecar.

    The SEC filing is shown in its real machine-readable form: the EDGAR Form 8-K
    cover-page header (registrant, jurisdiction, commission file number, the date
    of the earliest event reported), the Item 1.05 heading and its four mandated
    content elements, and the Inline-XBRL fragment that tags the Item 1.05 facts
    with the real SEC Cybersecurity Disclosure (CYD) taxonomy concepts. The whole
    export is a pure DERIVED transform of the packet (the canonical fact-record +
    the SEC claims + the SEC clock); no LLM, no now(), never in the hashed run-log,
    so byte-identical replay and every sealed sha are untouched. Honest: this is an
    EDGAR-shaped export of the real fields, not a filed submission, so no accession
    number is invented. Rendered only when the SEC branch produced a filing."""
    if not ex or not ex.get("edgar_8k"):
        return ""
    edgar = ex["edgar_8k"]
    ixbrl = ex.get("ixbrl", "")
    parts = ["<h2>8g. EDGAR-shaped Form 8-K Item 1.05 + Inline-XBRL export</h2>",
             "<p class='sub'>An examiner's intake system does not read the HTML "
             "packet: it ingests a STRUCTURED submission. This is the SEC filing in "
             "its real machine-readable form: a Form 8-K Item 1.05 with the real "
             "EDGAR cover-page header and the four mandated content elements (the "
             "material aspects of the nature, the scope, and the timing of the "
             "incident, and the material impact or reasonably likely material "
             "impact), plus an Inline-XBRL fragment that tags the Item 1.05 facts "
             "with the SEC's own Cybersecurity Disclosure (CYD) taxonomy concepts. "
             "It is a pure deterministic export of the typed facts (no LLM); the "
             "prose is the drafter's, the structure and the tags are deterministic. "
             "This is an EDGAR-SHAPED export of the real fields and the real CYD "
             "concept names, NOT a filed EDGAR submission, so no accession number "
             "is assigned.</p>"]
    # The EDGAR cover-page header, in form order.
    cover = edgar.get("cover", {})
    cover_rows = [[label, cover.get(label, "")]
                  for label in edgar.get("cover_field_order", [])
                  if label in cover]
    # The Item 1.05 heading is a cover-order entry without a value; render the
    # remaining filer fields (CIK) that are not in the ordered cover list too.
    for label, value in cover.items():
        if label not in edgar.get("cover_field_order", []):
            cover_rows.append([label, value])
    parts.append("<h3>EDGAR Form 8-K cover-page header</h3>")
    parts.append(_rows(["Cover field", "Value"], cover_rows))
    parts.append(
        f"<p class='sub'>Form type <code>{_esc(edgar.get('form_type'))}</code>, "
        f"Item <code>{_esc(edgar.get('item'))}</code> "
        f"({_esc(edgar.get('item_heading'))}). Period of report (date of earliest "
        f"event reported): <code>{_esc(edgar.get('period_of_report'))}</code>, the "
        f"SEC materiality-determination date the four-business-day clock anchors "
        f"at.</p>")
    # The four mandated Item 1.05 content elements.
    parts.append("<h3>Item 1.05 mandated content elements</h3>")
    for e in edgar.get("content_elements", []):
        body = e.get("body", "") or (
            "(the structured facts below; no narrative was drafted for this "
            "element)")
        parts.append(f"<p class='sub'><strong>{_esc(e.get('label'))}</strong> "
                     f"<em>({_esc(e.get('instruction'))})</em></p>")
        parts.append(f"<pre>{_esc(body)}</pre>")
    # The typed facts that drive the tagging.
    facts = edgar.get("facts", {})
    parts.append("<h3>Tagged facts (from the SEC claims and the statutory clock)</h3>")
    parts.append(_rows(
        ["Fact", "Value"],
        [["records_affected", facts.get("records_affected")],
         ["incident_start_utc", facts.get("incident_start_utc")],
         ["attacker", facts.get("attacker")],
         ["containment", facts.get("containment")],
         ["materiality_determination_utc",
          facts.get("materiality_determination_utc")],
         ["statutory_deadline_utc", facts.get("statutory_deadline_utc")]]))
    # The Inline-XBRL fragment, tagging the Item 1.05 facts with the CYD concepts.
    if ixbrl:
        parts.append("<h3>Inline-XBRL fragment (SEC CYD taxonomy)</h3>")
        parts.append(
            "<p class='sub'>The Item 1.05 facts tagged with the SEC Cybersecurity "
            "Disclosure (CYD) taxonomy under "
            "<code>http://xbrl.sec.gov/cyd/2024</code>: the material-cybersecurity-"
            "incident text block, the nature/scope/timing text block, and the "
            "material-impact text block, each dimensioned by the "
            "<code>MaterialCybersecurityIncidentAxis</code> with a custom member "
            "identifying this incident (more than one incident can be reported on a "
            "single 8-K). The fragment is well-formed XML and tags the real CYD "
            "concept names.</p>")
        parts.append(f"<pre>{_esc(ixbrl)}</pre>")
    if edgar.get("export_note"):
        parts.append(f"<p class='sub'><em>{_esc(edgar.get('export_note'))}</em></p>")
    return "".join(parts)


def _render_ecosystem_exports(ex: dict) -> str:
    """Render the ecosystem-exports reference (STIX 2.1 / OSCAL / MISP) (E4.7).

    The incident plugs into the security and compliance ecosystem through three
    named-standard exports, each a pure DERIVED transform of the packet (no LLM, no
    now(), no uuid4(), never in the hashed run-log, so byte-identical replay and
    every sealed sha are untouched):

      - a valid OASIS STIX 2.1 bundle (the incident as the threat-intel ecosystem's
        native object: the attacker as threat-actor + malware, the victim as an
        identity, the incident SDO with the core incident extension, and a
        course-of-action per confirmed control finding);
      - a NIST OSCAL assessment-results document (the E4.4 control-evidence register
        as the named GRC standard: each control a finding with its named-framework
        references, each evidenced control an observation linked to the run-log);
      - a MISP-core-format event (the CERT/ISAC sharing object, riding on the same
        STIX mapping).

    This renders a compact REFERENCE (the per-standard object counts and the honest
    coverage note), with the full documents available as the JSON sidecar's
    ecosystem_exports block and the standard-native validators
    (scripts/stix_export.py, scripts/oscal_export.py, scripts/misp_export.py). The
    validators are the receipt; this section names what was emitted."""
    if not ex:
        return ""
    rows: list[list] = []
    stix = ex.get("stix")
    if stix:
        objs = stix.get("objects", [])
        by_type: dict[str, int] = {}
        for o in objs:
            by_type[o.get("type")] = by_type.get(o.get("type"), 0) + 1
        sdo_summary = ", ".join(
            f"{by_type[t]} {t}" for t in (
                "threat-actor", "malware", "identity", "incident",
                "observed-data", "course-of-action", "relationship")
            if by_type.get(t))
        rows.append([
            "STIX 2.1 bundle (OASIS)",
            f"{len(objs)} objects: {sdo_summary}",
            "BUILT: a valid STIX 2.1 bundle a TIP (MISP, OpenCTI, Sentinel, "
            "Splunk ES) ingests; not pushed over a live TAXII server (STUB)."])
    oscal = ex.get("oscal")
    if oscal:
        ar = oscal.get("assessment-results", {})
        result = (ar.get("results") or [{}])[0]
        rows.append([
            "OSCAL assessment-results (NIST)",
            f"{len(result.get('findings', []))} findings, "
            f"{len(result.get('observations', []))} observations "
            f"(OSCAL {ar.get('metadata', {}).get('oscal-version', '')})",
            "BUILT: the E4.4 control register as a NIST OSCAL assessment-results "
            "document; assessment-results only, not a full SSP + plan + POA&M "
            "suite (STUB)."])
    misp = ex.get("misp")
    if misp:
        event = misp.get("Event", {})
        rows.append([
            "MISP event (core format)",
            f"{len(event.get('Attribute', []))} attributes, "
            f"{len(event.get('Galaxy', []))} galaxies, "
            f"{len(event.get('Tag', []))} tags",
            "BUILT: a well-formed MISP-core-format event for CERT/ISAC sharing; "
            "not pushed to a live MISP instance (STUB). MISP also imports the "
            "STIX bundle directly."])
    if not rows:
        return ""
    parts = [
        "<h2>8h. Ecosystem exports (STIX 2.1 / OSCAL / MISP)</h2>",
        "<p class='sub'>The incident also speaks the native languages of the "
        "security and compliance ecosystem, so it drops into a SIEM/SOAR, a GRC "
        "tool, and a threat-intel platform without re-keying. Each export below is "
        "a pure deterministic transform of the data this packet already carries "
        "(the canonical fact-record, the contradiction diff, and the "
        "control-evidence register), with stable UUIDv5 ids and fact-record "
        "timestamps (no LLM, no now(), no random ids), so it never enters the "
        "hashed run-log and byte-identical replay is untouched. The full documents "
        "are in the JSON sidecar (<code>ecosystem_exports</code>); the "
        "standard-native validators (<code>scripts/stix_export.py</code>, "
        "<code>scripts/oscal_export.py</code>, <code>scripts/misp_export.py</code>) "
        "are the receipt.</p>",
        _rows(["Standard", "Emitted", "Coverage (honest scope)"], rows),
    ]
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
        local = c.get("deadline_local", "")
        local_html = (f'<div class="jlocal">local: {_esc(local)}</div>'
                      if local else "")
        chips.append(
            f'<div class="jchip {cls}">'
            f'<div class="jname">{_esc(c.get("name", ""))}</div>'
            f'{trigger_html}'
            f'<div class="jdeadline">deadline {_esc(c.get("deadline", ""))}</div>'
            f'{local_html}'
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


def _render_privilege(pr: dict) -> str:
    """Render the privilege / work-product designation (E4.10): the war-room record
    split into a DISCLOSABLE set (the filings + the statutory-required content) and
    a PRIVILEGED set (the internal legal deliberation: the materiality /
    reportability rationale, the determination memos, the reconciliation, the
    Challenger critique, the legal-hold counsel direction), each item tagged with
    its privilege basis (privileged legal advice / attorney work-product).

    This is the latent malpractice trap a lawyer thinks of and an engineer does
    not: after Capital One / Clark Hill / Rutter's, courts pierce privilege when the
    incident record looks like ordinary business work. The split lets counsel hand a
    regulator the disclosable set WITHOUT waiving privilege over the deliberation. It
    is a PURE DERIVED classification keyed entirely by the run-log EVENT TYPE
    (floor/privilege.py), never an LLM judging privilege: zero LLM, no now(); it
    never enters the hashed run-log and gates nothing. The renderer never leaks the
    privileged set into the disclosable set."""
    if not pr or not pr.get("all_items"):
        return ""
    disclosable = pr.get("disclosable", [])
    privileged = pr.get("privileged", [])
    parts = [
        "<h2>14. Privilege / work-product designation (the disclosable vs. "
        "privileged split)</h2>",
        f"<p class='sub'><strong>{_esc(pr.get('verdict', ''))}</strong></p>",
        "<p class='sub'>A breach war-room record is a litigation goldmine for "
        "plaintiffs unless it is structured to support attorney-client privilege and "
        "attorney work-product protection. After Capital One, Clark Hill, and "
        "Rutter's, courts pierce privilege when the incident record looks like "
        "ordinary business / IR work rather than counsel-directed legal analysis. "
        "Each artifact this run produced is classified by its event type into a "
        "DISCLOSABLE set (the filings and the statutory-required content, produced to "
        "a regulator) and a PRIVILEGED set (the internal legal deliberation, "
        "withheld). The classification is a pure derived lookup on the event type, "
        "never an LLM judging privilege; it never enters the hashed run-log and "
        "gates nothing.</p>",
    ]
    # The disclosable set: what counsel hands a regulator.
    parts.append("<h3>Disclosable set (produced to the regulator)</h3>")
    if disclosable:
        parts.append(_rows(
            ["Artifact", "Privilege basis", "Records"],
            [[i.get("description"), i.get("basis_label"), i.get("count")]
             for i in disclosable]))
    else:
        parts.append("<p class='sub'>No disclosable artifact in this run.</p>")
    # The privileged set: what counsel withholds, under the work-product banner.
    parts.append("<h3>Privileged set (withheld: legal advice and attorney "
                 "work-product)</h3>")
    if privileged:
        parts.append(
            f"<p class='bad'><strong>{_esc(pr.get('banner', ''))}</strong></p>")
        parts.append(_rows(
            ["Artifact", "Privilege basis", "Records"],
            [[i.get("description"), i.get("basis_label"), i.get("count")]
             for i in privileged]))
    else:
        parts.append("<p class='sub'>No privileged artifact in this run.</p>")
    return "".join(parts)


def _render_timeline(t: dict) -> str:
    """Render the unified incident timeline (E4.10): the single chronological
    incident timeline reconstructed from the sealed run (every clock start, draft,
    gate, veto, release, recruit, with its UTC timestamp + actor), the first
    artifact the board and the examiner ask for.

    It is a PURE DERIVED reconstruction over the assembled packet's events
    (floor/timeline.py), ordered deterministically. Because every row comes from the
    same events the run-log sha and the per-entry hash chain cover, the timeline is
    tamper-evident: each entry is tied to the run's chain head, so re-ordering or
    dropping a log entry re-orders or breaks the timeline and moves the head. Zero
    LLM, no now(); it never enters the hashed run-log and gates nothing."""
    if not t or not t.get("entries"):
        return ""
    chain_head = t.get("chain_head", "")
    parts = [
        "<h2>15. Unified incident timeline (reconstructed from the sealed log)</h2>",
        "<p class='sub'>The first artifact a board or an examiner asks for is a "
        "single authoritative timeline: when did we detect, when did each statutory "
        "clock start, when did each draft post, when did the diff gate, when was a "
        "contradiction vetoed, when did the fact change, when did each filing "
        "release. This is that timeline, reconstructed purely from the sealed run's "
        "events and ordered chronologically. It is derived read-only from the same "
        "events the run-log sha and the per-entry hash chain cover, so it is itself "
        "tamper-evident: re-ordering or dropping a log entry re-orders or breaks this "
        "timeline and moves the chain head.</p>",
    ]
    if chain_head:
        parts.append(
            f"<p class='sub'>Sealed at the per-entry hash chain head "
            f"<span class='hash'>{_esc(chain_head)}</span>.</p>")
    rows = []
    for e in t.get("entries", []):
        actor = e.get("actor") or "(system)"
        note = e.get("deadline_note") or ""
        rows.append([e.get("ts"), actor, e.get("description"),
                     e.get("branch") or "(global)", note])
    parts.append(_rows(
        ["UTC timestamp", "Actor", "Event", "Branch", "Deadline context"], rows))
    return "".join(parts)


def _render_after_action(a: dict) -> str:
    """Render the after-action artifact (E4.10): a structured post-incident summary
    derived from the run (the response-time margin per clock, where the facts
    changed, what the Challenger caught, the controls that operated, any breaches),
    the stub a NIS2 / DORA final report or an internal lessons-learned starts from.

    It is a PURE DERIVED assembly over the same sealed run (floor/timeline.py); no
    LLM 'lessons' prose is generated, the Warden stays deterministic. Zero LLM, no
    now(); it never enters the hashed run-log and gates nothing."""
    if not a or not a.get("clock_margins"):
        return ""
    filed = a.get("deadlines_filed", 0)
    met = a.get("deadlines_met", 0)
    breached = a.get("deadlines_breached", 0)
    top_cls = "ok" if breached == 0 and filed else "bad"
    parts = [
        "<h2>16. After-action review (post-incident summary)</h2>",
        f"<p class='{top_cls}'><strong>{met} of {filed} filed statutory deadline(s) "
        f"met"
        + (f"; {breached} breached." if breached else "; no breaches.")
        + "</strong></p>",
        "<p class='sub'>Every regulated incident triggers a formal post-incident "
        "review (the NIS2 final report at one month, the DORA final report, the "
        "internal lessons-learned). This is the auto-assembled stub: the "
        "response-time margin per statutory clock, where the facts changed, what the "
        "adversarial Challenger caught, and the controls that operated, derived "
        "purely from the sealed run. No LLM lessons prose is generated here; it is a "
        "pure read over the run's own evidence.</p>",
    ]
    # The per-clock response-time margins.
    rows = []
    for m in a.get("clock_margins", []):
        if m.get("filed"):
            status = "MET" if m.get("met") else "BREACHED"
        else:
            status = "running"
        rows.append([m.get("clock"), m.get("deadline"),
                     m.get("filed_at") or "(running)",
                     m.get("margin_human"), status])
    parts.append("<p class='sub'>Response-time margin per statutory clock "
                 "(deadline minus filed-at):</p>")
    parts.append(_rows(
        ["Clock", "Statutory deadline", "Filed (UTC)", "Margin", "Status"], rows))
    # The narrative findings.
    findings = a.get("findings", [])
    if findings:
        parts.append("<p class='sub'>Findings:</p>")
        parts.append("<ul>" + "".join(
            f"<li>{_esc(f)}</li>" for f in findings) + "</ul>")
    # Where the facts changed.
    fc = a.get("fact_change")
    if fc:
        parts.append(
            f"<p class='sub'>Facts changed mid-incident: "
            f"<code>{_esc(fc.get('fact_key'))}</code> revised from "
            f"<code>{_esc(fc.get('old_value'))}</code> to "
            f"<code>{_esc(fc.get('new_value'))}</code>; "
            f"{len(fc.get('reopened_branches', []))} branch(es) reopened and "
            f"reconciled before re-filing.</p>")
    return "".join(parts)


def _render_policy_version(pv: dict) -> str:
    """Render the render-time policy / config version stamp (E4.10): which policy
    version governed this run.

    The stamp is a composite sha over the governing catalogs (regimes.yaml,
    controls.yaml) and the Warden rule set (the transition-authority table). It is
    derived at packet RENDER time and is deliberately NOT folded into the hashed
    run-log, so the sealed run-log sha and byte-identical replay are untouched. A
    reader knows which policy version produced this run; an edit to any policy
    component moves the composite sha."""
    if not pv or not pv.get("policy_version"):
        return ""
    composite = pv.get("policy_version", "")
    parts = [
        "<h2>17. Governing policy version (render-time stamp)</h2>",
        "<p class='sub'>Regulation in this system is configuration: the statutory "
        "clocks and mandated fields (regimes.yaml), the control mapping "
        "(controls.yaml), and the Warden rule set (the transition-authority table) "
        "are declarative. So a reader knows which policy version governed THIS run, "
        "the packet stamps a composite version sha over the exact governing policy "
        "bytes. The stamp is derived at RENDER time and is deliberately NOT folded "
        "into the hashed run-log: the run-log seals the run that occurred, the policy "
        "version is metadata about the policy that governed it, so the sealed "
        "run-log sha and byte-identical replay are untouched. An edit to any policy "
        "component moves this composite sha.</p>",
        f"<p class='sub'>Governing policy version: "
        f"<span class='hash'>{_esc(composite)}</span></p>",
    ]
    rows = [[c.get("name"), c.get("sha256")] for c in pv.get("components", [])]
    parts.append(_rows(["Policy component", "Component sha256"], rows))
    return "".join(parts)


def _render_regime_expert(re: dict) -> str:
    """Render the per-regime expert reasoning (E5.6): for each filing, the
    statutory standard its drafter was held to, the named factors it weighed, and
    the regime-specific RATIONALE block the drafter emitted explaining why the
    filing meets that standard.

    This is the visible payoff of the regime-expert drafters: each drafter is not a
    generic slot-filler but a domain expert in its own regulation, and this section
    shows its reasoning in regime-specific terms. It is a PURE additive render over
    the assembled packet; the rationale is explanatory prose the model emitted in an
    optional [REGIME_RATIONALE] fence, extracted out-of-log, so it gates nothing,
    enters no hashed run-log, and is rendered ONLY when present. The sealed captures
    carry no regime_expert block, so they render unchanged."""
    filings = re.get("filings") if re else None
    if not filings:
        return ""
    parts = [
        "<h2>7d. Regime-expert reasoning (each drafter is an expert in its own "
        "regulation)</h2>",
        "<p class='sub'>Each drafter is not a generic slot-filler: it is given the "
        "statutory standard its filing must meet, the named factors that regulator "
        "weighs, and the common failure modes for the regime, and it reasons in "
        "regime-specific terms. The reasoning below is the drafter's own optional "
        "rationale, explanatory prose only. It changes no load-bearing fact: the "
        "[CLAIMS] block the Warden diffs is attached after sanitization and is "
        "untouched, and this rationale is out-of-log, so the sealed run-log shas and "
        "byte-identical replay are unaffected.</p>",
    ]
    for f in filings:
        parts.append(
            f"<h3>{_esc(f.get('regime'))} expert reasoning</h3>")
        standard = f.get("statutory_standard")
        if standard:
            parts.append(
                f"<p class='sub'><strong>Statutory standard:</strong> "
                f"{_esc(standard)}</p>")
        factors = f.get("factors") or []
        if factors:
            parts.append(
                "<p class='sub'><strong>Factors this regulator weighs:</strong></p>"
                "<ul>" + "".join(f"<li>{_esc(x)}</li>" for x in factors) + "</ul>")
        rationale = f.get("rationale")
        if rationale:
            parts.append("<p class='sub'>The drafter's regime-specific rationale:</p>")
            parts.append(f"<pre>{_esc(rationale)}</pre>")
        else:
            parts.append(
                "<p class='sub'><em>This drafter emitted no separate rationale "
                "block for this run.</em></p>")
    return "".join(parts)


def _rationale_why_by_event(p: dict) -> dict:
    """Map each protocol Event name to the plain_why of the decision it drove, read
    from the packet's decision_rationale ledger (E9.1). The transition table's
    plain-English 'why' column and the room post both read THIS, so they are the
    same bytes. Pure render-time lookup over the assembled packet."""
    from floor.rationale import EVENT_RULE

    ledger = p.get("decision_rationale", {}) or {}
    out: dict[str, str] = {}
    for event, kind in EVENT_RULE.items():
        entry = ledger.get(kind)
        if entry:
            out[event.value] = entry.get("plain_why", "")
    return out


def _decided_by_badge(decided_by: str, label: str) -> str:
    """The determinism chip (E9.2): a colored badge stating, for one decision,
    whether a fixed Warden rule decided it with no AI judgment, an LLM drafted the
    content a fixed rule then checked, or it is LLM content only. The class is a
    STATIC property of the decision kind (floor/rationale.DECIDED_BY), so the chip
    is the same in the packet and the web. A deterministic rule is the strong,
    green claim; the others are honestly amber."""
    if not label:
        return ""
    cls = "cstat-ok" if decided_by == "deterministic_rule" else "cstat-bad"
    return f"<span class='cstat {cls}'>{_esc(label)}</span>"


def _provenance_trail(hashes: list) -> str:
    """The provenance trail (E9.2): the per-entry content hashes of the exact
    run-log entries this explanation rests on, each binding the rationale to its
    input entry by content. Computed READ-ONLY from the packet's transitions with
    the SAME canonicalizer the hash chain uses; never re-keys the chain."""
    if not hashes:
        return "<span class='sub'>(no input entry: a standing-state rationale)</span>"
    items = "".join(
        f"<li><span class='hash'>{_esc(h)}</span></li>" for h in hashes)
    return (f"<span class='sub'>Bound to {len(hashes)} run-log "
            f"entr{'y' if len(hashes) == 1 else 'ies'} by content hash:</span>"
            f"<ul class='provenance'>{items}</ul>")


def _render_rationale(p: dict) -> str:
    """Render the Decision rationale section (E9.1 + E9.2): per Warden decision, the
    governing rule id, the ONE plain-English 'why' that names the exact driving
    fact, the determinism chip (was it a fixed rule or AI content?), and the
    provenance trail (the exact input run-log entries it rests on, by content
    hash). This is the SAME source the room post and the web gate panel read, so the
    three read the same bytes. A pure derived render over the assembled packet; it
    never enters the hashed run-log and gates nothing."""
    ledger = p.get("decision_rationale", {}) or {}
    if not ledger:
        return ""
    rows = [
        [entry.get("rule_id"),
         _decided_by_badge(entry.get("decided_by", ""),
                           entry.get("decided_by_label", "")),
         entry.get("plain_why"),
         _provenance_trail(entry.get("evidence_entry_hashes", []) or [])]
        for entry in ledger.values()
    ]
    body = "".join(
        "<tr><td>" + _esc(rid) + "</td><td>" + chip + "</td><td>" + _esc(why)
        + "</td><td>" + prov + "</td></tr>"
        for rid, chip, why, prov in rows)
    parts = [
        "<h2>4a. Decision rationale (one source for every &quot;why&quot;)</h2>",
        "<p class='sub'>Every Warden decision carries a typed rationale built from "
        "three deterministic ingredients: which transition fired, which rule governs "
        "it, and which fact drove it (it names the EXACT driving fact value). Each "
        "row also carries a determinism chip stating whether a FIXED RULE decided it "
        "with no AI judgment or an LLM drafted content a fixed rule then checked, and "
        "a provenance trail binding the explanation to the exact input run-log "
        "entries by content hash. The Warden's room post, this section, and the web "
        "copy all read this ONE source (floor/rationale.py), so they are the same "
        "bytes, not three hand-typed strings. It is a pure derived render: zero LLM, "
        "never appended to the hashed run-log, gates nothing.</p>",
        "<table><thead><tr><th>Governing rule</th><th>How decided</th>"
        "<th>Plain-English why (names the driving fact)</th>"
        "<th>Provenance (input entries by content hash)</th></tr></thead><tbody>"
        + body + "</tbody></table>",
    ]
    return "".join(parts)


# The non-engineer's real questions, each answered DETERMINISTICALLY from the
# decision-rationale ledger and the existing release / reconciliation / replay
# blocks. The condition decides whether the card applies to THIS run; the answer
# pulls the verbatim rationale (the same bytes the room and the web show) plus the
# concrete facts already in the packet. No new judgment, no LLM: a pure derived
# read that turns the ledger into the questions a CISO or GC actually asks.
def _render_counter_questions(packet: dict) -> str:
    """Render the counter-question card (E9.2): the non-engineer's actual questions
    (did anything get blocked and why, was anything decided by AI, was a duplicate
    filed twice, can I prove none of this was altered) answered deterministically
    from the rationale ledger and the existing release / reconciliation / replay
    blocks. Pure derived read over the assembled packet; never in the hashed
    run-log, gates nothing."""
    ledger = packet.get("decision_rationale", {}) or {}
    rec = packet.get("reconciliation", {}) or {}
    release = packet.get("release", {}) or {}
    replay = packet.get("replay", {}) or {}
    chaos = packet.get("chaos", {}) or {}

    qa: list[tuple[str, str]] = []

    # Q1: was anything blocked, and why? (the contradiction veto)
    blocked = ledger.get("diff_blocked")
    resolved = ledger.get("diff_resolved")
    if blocked:
        ans = blocked.get("plain_why", "")
        if resolved:
            ans += " " + resolved.get("plain_why", "")
        else:
            ans += " Release stays held until the filings agree."
    else:
        ans = ("Nothing was blocked on a contradiction. The cross-filing diff was "
               "GREEN: every load-bearing fact agreed across the filings.")
    qa.append(("Did the referee block anything, and exactly why?", ans))

    # Q2: was any of this decided by AI? (the determinism chips, counted)
    fixed = [k for k, v in ledger.items()
             if v.get("decided_by") == "deterministic_rule"]
    ai_checked = [k for k, v in ledger.items()
                  if v.get("decided_by") == "llm_content_with_deterministic_check"]
    qa.append((
        "Was any gate decided by an AI?",
        f"No gate was decided by an AI. {len(fixed)} decision(s) were made by a "
        f"FIXED Warden rule with no AI judgment (the block, the diff, the two-key "
        f"release). {len(ai_checked)} decision(s) involved AI-drafted content that a "
        "fixed rule then CHECKED. Every badge above states which is which; the "
        "Warden that gates, blocks, releases, and clocks runs no AI."))

    # Q3: was anything filed twice? (exactly-once under a kill)
    dropped = chaos.get("duplicates_dropped", 0)
    if chaos.get("events"):
        qa.append((
            "A team dropped offline mid-incident. Was anything filed twice?",
            f"No. A drafter was killed after posting; on restart the idempotency "
            f"ledger dropped {dropped} duplicate filing(s). Each filing landed "
            "exactly once, with no double-file across the declared-dead window."))

    # Q4: did a human actually release, or did the system self-release?
    signoffs = release.get("signoffs", []) or []
    if signoffs:
        roles = ", ".join(sorted({s.get("role", "") for s in signoffs if s.get("role")}))
        branch_count = len(release.get("released_branches", []) or [])
        qa.append((
            "Did a human actually authorize the release?",
            f"Yes, and two distinct humans had to. Each released branch carries TWO "
            f"keys ({roles}); one key alone never turns the lock. "
            f"{branch_count} branch(es) released only after both keys signed."))

    # Q5: a fact changed after release; what stopped a silent re-file?
    amend = ledger.get("amend_blocked")
    if rec:
        ans = ("After release a load-bearing fact was revised. The amendment guard "
               "held the re-filing BLOCKED until both reopened drafters concurred on "
               "one shared figure.")
        if amend:
            ans = amend.get("plain_why", "") + " " + (
                "The two drafters reconciled through Band; the amended diff passed "
                "GREEN only after concurrence, then re-released under the same "
                "two-key gate.")
        qa.append(("A fact changed after filing. What stopped a silent re-file?", ans))

    # Q6: can I prove none of this was altered? (replay + chain + signature)
    sha = replay.get("original_sha256", "")
    if sha:
        bi = "byte for byte" if replay.get("byte_identical") else "with a MISMATCH"
        head = replay.get("chain_head", "")
        head_line = (f" A per-entry hash chain (head {head[:16]}...) makes any "
                     "reorder or omission detectable.") if head else ""
        qa.append((
            "Can I prove none of this was altered?",
            f"Yes, without trusting us. The run replays {bi} to the recorded "
            f"SHA-256 ({sha[:16]}...).{head_line} A detached Ed25519 signature binds "
            "that exact ordered run; you re-derive all three in your own browser."))

    if not qa:
        return ""
    cards = "".join(
        "<details class='cq'><summary>" + _esc(q) + "</summary>"
        "<p class='sub'>" + _esc(a) + "</p></details>"
        for q, a in qa)
    return (
        "<h2>4b. Plain answers to the questions a non-engineer asks</h2>"
        "<p class='sub'>The questions an incident commander, a general counsel, or "
        "a board member actually asks, each answered DETERMINISTICALLY from the "
        "decision-rationale ledger and the release, amendment, and replay records "
        "already in this packet. No new judgment, no AI: the answers are the same "
        "bytes the room and the web console show.</p>"
        + cards)


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
    why_of = _rationale_why_by_event(p)
    transition_rows = _rows(
        ["Branch", "From state", "Event", "To state", "Admitted", "Actor",
         "Why (plain English)"],
        [[t.get("correlation_id"), t.get("from_state"), t.get("event"),
          t.get("to_state") or t.get("reason"), t.get("admitted"), t.get("actor"),
          why_of.get(t.get("event"), "")]
         for t in transitions],
    )
    lifecycle_rows = _rows(
        ["Band message id", "States observed"],
        [[m.get("message_id"), " -> ".join(m.get("states", []))] for m in lifecycle],
    )
    clock_rows = _rows(
        ["Clock", "Branch", "Trigger event", "Started", "Deadline (UTC)",
         "Deadline (regulator local)", "Holiday calendar", "Stopped", "Breached"],
        [[c.get("name"), c.get("correlation_id"), c.get("trigger_event"),
          c.get("started"), c.get("deadline"),
          c.get("deadline_local") or "(UTC only)",
          c.get("holiday_calendar") or "(calendar-hour, no holiday math)",
          c.get("stopped") or "(running)", c.get("breached")]
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
    rationale_block = _render_rationale(p)
    counter_questions_block = _render_counter_questions(p)
    diff_summary = _render_diff(diff)
    consistency_block = _render_consistency(p.get("consistency", {}))
    reconciliation_block = _render_reconciliation(p.get("reconciliation", {}))
    deficiency_block = _render_deficiency(p.get("deficiency", {}))
    completeness_block = _render_completeness(p.get("completeness", {}))
    submission_block = _render_submission(p.get("submission", {}))
    controls_block = _render_controls(p.get("controls", {}))
    sod_block = _render_sod(p.get("sod", {}))
    assertion_block = _render_assertion(p.get("assertion", {}))
    egress_block = _render_egress(p.get("egress", {}))
    chaos_block = _render_chaos(p.get("chaos", {}))
    security_block = _render_security(p.get("security", {}))
    regime_expert_block = _render_regime_expert(p.get("regime_expert", {}))
    grounding_block = _render_grounding(p.get("grounding", {}))
    rag_grounding_block = _render_rag_grounding(p.get("rag_grounding", {}))
    calibration_block = _render_calibration(p.get("calibration", {}))
    adversarial_block = _render_adversarial_review(p.get("adversarial_review", {}))
    reportability_block = _render_reportability(p.get("reportability", {}))
    affected_party_block = _render_affected_party(p.get("affected_party", {}))
    cross_border_block = _render_cross_border(p.get("cross_border", {}))
    legal_hold_block = _render_legal_hold(p.get("legal_hold", {}))
    materiality_block = _render_materiality(p.get("materiality", {}))
    recruit_block = _render_recruit(p.get("recruit", {}))
    nydfs_recruit_block = _render_nydfs_recruit(p.get("nydfs_recruit", {}))
    release_block = _render_release(p.get("release", {}))
    edgar_block = _render_edgar_export(p.get("edgar_export", {}))
    ecosystem_block = _render_ecosystem_exports(p.get("ecosystem_exports", {}))
    attestation_block = _render_attestation(p.get("attestation", {}))
    timestamp_block = _render_timestamp(p.get("timestamp", {}))
    reliability_block = _render_reliability(p.get("reliability", {}))
    gateway_block = _render_routing(p.get("gateway", {}))
    operability_block = _render_operability(p.get("operability", {}))
    privilege_block = _render_privilege(p.get("privilege", {}))
    timeline_block = _render_timeline(p.get("timeline", {}))
    after_action_block = _render_after_action(p.get("after_action", {}))
    policy_version_block = _render_policy_version(p.get("policy_version", {}))
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
.cstat {{ display: inline-block; border-radius: 4px; padding: 1px 8px; font-size: 12px;
          font-weight: 700; letter-spacing: 0.5px; }}
.cstat-ok {{ background: #e6f4ec; color: #1d7a43; }}
.cstat-bad {{ background: #fbf2dd; color: #8a5a00; }}
.cstat-na {{ background: #eef0f3; color: #5b6473; }}
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
.provenance {{ margin: 4px 0 0; padding-left: 16px; }}
.provenance li {{ margin: 2px 0; }}
.cq {{ border: 1px solid #d7dce4; border-radius: 6px; margin: 6px 0; padding: 4px 10px;
       background: #fbfcfe; break-inside: avoid; }}
.cq summary {{ cursor: pointer; font-weight: 600; padding: 4px 0; }}
.cq[open] summary {{ border-bottom: 1px solid #e1e5ec; margin-bottom: 4px; }}

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
.jlocal {{ font-size: 11px; color: #5b6473; font-family: ui-monospace, monospace; }}
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

{completeness_block}

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
<p class="sub">The Warden admits or rejects every handoff; illegal moves never execute.
The "why" column reads the same decision-rationale source the Warden posted in the
room and the web shows, so the three never disagree.</p>
{transition_rows}

{rationale_block}

{counter_questions_block}

<h2>5. Statutory clocks</h2>
<p class="sub">Each deadline is stored and compared as a single UTC instant; the
"regulator local" column derives that same instant in the regulator's own IANA
time zone at render time (the same 72-hour window is a different wall-clock in
Brussels than in London). A business-day clock counts against its OWN
jurisdiction's public-holiday calendar: the SEC 4-business-day count skips US
federal holidays (Juneteenth, etc.), not another country's.</p>
{clock_rows}

{reportability_block}

{affected_party_block}

{cross_border_block}

{legal_hold_block}

{materiality_block}

{recruit_block}

{nydfs_recruit_block}

<h2>6. Cross-filing contradiction diff</h2>
{diff_summary}

{consistency_block}

{reconciliation_block}

{deficiency_block}

<h2>7. Drafted filings</h2>
{filing_blocks or '<p>No filings drafted.</p>'}

{chaos_block}

{security_block}

{regime_expert_block}

{grounding_block}

{rag_grounding_block}

{calibration_block}

{adversarial_block}

{release_block}

{edgar_block}

{ecosystem_block}

{submission_block}

{controls_block}

{sod_block}

{assertion_block}

{egress_block}

{attestation_block}

{timestamp_block}

{reliability_block}

{gateway_block}

{operability_block}

{privilege_block}

{timeline_block}

{after_action_block}

{policy_version_block}

<h2>8. Byte-identical replay</h2>
<p>Run-log SHA-256: <span class="hash">{_esc(replay.get('original_sha256', ''))}</span></p>
<p>Replayed SHA-256: <span class="hash">{_esc(replay.get('replayed_sha256', ''))}</span></p>
<p class="{'ok' if replay.get('byte_identical') else 'bad'}">
  {'Replay reproduced the run log byte for byte.' if replay.get('byte_identical')
   else 'Replay did not match.'}</p>

{pending_section}
</div></body></html>"""
