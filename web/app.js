"use strict";

// Deadline Room replay viewer. Loads a captured Examiner Packet plus its run-log
// JSONL, builds an ordered step timeline, animates it, and re-verifies the
// byte-identical replay hash in the browser against the bundled log.

const TIME_COMPRESSION_LABEL = "1 second = 30 captured minutes";

// ---- small DOM helpers ------------------------------------------------------
const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};
const fmtNum = (n) => Number(n).toLocaleString("en-US");

// ---- canonical JSON + SHA-256 (mirrors warden/replay.py exactly) -----------
// Python writes each run-log line as json.dumps(entry, sort_keys=True,
// separators=(",",":")), joins with "\n", and appends a trailing "\n", then
// sha256 of that UTF-8 text. We reproduce that recipe so the verify is exact.
function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "number") return numberToJson(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
}

// json.dumps renders integers without a decimal point and floats with one. The
// run log carries only integers and strings, so integer rendering is what
// matters; guard floats defensively anyway.
function numberToJson(n) {
  if (Number.isInteger(n)) return String(n);
  return String(n);
}

function recanonicalizeJsonl(text) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const out = lines.map((l) => canonicalize(JSON.parse(l)));
  return out.join("\n") + "\n";
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- time helpers -----------------------------------------------------------
const ms = (iso) => new Date(iso).getTime();
function fmtClock(milliseconds) {
  if (milliseconds <= 0) return "00:00:00";
  let s = Math.floor(milliseconds / 1000);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  const pad = (x) => String(x).padStart(2, "0");
  const hms = `${pad(h)}:${pad(m)}:${pad(s)}`;
  return d > 0 ? `${d}d ${hms}` : hms;
}
function fmtTs(iso) {
  // 2026-06-16T02:14:00+00:00 -> 2026-06-16 02:14 UTC
  return iso.replace("T", " ").replace(/:\d{2}\+00:00$/, " UTC").replace(/\+00:00$/, " UTC");
}

// ---- role / display naming --------------------------------------------------
const ROLE_OF = {
  warden: "warden", triage: "triage",
  nis2_drafter: "drafter", sec_drafter: "drafter", dora_drafter: "drafter",
  lena: "human",
};
const DISPLAY = {
  warden: "Deadline Warden", triage: "Triage",
  nis2_drafter: "NIS2 Drafter", sec_drafter: "SEC Drafter", dora_drafter: "DORA Drafter",
  lena: "Lena (human owner)",
};
const ROSTER = [
  { id: "warden", role: "warden" },
  { id: "triage", role: "triage" },
  { id: "nis2_drafter", role: "drafter" },
  { id: "sec_drafter", role: "drafter" },
  { id: "dora_drafter", role: "drafter" },
];

// ---- state ------------------------------------------------------------------
let manifest = null;
let packet = null;
let runLogText = "";
let steps = [];          // ordered timeline steps
let cursor = 0;          // index into steps (0 = nothing happened yet)
let playing = false;
let playTimer = null;

// ============================================================================
// Build the ordered timeline of steps from the packet.
// Each step: { ts, kind, actor, label, apply(viewState) } — but we keep it data
// driven: a step records what becomes true, and render(cursor) reduces all steps
// up to the cursor into the live view.
// ============================================================================
function buildSteps(p) {
  const out = [];
  const handoffs = p.handoff_trace || [];
  // index handoffs by message_id + kind so a transition can light its edge
  const transitions = p.state_transitions || [];

  // A synthetic opening step: room created, clocks started.
  out.push({
    ts: p.clocks && p.clocks.length ? p.clocks[0].started : null,
    caption: `Warden created the incident room and started ${(p.clocks || []).length} statutory clocks at T0.`,
    speakers: ["warden"],
  });

  // Fact-record fan-out: the first fact_record handoffs share one message id.
  const factHandoffs = handoffs.filter((h) => h.kind === "fact_record");
  if (factHandoffs.length) {
    out.push({
      ts: firstTsForEvent(transitions, "fact_record_posted"),
      caption: `Triage posted the canonical fact-record and @mentioned all ${factHandoffs.length} drafters.`,
      speakers: ["triage"],
      message: {
        from: "triage", to: "drafters", kind: "fact_record",
        mid: factHandoffs[0].message_id,
        body: "INCIDENT FACT-RECORD (canonical). Drafters: draft your regime notification from these facts and post back @mentioning the Warden.",
      },
      handoffKeys: factHandoffs.map((h) => hKey(h)),
    });
  }

  // Per-branch drafting: walk draft handoffs (drafter -> Warden) in order.
  const draftHandoffs = handoffs.filter((h) => h.kind === "draft");
  for (const h of draftHandoffs) {
    const actor = branchActor(h.from);
    out.push({
      ts: firstTsForBranchEvent(transitions, branchOf(actor), "draft_posted"),
      caption: `${h.from} drafted its notification and posted back @mentioning the Warden.`,
      speakers: [actor],
      message: {
        from: actor, to: "warden", kind: "draft", mid: h.message_id,
        body: `${h.from} mandatory notification draft attached.`,
      },
      handoffKeys: [hKey(h)],
      branchState: { branch: branchOf(actor), state: "draft_submitted" },
    });
  }

  // The contradiction beat.
  const blocked = (p.diff && p.diff.blocked_conflicts) || [];
  if (blocked.length) {
    out.push({
      ts: firstTsForEvent(transitions, "diff_blocked"),
      caption: "The Warden's deterministic diff found a conflict on a load-bearing fact and BLOCKED signoff.",
      speakers: ["warden"],
      message: {
        from: "warden", to: "room", kind: "block",
        body: "Cross-filing contradiction. Submission blocked.\n" + blocked.join("\n"),
      },
      reveal: "contradiction",
      allBranchState: "blocked",
    });
    if (p.diff.resolution) {
      const r = p.diff.resolution;
      out.push({
        ts: firstTsForEvent(transitions, "diff_passed"),
        caption: `Fact corrected on ${r.fixed_branch.toUpperCase()} (${r.corrected_field}); the diff re-ran green and signoff unblocked.`,
        speakers: ["triage", "warden"],
        message: {
          from: "triage", to: "room", kind: "concur",
          body: `Correction: ${r.corrected_field} ${r.from_value} -> ${r.to_value} on ${r.fixed_branch.toUpperCase()}. Diff re-run GREEN.`,
        },
        allBranchState: "contradiction_checked",
      });
    }
  } else {
    // clean green diff
    out.push({
      ts: firstTsForEvent(transitions, "diff_passed"),
      caption: "The Warden ran the cross-filing contradiction diff: GREEN, all filings agree.",
      speakers: ["warden"],
      message: { from: "warden", to: "room", kind: "concur", body: "Cross-filing contradiction diff: GREEN. No conflicts." },
    });
  }

  // The chaos beat (insert near the killed branch's draft if present).
  const chaosEvents = (p.chaos && p.chaos.events) || [];
  if (chaosEvents.length) {
    out.push({
      ts: firstTsForBranchEvent(transitions, "sec", "draft_posted") || lastTs(out),
      caption: `Exactly-once under a live kill: a drafter was killed after posting; on restart the dedup ledger dropped the duplicate (${p.chaos.duplicates_dropped} duplicate dropped).`,
      speakers: ["sec_drafter"],
      message: {
        from: "sec_drafter", to: "warden", kind: "concur",
        body: "Recovered after kill at position B. Round-1 draft already in the room; duplicate dropped. Filed exactly once.",
      },
      reveal: "chaos",
    });
  }

  // Signoff + release.
  out.push({
    ts: firstTsForEvent(transitions, "human_released"),
    caption: "Warden opened signoff; the human owner released. Every released branch's clock stopped.",
    speakers: ["warden", "lena"],
    message: { from: "lena", to: "room", kind: "concur", body: "Human owner released the filings. Clocks stopped." },
    allBranchState: "released",
  });

  // The amendment reconciliation beat.
  const rec = p.reconciliation;
  if (rec) {
    out.push({
      ts: tsForEventBranch(transitions, "fact_amended", "sec"),
      caption: `Amendment: ${rec.fact_key} revised ${fmtNum(rec.old_value)} -> ${fmtNum(rec.new_value)}. SEC and NIS2 branches reopened (amending).`,
      speakers: ["triage"],
      message: {
        from: "triage", to: "drafters", kind: "propose",
        mid: rec.amend_message_id,
        body: `FACT AMENDMENT. ${rec.fact_key} revised ${fmtNum(rec.old_value)} -> ${fmtNum(rec.new_value)}. Reopen, reconcile a shared characterization, re-file.`,
      },
      branchSet: { sec: "amending", nis2: "amending" },
    });
    if (rec.blocked_before_reconciliation) {
      out.push({
        ts: tsForEventBranch(transitions, "fact_amended", "sec"),
        caption: "Warden guard BLOCKED the amendment before reconciliation: no concur envelope yet.",
        speakers: ["warden"],
        message: { from: "warden", to: "room", kind: "block", body: "Amendment blocked: " + rec.block_reason },
        reveal: "reconciliation",
      });
    }
    (rec.exchange || []).forEach((e, i) => {
      const actor = e.from === "SEC Drafter" ? "sec_drafter" : "nis2_drafter";
      const to = e.to === "SEC Drafter" ? "sec_drafter" : "nis2_drafter";
      out.push({
        ts: tsForEventBranch(transitions, "draft_posted", actor === "sec_drafter" ? "sec" : "nis2") || lastTs(out),
        caption: `${e.from} ${e.verdict === "propose" ? "proposed how to characterize the revised figure to" : "concurred back to"} ${e.to} (hash-linked envelope).`,
        speakers: [actor],
        message: {
          from: actor, to: to, kind: e.verdict,
          mid: e.band_message_id,
          body: `${e.verdict.toUpperCase()} ${rec.fact_key}=${fmtNum(e.proposed_value)}. "${e.characterization}"`,
        },
        handoffKeys: handoffKeyForReconcile(handoffs, e.verdict),
        reveal: "reconciliation",
      });
    });
    out.push({
      ts: tsForEventBranch(transitions, "human_released", "sec"),
      caption: `Concur exists; both branches re-filed at the reconciled figure ${fmtNum(rec.concurred_value)}. Amended diff green only after concurrence; re-released.`,
      speakers: ["warden", "lena"],
      message: { from: "lena", to: "room", kind: "concur", body: `Amended filings released at ${fmtNum(rec.concurred_value)}.` },
      branchSet: { sec: "released", nis2: "released" },
    });
  }

  // Final replay step.
  out.push({
    ts: lastTs(out),
    caption: `Replay byte-identical: ${p.replay.byte_identical}. Examiner Packet sealed (sha ${p.replay.original_sha256.slice(0, 12)}...).`,
    speakers: ["warden"],
    final: true,
  });

  return out;
}

// ---- step-build helpers -----------------------------------------------------
function hKey(h) { return `${h.from}|${h.to}|${h.kind}`; }
function branchOf(actor) {
  if (actor === "sec_drafter") return "sec";
  if (actor === "nis2_drafter") return "nis2";
  if (actor === "dora_drafter") return "dora";
  return "";
}
function branchActor(fromLabel) {
  if (fromLabel.startsWith("SEC")) return "sec_drafter";
  if (fromLabel.startsWith("NIS2")) return "nis2_drafter";
  if (fromLabel.startsWith("DORA")) return "dora_drafter";
  return "triage";
}
function firstTsForEvent(transitions, event) {
  const t = transitions.find((x) => x.event === event && x.admitted);
  return t ? t.ts : null;
}
function firstTsForBranchEvent(transitions, branch, event) {
  const t = transitions.find((x) => x.event === event && x.admitted && x.correlation_id === `inc-8842:${branch}`);
  return t ? t.ts : null;
}
function tsForEventBranch(transitions, event, branch) {
  const matches = transitions.filter((x) => x.event === event && x.admitted && x.correlation_id === `inc-8842:${branch}`);
  return matches.length ? matches[matches.length - 1].ts : null;
}
function lastTs(out) {
  for (let i = out.length - 1; i >= 0; i--) if (out[i].ts) return out[i].ts;
  return null;
}
function handoffKeyForReconcile(handoffs, verdict) {
  const kind = verdict === "propose" ? "reconcile_propose" : "reconcile_concur";
  return handoffs.filter((h) => h.kind === kind).map((h) => hKey(h));
}

// ============================================================================
// Rendering: reduce steps[0..cursor] into the live view.
// ============================================================================
function render() {
  const active = steps.slice(0, cursor);
  const latest = active[active.length - 1] || null;
  const nowTs = latest && latest.ts ? latest.ts : (steps[0] && steps[0].ts);

  $("#step-label").textContent = `step ${cursor} / ${steps.length}`;
  $("#scrubber").value = String(cursor);
  $("#event-caption").textContent = latest ? latest.caption : "Press play to replay the captured run.";
  $("#clock-now-ts").textContent = nowTs ? fmtTs(nowTs) : "--";

  renderRoster(latest);
  renderFeed(active);
  renderClocks(nowTs);
  renderHandoffs(active);
  renderBranchStates(active);
  renderReveals(active);
}

function renderRoster(latest) {
  const wrap = $("#roster");
  wrap.innerHTML = "";
  const speakers = new Set(latest ? latest.speakers || [] : []);
  for (const a of ROSTER) {
    const chip = el("div", `agent-chip role-${a.role}` + (cursor > 0 ? " active" : ""));
    if (speakers.has(a.id)) chip.classList.add("speaking");
    chip.appendChild(el("span", "dot"));
    chip.appendChild(el("span", null, DISPLAY[a.id]));
    wrap.appendChild(chip);
  }
}

function renderFeed(active) {
  const feed = $("#feed");
  feed.innerHTML = "";
  const msgs = active.filter((s) => s.message);
  if (!msgs.length) {
    feed.appendChild(el("div", "feed-empty", "The room is quiet. Play the timeline to bring it alive."));
    return;
  }
  for (const s of msgs) {
    const m = s.message;
    const row = el("div", `msg kind-${m.kind}`);
    const head = el("div", "msg-head");
    const from = el("span", `from ${ROLE_OF[m.from] || ""}`, DISPLAY[m.from] || m.from);
    head.appendChild(from);
    head.appendChild(el("span", "to", "@ " + (m.to === "warden" ? "Deadline Warden" : m.to)));
    row.appendChild(head);
    row.appendChild(el("div", "body", m.body));
    if (m.mid) row.appendChild(el("div", "mid", "msg " + m.mid));
    feed.appendChild(row);
  }
  feed.scrollTop = feed.scrollHeight;
}

function renderClocks(nowTs) {
  const wrap = $("#clocks");
  wrap.innerHTML = "";
  const now = nowTs ? ms(nowTs) : (packet.clocks[0] ? ms(packet.clocks[0].started) : 0);
  for (const c of packet.clocks) {
    const started = ms(c.started);
    const deadline = ms(c.deadline);
    const stoppedAt = c.stopped ? ms(c.stopped) : null;
    const isStopped = stoppedAt != null && now >= stoppedAt;
    const evalAt = isStopped ? stoppedAt : Math.min(now, deadline);
    const remaining = deadline - evalAt;
    const total = deadline - started;
    const elapsed = Math.max(0, Math.min(total, evalAt - started));
    const pct = total > 0 ? (elapsed / total) * 100 : 0;
    const breached = !isStopped && now > deadline;
    const warn = !isStopped && !breached && remaining < total * 0.25;

    const cell = el("div", "clock " + (isStopped ? "stopped" : breached ? "breach running" : "running") + (warn ? " warn" : ""));
    cell.appendChild(el("span", "status-pill", isStopped ? "stopped" : breached ? "breach" : "running"));
    cell.appendChild(el("div", "name", c.name));
    cell.appendChild(el("div", "remaining", isStopped ? "stopped, " + fmtClock(deadline - stoppedAt) + " to spare" : breached ? "BREACHED" : fmtClock(remaining)));
    cell.appendChild(el("div", "deadline", "deadline " + fmtTs(c.deadline)));
    const bar = el("div", "bar");
    const fill = el("span");
    fill.style.width = Math.max(0, Math.min(100, pct)) + "%";
    bar.appendChild(fill);
    cell.appendChild(bar);
    wrap.appendChild(cell);
  }
}

function renderHandoffs(active) {
  const lit = new Set();
  for (const s of active) for (const k of (s.handoffKeys || [])) lit.add(k);
  const wrap = $("#handoffs");
  wrap.innerHTML = "";
  for (const h of packet.handoff_trace) {
    const key = hKey(h);
    const row = el("div", `handoff kind-${h.kind}` + (lit.has(key) ? " lit" : ""));
    row.appendChild(el("span", "h-from", h.from));
    row.appendChild(el("span", "arrow", "->"));
    row.appendChild(el("span", "h-to", h.to));
    row.appendChild(el("span", "kind", h.kind));
    wrap.appendChild(row);
  }
}

function renderBranchStates(active) {
  const states = { nis2: "idle", sec: "idle", dora: "idle" };
  for (const s of active) {
    if (s.branchState) states[s.branchState.branch] = s.branchState.state;
    if (s.allBranchState) for (const b of Object.keys(states)) states[b] = s.allBranchState;
    if (s.branchSet) for (const b of Object.keys(s.branchSet)) states[b] = s.branchSet[b];
  }
  const wrap = $("#branch-states");
  wrap.innerHTML = "";
  for (const b of ["nis2", "sec", "dora"]) {
    const row = el("div", "branch-state");
    row.appendChild(el("span", "label", b.toUpperCase()));
    const cls = states[b] === "released" ? "released"
      : states[b] === "blocked" ? "blocked"
      : states[b] === "amending" ? "amending"
      : states[b] === "draft_submitted" || states[b] === "drafting" ? "drafting" : "";
    row.appendChild(el("span", "state " + cls, states[b].replace(/_/g, " ")));
    wrap.appendChild(row);
  }
}

function renderReveals(active) {
  const revealed = new Set();
  for (const s of active) if (s.reveal) revealed.add(s.reveal);
  toggle("#contradiction-section", revealed.has("contradiction"));
  toggle("#chaos-section", revealed.has("chaos"));
  toggle("#reconciliation-section", revealed.has("reconciliation"));
}
function toggle(sel, on) { $(sel).classList.toggle("hidden", !on); }

// ============================================================================
// Static panels (built once per packet, not animated).
// ============================================================================
function renderStaticPanels() {
  $("#room-id").textContent = "room " + packet.incident.band_room_id;

  // Compression banner
  $("#compression-banner").innerHTML = "";
  const b = $("#compression-banner");
  b.appendChild(el("b", null, "REPLAY OF A CAPTURED LIVE BAND RUN"));
  b.appendChild(el("span", null, TIME_COMPRESSION_LABEL));
  b.appendChild(el("span", null, "log sha " + packet.replay.original_sha256.slice(0, 16) + "..."));
  b.appendChild(el("span", null, "this is forensic playback, not a simulator"));

  // Contradiction body
  const cBody = $("#contradiction-body");
  cBody.innerHTML = "";
  const blocked = (packet.diff && packet.diff.blocked_conflicts) || [];
  if (blocked.length) {
    $("#contradiction-badge").textContent = packet.diff.resolution ? "blocked, then cleared" : "blocked";
    $("#contradiction-badge").className = "badge " + (packet.diff.resolution ? "amber" : "red");
    for (const line of blocked) cBody.appendChild(el("div", "conflict", line));
    if (packet.diff.resolution) {
      const r = packet.diff.resolution;
      const res = el("div", "resolution");
      res.innerHTML = `<strong>Resolved.</strong> ${r.corrected_field} corrected on ${r.fixed_branch.toUpperCase()}: <code>${r.from_value}</code> -> <code>${r.to_value}</code>. The diff re-ran green and signoff was admitted.`;
      cBody.appendChild(res);
    }
  }

  // Chaos body
  const chaos = packet.chaos || {};
  const xBody = $("#chaos-body");
  xBody.innerHTML = "";
  if ((chaos.events || []).length) {
    const intro = el("p", "small muted",
      `${chaos.duplicates_dropped} duplicate dropped. The exactly-once guarantee holds at the transport level: the killed drafter's round-1 filing appears once.`);
    xBody.appendChild(intro);
    for (const ev of chaos.events) {
      const card = el("div", "conflict");
      card.style.borderColor = ev.phase === "kill" ? "var(--red)" : "var(--green)";
      card.style.background = ev.phase === "kill" ? "var(--red-soft)" : "var(--green-soft)";
      card.innerHTML = `<strong>${ev.branch.toUpperCase()} ${ev.phase}</strong> (${ev.disposition}). ${ev.note || ""}`;
      xBody.appendChild(card);
    }
  }
  if ((chaos.ledger || []).length) {
    const table = el("table", "ledger-table");
    table.innerHTML = "<thead><tr><th>dedup key</th><th>attempt</th><th>disposition</th></tr></thead>";
    const tb = el("tbody");
    for (const e of chaos.ledger) {
      const tr = el("tr");
      tr.appendChild(el("td", null, e.key));
      tr.appendChild(el("td", null, String(e.attempt)));
      tr.appendChild(el("td", "disp-" + e.disposition, e.disposition.replace(/_/g, " ")));
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    xBody.appendChild(table);
  }

  // Reconciliation body
  const rBody = $("#reconciliation-body");
  rBody.innerHTML = "";
  const rec = packet.reconciliation;
  if (rec) {
    const kv = el("dl", "kv");
    addKv(kv, "fact", rec.fact_key);
    addKv(kv, "revised", `${fmtNum(rec.old_value)} -> ${fmtNum(rec.new_value)}`);
    addKv(kv, "reopened", (rec.reopened_branches || []).map((x) => x.toUpperCase()).join(", "));
    addKv(kv, "blocked first", String(rec.blocked_before_reconciliation));
    addKv(kv, "concurred at", fmtNum(rec.concurred_value));
    rBody.appendChild(kv);
    if (rec.block_reason) {
      const blk = el("div", "conflict");
      blk.style.marginTop = "0.6rem";
      blk.innerHTML = `<strong>Guard held the amendment blocked until concurrence:</strong> ${rec.block_reason}`;
      rBody.appendChild(blk);
    }
    const chain = el("div", "envelope-chain");
    for (const e of rec.exchange || []) {
      const env = el("div", "envelope " + e.verdict);
      const head = el("div", "env-head");
      head.appendChild(el("span", "env-verdict", e.verdict));
      head.appendChild(el("span", "muted", `${e.from} -> ${e.to}`));
      env.appendChild(head);
      env.appendChild(el("div", "char", `"${e.characterization}"`));
      const hashes = el("div", "hashes");
      hashes.appendChild(el("div", null, "envelope " + e.envelope_sha256.slice(0, 24) + "..."));
      if (e.prior_envelope_hash) {
        hashes.appendChild(el("div", "link-ok", "hash-linked to prior " + e.prior_envelope_hash.slice(0, 24) + "..."));
      } else {
        hashes.appendChild(el("div", "muted-2", "chain root (no prior)"));
      }
      env.appendChild(hashes);
      chain.appendChild(env);
    }
    rBody.appendChild(chain);
    const note = el("p", "small muted");
    note.style.marginTop = "0.6rem";
    note.textContent = `Diff passed only after concur: ${rec.diff_passed_only_after_concur}. The hash chain is the tamper-evident audit trail of the deliberation.`;
    rBody.appendChild(note);
  }

  // Packet meta + verdict
  const greenVerdict = !((packet.diff.blocked_conflicts || []).length) || packet.diff.resolution || packet.diff.green;
  $("#verdict-badge").textContent = greenVerdict ? "released, clean" : "blocked";
  $("#verdict-badge").className = "badge " + (greenVerdict ? "green" : "red");
  const meta = $("#packet-meta");
  meta.innerHTML = "";
  const mkv = el("dl", "kv");
  addKv(mkv, "incident", packet.incident.incident_id);
  addKv(mkv, "entity", packet.incident.fact_record.regulated_entity);
  addKv(mkv, "mode", packet.incident.mode);
  addKv(mkv, "records", fmtNum(packet.incident.fact_record.records_affected) + (packet.reconciliation ? " -> " + fmtNum(packet.reconciliation.new_value) : ""));
  addKv(mkv, "breaches", (packet.breached_clocks || []).length ? packet.breached_clocks.join(", ") : "none");
  addKv(mkv, "replay", packet.replay.byte_identical ? "byte-identical" : "MISMATCH");
  meta.appendChild(mkv);

  $("#recorded-hash").textContent = packet.replay.original_sha256;
  $("#recomputed-hash").textContent = "--";
  const vr = $("#verify-result");
  vr.className = "verify-result pending";
  vr.textContent = "Not yet verified. Click to recompute from the bundled run log.";

  // Filings
  const fWrap = $("#filings");
  fWrap.innerHTML = "";
  (packet.filings || []).forEach((f, i) => {
    const isAmended = packet.reconciliation && i >= (packet.filings.length - (packet.reconciliation.reopened_branches || []).length);
    const card = el("div", "filing" + (isAmended ? " amended" : ""));
    const head = el("div", "filing-head");
    head.appendChild(el("span", "regime", f.regime + (isAmended ? " (amended)" : "")));
    head.appendChild(el("span", "model", f.model));
    card.appendChild(head);
    card.appendChild(el("div", "filing-text", stripClaims(f.text)));
    fWrap.appendChild(card);
  });
}

function addKv(dl, k, v) { dl.appendChild(el("dt", null, k)); dl.appendChild(el("dd", null, String(v))); }
function stripClaims(text) { return text.replace(/\[CLAIMS\][\s\S]*?\[\/CLAIMS\]/g, "").trim(); }

// ============================================================================
// Transport: play / pause / scrub.
// ============================================================================
function setCursor(n) {
  cursor = Math.max(0, Math.min(steps.length, n));
  render();
  if (cursor >= steps.length) stopPlay();
}
function step() {
  if (cursor >= steps.length) { stopPlay(); return; }
  setCursor(cursor + 1);
}
function startPlay() {
  if (playing) return;
  if (cursor >= steps.length) cursor = 0;
  playing = true;
  $("#play").textContent = "Pause";
  scheduleNext();
}
function scheduleNext() {
  const speed = parseFloat($("#speed").value) || 1;
  const base = 1100; // ms per step at 1x
  playTimer = setTimeout(() => {
    step();
    if (playing && cursor < steps.length) scheduleNext();
    else stopPlay();
  }, base / speed);
}
function stopPlay() {
  playing = false;
  $("#play").textContent = "Play";
  if (playTimer) { clearTimeout(playTimer); playTimer = null; }
}

// ============================================================================
// In-browser replay-hash verification.
// ============================================================================
async function verifyReplayHash() {
  const vr = $("#verify-result");
  vr.className = "verify-result pending";
  vr.textContent = "Recomputing SHA-256 of the bundled run log in your browser...";
  try {
    const canonical = recanonicalizeJsonl(runLogText);
    const hex = await sha256Hex(canonical);
    $("#recomputed-hash").textContent = hex;
    if (hex === packet.replay.original_sha256) {
      vr.className = "verify-result ok";
      vr.textContent = "Match. The browser re-derived the exact hash the Warden recorded. Replay is byte-identical, verified client-side.";
    } else {
      vr.className = "verify-result fail";
      vr.textContent = "Mismatch. The recomputed hash does not equal the recorded hash.";
    }
  } catch (err) {
    vr.className = "verify-result fail";
    vr.textContent = "Verification could not run: " + err.message +
      " (the SubtleCrypto API needs a secure context; serve over http://localhost or https, not file://).";
  }
}

// ============================================================================
// Scenario loading.
// ============================================================================
async function loadScenario(scn) {
  stopPlay();
  const [p, log] = await Promise.all([
    fetch(scn.packet).then((r) => r.json()),
    fetch(scn.run_log).then((r) => r.text()),
  ]);
  packet = p;
  runLogText = log;
  steps = buildSteps(packet);
  $("#scrubber").max = String(steps.length);
  cursor = 0;
  renderStaticPanels();
  render();
}

async function init() {
  manifest = await fetch("data/manifest.json").then((r) => r.json());
  const sel = $("#scenario");
  for (const scn of manifest.scenarios) {
    const opt = el("option", null, scn.label);
    opt.value = scn.id;
    sel.appendChild(opt);
  }
  sel.addEventListener("change", () => {
    const scn = manifest.scenarios.find((s) => s.id === sel.value);
    if (scn) loadScenario(scn);
  });
  // default to the contradiction scenario: it shows the veto beat on camera
  const def = manifest.scenarios.find((s) => s.id === "inject_contradiction") || manifest.scenarios[0];
  sel.value = def.id;
  await loadScenario(def);

  $("#play").addEventListener("click", () => (playing ? stopPlay() : startPlay()));
  $("#restart").addEventListener("click", () => { stopPlay(); setCursor(0); });
  $("#scrubber").addEventListener("input", (e) => { stopPlay(); setCursor(parseInt(e.target.value, 10)); });
  $("#verify").addEventListener("click", verifyReplayHash);
}

init().catch((err) => {
  document.body.insertAdjacentHTML("afterbegin",
    `<div style="padding:1rem;background:#3a1820;color:#ff5f6e;font-family:monospace">Failed to load: ${err.message}. Serve this directory over http (py -m http.server) rather than opening the file directly.</div>`);
});
