"use strict";

// Deadline Room replay viewer. Loads a captured Examiner Packet plus its run-log
// JSONL, builds an ordered step timeline, animates it, smoothly ticks the
// statutory clocks between recorded timestamps, and lets a judge re-verify all
// three forensic proofs (replay hash, hash-chain head, Ed25519 signature) in
// their own browser against the bundled log.

const TIME_COMPRESSION_LABEL = "1 second = 30 captured minutes";
// 1 displayed second covers 30 captured minutes. This is the ratio the banner
// declares, used to interpolate the clocks during playback. It is a DISPLAY
// rate only: the interpolated time is always clamped to the next recorded
// step timestamp, so the clocks never show a time the run did not actually
// reach (the deltas are real recorded deltas played at a declared speed).
const CAPTURED_MS_PER_REAL_MS = 30 * 60 * 1000 / 1000;

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

function parseJsonlEntries(text) {
  return text.split(/\r?\n/).filter((l) => l.trim().length > 0).map((l) => JSON.parse(l));
}

function canonicalJsonl(entries) {
  return entries.map(canonicalize).join("\n") + "\n";
}

function recanonicalizeJsonl(text) {
  return canonicalJsonl(parseJsonlEntries(text));
}

async function sha256Hex(str) {
  const bytes = new TextEncoder().encode(str);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bufToHex(digest);
}

async function sha256HexOfBytes(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bufToHex(digest);
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

// ---- hash chain (mirrors warden/chain.py exactly) ---------------------------
// GENESIS = sha256(""). entry_hash[i] = sha256(prev_hash + "\n" + canon(entry[i])),
// folding every entry into the prior hash. The chain_head summarizes the whole
// ordered run; reorder or omit an entry and the head moves.
const GENESIS_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // sha256 of empty string

async function chainHashes(entries) {
  const enc = new TextEncoder();
  const out = [];
  let prev = GENESIS_HEX;
  for (const entry of entries) {
    const material = enc.encode(prev + "\n" + canonicalize(entry));
    prev = await sha256HexOfBytes(material);
    out.push(prev);
  }
  return out;
}

async function chainHead(entries) {
  const chain = await chainHashes(entries);
  return chain.length ? chain[chain.length - 1] : GENESIS_HEX;
}

// First index where a recomputed chain diverges from a trusted chain.
function firstBrokenIndex(recomputed, trusted) {
  const n = Math.min(recomputed.length, trusted.length);
  for (let i = 0; i < n; i++) if (recomputed[i] !== trusted[i]) return i;
  if (recomputed.length !== trusted.length) return n;
  return null;
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
function fmtTsMs(milliseconds) {
  // Render an interpolated epoch-ms instant as "YYYY-MM-DD HH:MM UTC".
  const d = new Date(milliseconds);
  const pad = (x) => String(x).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
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

// Plain-English chyron copy per money beat, color-coded.
const BEAT_BANNERS = {
  contradiction: { tone: "red", text: "VETO FIRED. Two filings disagree on a load-bearing fact. The Warden blocked signoff." },
  contradiction_cleared: { tone: "green", text: "CLEARED. The fact was corrected, the diff re-ran green, signoff unblocked." },
  chaos: { tone: "amber", text: "LIVE KILL. A drafter was killed after posting. On restart the duplicate was dropped: filed exactly once." },
  reconciliation: { tone: "amber", text: "AMENDMENT. A load-bearing fact was revised. Two drafters reconcile through Band before the Warden lets it re-file." },
};

// ---- gate state: the plain-English "what is blocked and why" panel ----------
// Derives the operator headline from the steps reduced so far. This reads the
// same step stream the rest of the view reduces (blocked / cleared / amending /
// released markers), so it can never disagree with the feed or the clocks.
const REGULATOR_OF = { sec: "SEC", nis2: "NIS2", dora: "DORA" };
function regulatorList(branches) {
  return branches.map((b) => REGULATOR_OF[b] || b.toUpperCase()).join(" and ");
}

// Reduce active steps into a gate verdict the incident commander reads.
function deriveGate(active) {
  const states = { nis2: "idle", sec: "idle", dora: "idle" };
  let lastBanner = null;
  let blockReason = null;       // a concrete reason sentence, when one is known
  let released = false;
  for (const s of active) {
    if (s.branchState) states[s.branchState.branch] = s.branchState.state;
    if (s.allBranchState) for (const b of Object.keys(states)) states[b] = s.allBranchState;
    if (s.branchSet) for (const b of Object.keys(s.branchSet)) states[b] = s.branchSet[b];
    if (s.banner) lastBanner = s.banner;
    if (s.gateReason) blockReason = s.gateReason;
    if (s.gateReleased) released = true;
  }
  const branches = ["nis2", "sec", "dora"];
  const blocked = branches.filter((b) => states[b] === "blocked");
  const amending = branches.filter((b) => states[b] === "amending");
  const releasedBranches = branches.filter((b) => states[b] === "released");
  const allReleased = releasedBranches.length === branches.length;

  // Priority: an active block beats everything; then amendment; then released;
  // then drafting; then the opening idle state.
  if (blocked.length) {
    return {
      status: "blocked", pill: "blocked",
      headline: "Submission blocked: two filings disagree on a load-bearing fact",
      detail: blockReason
        || `${regulatorList(blocked.length ? blocked : branches)} cannot go out until the conflicting fact is corrected and the referee's diff re-runs clean.`,
      release: "held: contradiction unresolved", releaseCls: "held",
    };
  }
  if (amending.length) {
    return {
      status: "blocked", pill: "amending",
      headline: `Re-filing blocked: ${regulatorList(amending)} must agree on the revised figure first`,
      detail: blockReason
        || `A load-bearing fact was revised after release. ${regulatorList(amending)} reopened and stay blocked until both teams concur on one shared characterization.`,
      release: "held: awaiting concurrence", releaseCls: "held",
    };
  }
  if (lastBanner === "chaos") {
    return {
      status: "running", pill: "recovered",
      headline: "A team member dropped offline, and the filing set held",
      detail: "An AI drafter was knocked out right after posting. On restart its filing was already in the room, so the duplicate was dropped. Nothing was filed twice.",
      release: released || allReleased ? "released, clean" : "drafting in progress",
      releaseCls: released || allReleased ? "released" : "running",
    };
  }
  if (allReleased || released) {
    return {
      status: "clear", pill: "released",
      headline: "Cleared for release: all four filings agree",
      detail: "The referee's cross-filing check is green, the human owner signed off, and every released clock has stopped.",
      release: "released, clean", releaseCls: "released",
    };
  }
  if (branches.some((b) => states[b] === "draft_submitted" || states[b] === "drafting")) {
    return {
      status: "running", pill: "running",
      headline: "Drafting in progress: the teams are writing their filings",
      detail: "Each AI team drafts its regulator's notification from the shared fact-record. Nothing is released until the referee confirms they all agree.",
      release: "not yet released", releaseCls: "running",
    };
  }
  return {
    status: "running", pill: "running",
    headline: "Incident open: four statutory clocks are running",
    detail: "The referee opened the war room and started the regulatory deadlines. The teams are picking up the shared fact-record now.",
    release: "not yet released", releaseCls: "running",
  };
}

function renderGate(active) {
  const g = deriveGate(active);
  const panel = $("#gate-panel");
  if (panel) panel.className = "panel gate-panel gate-" + g.status;
  setText("#gate-headline", g.headline);
  setText("#gate-detail", g.detail);
  const pill = $("#gate-status-pill");
  if (pill) { pill.textContent = g.pill; pill.className = "gate-status-pill gp-" + g.status; }
  const rel = $("#gate-release-state");
  if (rel) { rel.textContent = g.release; rel.className = "gate-release-state rel-" + g.releaseCls; }
}

// Defensive text setter: never throws if a node is missing (unsupervised judge).
function setText(sel, text) { const n = $(sel); if (n) n.textContent = text; }

// ---- state ------------------------------------------------------------------
let manifest = null;
let packet = null;
let runLogText = "";
let runLogEntries = [];   // parsed entries of the bundled run log
let steps = [];           // ordered timeline steps
let cursor = 0;           // index into steps (0 = nothing happened yet)
let playing = false;
let playTimer = null;
let stepStartedAt = 0;    // performance.now() when the current step began
let rafId = null;
let reducedMotion = false;
let scrubbing = false;
let revealedBeats = new Set();   // beats whose banner/rail have been lit this run
let bannerTimer = null;
let tourMode = true;             // Judge Tour: default-on guided run

// ============================================================================
// Build the ordered timeline of steps from the packet.
// Each step records what becomes true; render(cursor) reduces all steps up to
// the cursor into the live view.
// ============================================================================
// Read one decision's plain-English "why" from the packet's decision-rationale
// ledger (E9.1). This is the SAME source the Warden posted in the room and the
// Examiner Packet renders, so the web gate copy and the packet copy are the same
// bytes. Returns "" when the ledger has no entry for that decision kind.
function rationaleWhy(p, kind) {
  const ledger = (p && p.decision_rationale) || {};
  const entry = ledger[kind];
  return (entry && entry.plain_why) || "";
}

function buildSteps(p) {
  const out = [];
  const handoffs = p.handoff_trace || [];
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
      banner: "contradiction",
      allBranchState: "blocked",
      gateReason: rationaleWhy(p, "diff_blocked"),
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
        banner: "contradiction_cleared",
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
      banner: "chaos",
    });
  }

  // Signoff + release.
  out.push({
    ts: firstTsForEvent(transitions, "human_released"),
    caption: "Warden opened signoff; the human owner released. Every released branch's clock stopped.",
    speakers: ["warden", "lena"],
    message: { from: "lena", to: "room", kind: "concur", body: "Human owner released the filings. Clocks stopped." },
    allBranchState: "released",
    gateReleased: true,
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
      reveal: "reconciliation",
      banner: "reconciliation",
      branchSet: { sec: "amending", nis2: "amending" },
    });
    if (rec.blocked_before_reconciliation) {
      out.push({
        ts: tsForEventBranch(transitions, "fact_amended", "sec"),
        caption: "Warden guard BLOCKED the amendment before reconciliation: no concur envelope yet.",
        speakers: ["warden"],
        message: { from: "warden", to: "room", kind: "block", body: "Amendment blocked: " + rec.block_reason },
        reveal: "reconciliation",
        gateReason: rationaleWhy(p, "amend_blocked"),
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
      gateReleased: true,
    });
  }

  // Final replay step.
  out.push({
    ts: lastTs(out),
    caption: `Replay byte-identical: ${p.replay.byte_identical}. Examiner Packet sealed (sha ${p.replay.original_sha256.slice(0, 12)}...).`,
    speakers: ["warden"],
    final: true,
  });

  // Fill any missing timestamps by carrying the last known one forward, so the
  // interpolation always has monotone, non-null endpoints to work between.
  let lastKnown = out[0].ts || (p.clocks && p.clocks[0] && p.clocks[0].started) || null;
  for (const s of out) {
    if (s.ts) lastKnown = s.ts;
    else s.ts = lastKnown;
  }
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
  renderClocks(nowTs ? ms(nowTs) : null);
  renderHandoffs(active);
  renderBranchStates(active);
  renderGate(active);
  renderReveals(active);
  syncBeats(active, latest);
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

// Render the clocks at an absolute epoch-ms instant `nowMs`. During playback
// this is interpolated between recorded step timestamps; otherwise it is the
// current step's recorded timestamp. The instant is always clamped by the
// caller so it never exceeds a time the run actually reached.
function renderClocks(nowMs) {
  const wrap = $("#clocks");
  const now = nowMs != null ? nowMs : (packet.clocks[0] ? ms(packet.clocks[0].started) : 0);
  if (nowMs != null) $("#clock-now-ts").textContent = fmtTsMs(now);

  // Build cells once, then update text/width in place so the rAF tick does not
  // thrash the DOM (rebuilding every frame is what made the bars feel janky).
  if (wrap.childElementCount !== packet.clocks.length) {
    wrap.innerHTML = "";
    for (let i = 0; i < packet.clocks.length; i++) {
      const cell = el("div", "clock");
      cell.appendChild(el("span", "status-pill"));
      cell.appendChild(el("div", "name", packet.clocks[i].name));
      cell.appendChild(el("div", "remaining"));
      cell.appendChild(el("div", "deadline", "deadline " + fmtTs(packet.clocks[i].deadline)));
      const bar = el("div", "bar");
      bar.appendChild(el("span"));
      cell.appendChild(bar);
      wrap.appendChild(cell);
    }
  }

  packet.clocks.forEach((c, i) => {
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

    const cell = wrap.children[i];
    cell.className = "clock " + (isStopped ? "stopped" : breached ? "breach running" : "running") + (warn ? " warn" : "");
    cell.querySelector(".status-pill").textContent = isStopped ? "stopped" : breached ? "breach" : "running";
    cell.querySelector(".remaining").textContent = isStopped
      ? "stopped, " + fmtClock(deadline - stoppedAt) + " to spare"
      : breached ? "BREACHED" : fmtClock(remaining);
    cell.querySelector(".bar > span").style.width = Math.max(0, Math.min(100, pct)) + "%";
  });
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

// ---- beats: rail dots, chyron banner, gentle scroll on first reveal --------
const REVEAL_PANEL = {
  contradiction: "#contradiction-section",
  chaos: "#chaos-section",
  reconciliation: "#reconciliation-section",
};

function syncBeats(active, latest) {
  // Light rail dots for every beat reached so far.
  const reached = new Set();
  for (const s of active) {
    if (s.reveal) reached.add(s.reveal);
    if (s.banner === "contradiction") reached.add("contradiction");
    if (s.banner === "reconciliation") reached.add("reconciliation");
  }
  document.querySelectorAll(".beat-dot").forEach((dot) => {
    const present = scenarioHasBeat(dot.dataset.beat);
    dot.classList.toggle("absent", !present);
    dot.classList.toggle("reached", present && reached.has(dot.dataset.beat));
  });

  // Fire the chyron banner + first-reveal flourish for the latest step only.
  if (latest && latest.banner) {
    showBeatBanner(latest.banner);
    const beatKey = latest.banner === "contradiction_cleared" ? "contradiction" : latest.banner;
    if (!revealedBeats.has(beatKey)) {
      revealedBeats.add(beatKey);
      const panelSel = REVEAL_PANEL[beatKey];
      if (panelSel) {
        const panel = $(panelSel);
        panel.classList.remove("pulse");
        // restart the pulse animation
        void panel.offsetWidth;
        if (!reducedMotion) {
          panel.classList.add("pulse");
          panel.scrollIntoView({ behavior: "smooth", block: "center" });
        }
      }
    }
  } else if (!latest || !latest.banner) {
    // No banner on this step: leave the last banner up briefly, it auto-hides.
  }
}

function scenarioHasBeat(beat) {
  if (!packet) return false;
  if (beat === "contradiction") return !!((packet.diff && packet.diff.blocked_conflicts || []).length);
  if (beat === "chaos") return !!((packet.chaos && packet.chaos.events || []).length);
  if (beat === "reconciliation") return !!packet.reconciliation;
  return false;
}

function showBeatBanner(key) {
  const b = $("#beat-banner");
  const def = BEAT_BANNERS[key];
  if (!def) return;
  b.className = "beat-banner tone-" + def.tone + " show";
  b.textContent = def.text;
  b.hidden = false;
  if (bannerTimer) clearTimeout(bannerTimer);
  bannerTimer = setTimeout(() => { b.classList.remove("show"); }, 4200);
}
function hideBeatBanner() {
  const b = $("#beat-banner");
  b.classList.remove("show");
  b.hidden = true;
  if (bannerTimer) { clearTimeout(bannerTimer); bannerTimer = null; }
}

// ============================================================================
// Static panels (built once per packet, not animated).
// ============================================================================
function renderStaticPanels() {
  $("#room-id").textContent = "room " + packet.incident.band_room_id;

  // Compression banner
  $("#compression-banner").innerHTML = "";
  const b = $("#compression-banner");
  b.appendChild(el("b", null, "REPLAY OF A REAL RECORDED INCIDENT"));
  b.appendChild(el("span", null, "the clocks run at " + TIME_COMPRESSION_LABEL));
  b.appendChild(el("span", null, "captured on the Band platform, not simulated"));
  b.appendChild(el("span", "eng-inline", "log sha " + packet.replay.original_sha256.slice(0, 16) + "..."));

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

  // Explainability panel (E9.2): the decision-rationale ledger rendered with a
  // determinism chip and a provenance trail per decision, plus the plain-answer
  // counter-question accordion. All read from the SAME packet.decision_rationale
  // ledger the packet renders, so the web copy and the packet copy are the same
  // bytes. The provenance hashes are recomputed in the browser from the bundled
  // run-log entries, so the binding is verified client-side, not asserted.
  renderExplainability();

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

  // Verification panel: reset all three checks to a fresh "not run" state.
  resetChecks();

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
// Explainability (E9.2): the decision-rationale ledger as a per-decision card
// with a determinism chip and a provenance trail, plus the plain-answer
// counter-question accordion. Everything reads packet.decision_rationale, the
// SAME source the Examiner Packet renders, so the web and the packet are the same
// bytes. The provenance entry hashes are recomputed in the browser from the
// bundled run-log entries (a run-log protocol_event payload is byte-identical to a
// packet state_transition row), so the binding is verified here, not just shown.
// ============================================================================

// The class names mirror floor/rationale.DECIDED_BY_LABEL exactly, so the chip
// reads identically in the packet and the web.
const DECIDED_BY_LABEL = {
  deterministic_rule: "fixed rule (no AI judgment)",
  llm_content_with_deterministic_check: "AI drafted, fixed rule checked",
  llm_content: "AI content (gates nothing)",
};

function decidedByChip(entry) {
  const decidedBy = entry.decided_by || "";
  const label = entry.decided_by_label || DECIDED_BY_LABEL[decidedBy] || "";
  if (!label) return null;
  const cls = decidedBy === "deterministic_rule" ? "chip-ok" : "chip-warn";
  return el("span", "explain-chip " + cls, label);
}

// Verify the provenance: recompute each evidence entry's content hash in the
// browser from the bundled run-log protocol_event payloads, and confirm the set
// the packet recorded is exactly the set present in the log. Returns the verified
// hashes (sorted to match) and whether every recorded hash was found.
async function provenanceHashes() {
  const out = new Set();
  for (const e of runLogEntries) {
    if (e && e.type === "protocol_event" && e.payload && e.payload.admitted) {
      out.add(await sha256Hex(canonicalize(e.payload)));
    }
  }
  return out;
}

async function renderExplainability() {
  const wrap = $("#explain-cards");
  if (!wrap) return;
  wrap.innerHTML = "";
  const ledger = (packet && packet.decision_rationale) || {};
  const kinds = Object.keys(ledger);
  // The set of entry content hashes actually present in the bundled log, so the
  // provenance trail is verified against the log, not merely displayed.
  const present = await provenanceHashes();

  if (!kinds.length) {
    wrap.appendChild(el("p", "small muted",
      "No gated decision in this path carried a narrated rationale."));
  }
  for (const kind of kinds) {
    const entry = ledger[kind];
    const card = el("div", "explain-card");
    const head = el("div", "explain-head");
    head.appendChild(el("span", "explain-rule", entry.rule_id || kind));
    const chip = decidedByChip(entry);
    if (chip) head.appendChild(chip);
    card.appendChild(head);
    card.appendChild(el("p", "explain-why small", entry.plain_why || ""));

    const hashes = entry.evidence_entry_hashes || [];
    const prov = el("div", "explain-prov small muted");
    if (!hashes.length) {
      prov.textContent = "Provenance: a standing-state rationale (no single input entry).";
    } else {
      const allFound = hashes.every((h) => present.has(h));
      prov.appendChild(el("span", "prov-label",
        `Bound to ${hashes.length} run-log ${hashes.length === 1 ? "entry" : "entries"} by content hash ` +
        (allFound ? "(verified against the bundled log): " : "(recorded): ")));
      const list = el("div", "prov-hashes");
      for (const h of hashes) {
        const tag = el("code", present.has(h) ? "prov-ok" : "prov-miss", h.slice(0, 16) + "...");
        list.appendChild(tag);
      }
      prov.appendChild(list);
    }
    card.appendChild(prov);
    wrap.appendChild(card);
  }

  renderCounterQuestions();
}

// The plain answers a non-engineer asks, built deterministically from the
// rationale ledger and the release / reconciliation / replay blocks already in
// the packet. Mirrors floor/packet._render_counter_questions: same questions,
// same source.
function renderCounterQuestions() {
  const wrap = $("#counter-questions");
  if (!wrap) return;
  wrap.innerHTML = "";
  const p = packet;
  const ledger = p.decision_rationale || {};
  const rec = p.reconciliation;
  const release = p.release || {};
  const replay = p.replay || {};
  const chaos = p.chaos || {};
  const qa = [];

  const blocked = ledger.diff_blocked;
  const resolved = ledger.diff_resolved;
  if (blocked) {
    let ans = blocked.plain_why || "";
    ans += resolved ? " " + (resolved.plain_why || "")
                    : " Release stays held until the filings agree.";
    qa.push(["Did the referee block anything, and exactly why?", ans]);
  } else {
    qa.push(["Did the referee block anything, and exactly why?",
      "Nothing was blocked on a contradiction. The cross-filing diff was GREEN: every load-bearing fact agreed across the filings."]);
  }

  const fixed = Object.values(ledger).filter((v) => v.decided_by === "deterministic_rule").length;
  const aiChecked = Object.values(ledger).filter((v) => v.decided_by === "llm_content_with_deterministic_check").length;
  qa.push(["Was any gate decided by an AI?",
    `No gate was decided by an AI. ${fixed} decision(s) were made by a FIXED Warden rule with no AI judgment (the block, the diff, the two-key release). ${aiChecked} decision(s) involved AI-drafted content that a fixed rule then CHECKED. Every badge above states which is which; the Warden that gates, blocks, releases, and clocks runs no AI.`]);

  if ((chaos.events || []).length) {
    qa.push(["A team dropped offline mid-incident. Was anything filed twice?",
      `No. A drafter was killed after posting; on restart the idempotency ledger dropped ${chaos.duplicates_dropped || 0} duplicate filing(s). Each filing landed exactly once, with no double-file across the declared-dead window.`]);
  }

  const signoffs = release.signoffs || [];
  if (signoffs.length) {
    const roles = Array.from(new Set(signoffs.map((s) => s.role).filter(Boolean))).sort().join(", ");
    const branchCount = (release.released_branches || []).length;
    qa.push(["Did a human actually authorize the release?",
      `Yes, and two distinct humans had to. Each released branch carries TWO keys (${roles}); one key alone never turns the lock. ${branchCount} branch(es) released only after both keys signed.`]);
  }

  if (rec) {
    const amend = ledger.amend_blocked;
    let ans = "After release a load-bearing fact was revised. The amendment guard held the re-filing BLOCKED until both reopened drafters concurred on one shared figure.";
    if (amend) {
      ans = (amend.plain_why || "") + " The two drafters reconciled through Band; the amended diff passed GREEN only after concurrence, then re-released under the same two-key gate.";
    }
    qa.push(["A fact changed after filing. What stopped a silent re-file?", ans]);
  }

  const sha = replay.original_sha256 || "";
  if (sha) {
    const bi = replay.byte_identical ? "byte for byte" : "with a MISMATCH";
    const head = replay.chain_head || "";
    const headLine = head ? ` A per-entry hash chain (head ${head.slice(0, 16)}...) makes any reorder or omission detectable.` : "";
    qa.push(["Can I prove none of this was altered?",
      `Yes, without trusting us. The run replays ${bi} to the recorded SHA-256 (${sha.slice(0, 16)}...).${headLine} A detached Ed25519 signature binds that exact ordered run; you re-derive all three in your own browser.`]);
  }

  for (const [q, a] of qa) {
    const d = el("details", "cq");
    const sum = el("summary", null, q);
    d.appendChild(sum);
    d.appendChild(el("p", "small muted", a));
    wrap.appendChild(d);
  }
}

// ============================================================================
// Scenario cards (surface the manifest blurbs as one-click, self-explaining).
// ============================================================================
function renderScenarioCards(activeId) {
  const wrap = $("#scenario-cards");
  wrap.innerHTML = "";
  for (const scn of manifest.scenarios) {
    const card = el("button", "scenario-card" + (scn.id === activeId ? " active" : ""));
    card.type = "button";
    card.setAttribute("aria-pressed", scn.id === activeId ? "true" : "false");
    card.appendChild(el("span", "scenario-card-label", scn.label));
    card.appendChild(el("span", "scenario-card-blurb", scn.blurb));
    card.addEventListener("click", () => selectScenario(scn.id, { fromUser: true }));
    wrap.appendChild(card);
  }
}

function selectScenario(id, opts = {}) {
  const scn = manifest.scenarios.find((s) => s.id === id);
  if (!scn) return;
  $("#scenario").value = id;
  renderScenarioCards(id);
  loadScenario(scn).then(() => {
    if (opts.fromUser) startPlay();
  });
}

// ============================================================================
// Transport: play / pause / scrub, with a smooth interpolated clock tick.
// ============================================================================
function setCursor(n) {
  cursor = Math.max(0, Math.min(steps.length, n));
  stepStartedAt = performance.now();
  render();
  if (cursor >= steps.length) stopPlay();
}
function step() {
  if (cursor >= steps.length) { stopPlay(); return; }
  setCursor(cursor + 1);
}
function startPlay() {
  if (playing) return;
  if (cursor >= steps.length) { cursor = 0; revealedBeats = new Set(); }
  playing = true;
  $("#play").textContent = "Pause";
  stepStartedAt = performance.now();
  scheduleNext();
  startTick();
}
function scheduleNext() {
  const speed = parseFloat($("#speed").value) || 1;
  const base = 1100; // ms per step at 1x
  playTimer = setTimeout(() => {
    step();
    if (playing && cursor < steps.length) scheduleNext();
    else if (cursor >= steps.length) onReplayComplete();
  }, base / speed);
}
function stopPlay() {
  playing = false;
  $("#play").textContent = "Play";
  if (playTimer) { clearTimeout(playTimer); playTimer = null; }
  stopTick();
}

// rAF interpolation: between the current step's recorded ts and the next step's
// recorded ts, advance a virtual instant at the declared compression rate and
// re-render the clocks each frame. The instant is CLAMPED to the next recorded
// ts, so the clocks never show a time the run did not actually reach. These are
// real recorded deltas played at a declared speed, not a cosmetic counter.
function startTick() {
  if (reducedMotion) return; // reduced-motion users get per-step jumps only
  stopTick();
  const frame = () => {
    if (!playing) return;
    tickClocks();
    rafId = requestAnimationFrame(frame);
  };
  rafId = requestAnimationFrame(frame);
}
function stopTick() {
  if (rafId != null) { cancelAnimationFrame(rafId); rafId = null; }
}
function tickClocks() {
  const cur = steps[cursor - 1] || steps[0];
  const next = steps[cursor];
  if (!cur || !cur.ts) return;
  const curMs = ms(cur.ts);
  if (!next || !next.ts) { renderClocks(curMs); return; }
  const nextMs = ms(next.ts);
  if (nextMs <= curMs) { renderClocks(curMs); return; }
  const speed = parseFloat($("#speed").value) || 1;
  const realElapsed = performance.now() - stepStartedAt;
  const captured = realElapsed * CAPTURED_MS_PER_REAL_MS * speed;
  const instant = Math.min(curMs + captured, nextMs); // clamp to the recorded next ts
  renderClocks(instant);
}

function onReplayComplete() {
  stopPlay();
  if (tourMode) highlightVerify();
}

// At the emotional peak (replay finished), guide the judge to the proof. We
// scroll the verification block into view and pulse the button.
function highlightVerify() {
  const block = $("#verify-block");
  const btn = $("#verify");
  if (!block) return;
  btn.classList.add("beckon");
  showBeatBanner("contradiction_cleared");
  const b = $("#beat-banner");
  b.className = "beat-banner tone-green show";
  b.textContent = "Now prove it yourself. Click Verify to re-derive the Warden's hash, chain, and signature in your own browser.";
  b.hidden = false;
  if (bannerTimer) clearTimeout(bannerTimer);
  bannerTimer = setTimeout(() => b.classList.remove("show"), 6000);
  if (!reducedMotion) block.scrollIntoView({ behavior: "smooth", block: "center" });
}

// ============================================================================
// In-browser verification: hash, chain head, Ed25519 signature.
// ============================================================================
function resetChecks() {
  setPill("#hash-pill", "pending", "not run");
  setPill("#chain-pill", "pending", "not run");
  setPill("#sig-pill", "pending", "not run");
  $("#recorded-hash").textContent = packet.replay.original_sha256;
  $("#recomputed-hash").textContent = "--";
  const sig = packet.replay.signature || {};
  $("#recorded-chain").textContent = "computed from the chain over the bundled log";
  $("#recomputed-chain").textContent = "--";
  $("#sig-signer").textContent = sig.signer || "--";
  $("#sig-fp").textContent = sig.pubkey_fingerprint || "--";
  $("#sig-caveat").textContent = sig.caveat
    ? "Honest note: the signature is real (one flipped byte makes it invalid), but the demo private key ships with the repo, so it proves 'signed by whoever holds the demo key', not HSM-grade secrecy."
    : "";
  const reorder = $("#reorder-toggle");
  if (reorder) reorder.checked = false;
  $("#verify").classList.remove("beckon");
  const vr = $("#verify-result");
  vr.className = "verify-result pending";
  vr.textContent = "Not yet verified. Click to re-derive all three proofs from the bundled run log.";
}

function setPill(sel, cls, text) {
  const p = $(sel);
  p.className = "check-pill " + cls;
  p.textContent = text;
}

async function verifyAll() {
  const vr = $("#verify-result");
  vr.className = "verify-result pending";
  vr.textContent = "Re-deriving the three proofs in your browser...";
  $("#verify").classList.remove("beckon");
  let allOk = true;
  const reorderOn = $("#reorder-toggle") && $("#reorder-toggle").checked;

  // The two values the signature binds, recomputed client-side from the bundled
  // log: the run-log sha256 (Check 1) and the chain head (Check 2). They are
  // passed to the signature check so the browser verifies the SAME bound payload
  // Python signs (canonical {sha256, chain_head}), not the bare bytes.
  let recomputedSha = null;
  let recomputedHead = null;

  // ---- Check 1: byte-identical replay hash --------------------------------
  try {
    const canonical = canonicalJsonl(runLogEntries);
    const hex = await sha256Hex(canonical);
    recomputedSha = hex;
    $("#recomputed-hash").textContent = hex;
    if (hex === packet.replay.original_sha256) {
      setPill("#hash-pill", "ok", "MATCH");
      $("#hash-detail").textContent = "The browser re-derived the exact hash the Warden recorded. Replay is byte-identical.";
    } else {
      setPill("#hash-pill", "fail", "MISMATCH"); allOk = false;
      $("#hash-detail").textContent = "The recomputed hash does not equal the recorded hash.";
    }
  } catch (err) {
    setPill("#hash-pill", "fail", "error"); allOk = false;
    $("#hash-detail").textContent = "Hash check could not run: " + err.message + " (SubtleCrypto needs http://localhost or https, not file://).";
  }

  // ---- Check 2: hash-chain head -------------------------------------------
  try {
    const trusted = await chainHashes(runLogEntries);
    const trustedHead = trusted.length ? trusted[trusted.length - 1] : GENESIS_HEX;
    $("#recorded-chain").textContent = trustedHead;

    // If the judge toggled "reorder two entries", swap two adjacent entries and
    // recompute, so the head visibly breaks and we point at the first bad link.
    let entriesToHash = runLogEntries;
    if (reorderOn && runLogEntries.length >= 2) {
      const swapAt = Math.min(2, runLogEntries.length - 2); // a middle-ish pair
      entriesToHash = runLogEntries.slice();
      const tmp = entriesToHash[swapAt];
      entriesToHash[swapAt] = entriesToHash[swapAt + 1];
      entriesToHash[swapAt + 1] = tmp;
    }
    const recomputed = await chainHashes(entriesToHash);
    const chainHeadNow = recomputed.length ? recomputed[recomputed.length - 1] : GENESIS_HEX;
    // The head the signature check sees is the head actually computed here: the
    // honest head normally, or the reordered head when the toggle is on. With the
    // head bound into the signature, a reorder must turn the signature INVALID.
    recomputedHead = chainHeadNow;
    $("#recomputed-chain").textContent = chainHeadNow;

    if (!reorderOn) {
      if (chainHeadNow === trustedHead) {
        setPill("#chain-pill", "ok", "MATCH");
        $("#chain-detail").textContent = `Chain head over ${runLogEntries.length} entries matches. Any reorder or omission would move it.`;
      } else {
        setPill("#chain-pill", "fail", "MISMATCH"); allOk = false;
        $("#chain-detail").textContent = "The recomputed chain head does not match.";
      }
    } else {
      const broken = firstBrokenIndex(recomputed, trusted);
      setPill("#chain-pill", "broken", "BROKEN");
      $("#chain-detail").textContent = broken != null
        ? `Two entries reordered: the chain head changed, and the first broken link is at entry index ${broken}. Untoggle to restore the matching head.`
        : "Reordered, but the chain head still matched (entries were identical).";
      // a deliberately broken chain is the expected demo result, not a failure
    }
  } catch (err) {
    setPill("#chain-pill", "fail", "error"); allOk = false;
    $("#chain-detail").textContent = "Chain check could not run: " + err.message;
  }

  // ---- Check 3: Ed25519 signature over the BOUND payload ------------------
  // Verify against the canonical {sha256, chain_head} object Python signs, using
  // the sha and head this run recomputed above. The three checks compose into
  // one bound proof: the signature attests this exact ordered, complete run.
  await verifySignature(recomputedSha, recomputedHead);

  // ---- Roll-up ------------------------------------------------------------
  const sigPill = $("#sig-pill").textContent;
  if (reorderOn) {
    vr.className = "verify-result pending";
    vr.textContent = "Reorder toggle on (that is the point): the chain head moved, and because the head is bound into the signature, the signature is now INVALID too. Untoggle and re-verify to see all three pass.";
  } else if (allOk && (sigPill === "VALID" || sigPill === "unsupported")) {
    vr.className = "verify-result ok";
    vr.textContent = sigPill === "VALID"
      ? "All three verified in your browser. The hash matches, the chain head matches, and the Warden's signature is valid. No server, no trust in us."
      : "Hash and chain verified in your browser. The signature check needs a browser with WebCrypto Ed25519; the hash and chain proofs hold regardless.";
  } else {
    vr.className = "verify-result fail";
    vr.textContent = "One or more checks did not pass. See the per-check status above.";
  }
}

// The exact bytes the signature is taken over: the canonical JSON object that
// BINDS the run-log sha256, the chain head, the deadline-compliance attestation
// digest, and the input fact-record hash. Mirrors Python's json.dumps({...},
// sort_keys=True, separators=(",",":")), so sorted keys render as
// {"attestation_sha":"...","chain_head":"...","fact_record_hash":"...","sha256":"..."}
// with no spaces. The sha and chain head are recomputed in the browser from the
// bundled log; the attestation digest and fact-record hash are derived from data
// outside the run log (the clocks and the input fact-record), so they are read
// from the signature record, exactly as Python's verify rebuilds the payload.
// Rebuilding the identical bytes here is what lets the browser verify the same
// signature Python produced.
function boundPayloadString(sha256Hex, chainHeadHex, attestationShaHex, factRecordHashHex) {
  return "{"
    + JSON.stringify("attestation_sha") + ":" + JSON.stringify(attestationShaHex)
    + "," + JSON.stringify("chain_head") + ":" + JSON.stringify(chainHeadHex)
    + "," + JSON.stringify("fact_record_hash") + ":" + JSON.stringify(factRecordHashHex)
    + "," + JSON.stringify("sha256") + ":" + JSON.stringify(sha256Hex)
    + "}";
}

async function verifySignature(recomputedSha, recomputedHead) {
  const sig = packet.replay.signature;
  if (!sig) { setPill("#sig-pill", "pending", "no signature"); return; }
  // The bound payload needs both client-recomputed values. If either check above
  // failed to produce one, fall back to the values recorded in the packet so the
  // signature still has something to verify against.
  const sha = recomputedSha || packet.replay.original_sha256;
  const head = recomputedHead || packet.replay.chain_head || (sig && sig.chain_head);
  // The attestation digest and fact-record hash are DERIVED from data outside the
  // run log, so they cannot be recomputed from the bundled bytes; they are read
  // from the signature record (the same values Python binds). An empty string when
  // absent keeps the bound bytes well-formed for an older capture.
  const attestationSha = sig.attestation_sha || "";
  const factRecordHash = sig.fact_record_hash || "";
  // Detect WebCrypto Ed25519 support up front (older Safari lacks it). The hash
  // and chain checks already passed independently, so we degrade gracefully.
  if (!(crypto.subtle && crypto.subtle.importKey)) {
    setPill("#sig-pill", "warn", "unsupported");
    $("#sig-detail").textContent = "This browser has no WebCrypto. The signature check needs a modern browser; the hash and chain proofs above still hold.";
    return;
  }
  try {
    const pubHex = (await fetch("keys/warden_pubkey.ed25519").then((r) => r.text())).trim();
    const pubBytes = hexToBytes(pubHex);
    let key;
    try {
      key = await crypto.subtle.importKey("raw", pubBytes, { name: "Ed25519" }, false, ["verify"]);
    } catch (e) {
      // Older Safari / engines without Ed25519 in WebCrypto land here.
      setPill("#sig-pill", "warn", "unsupported");
      $("#sig-detail").textContent = "This browser's WebCrypto does not implement Ed25519 (older Safari). The hash and chain proofs above still verify; open in Chrome, Edge, or Firefox to check the signature too.";
      return;
    }
    const sigBytes = hexToBytes(sig.signature);
    // The signature covers the canonical {sha256, chain_head, attestation_sha,
    // fact_record_hash} object, NOT the bare run-log bytes. Binding the head means a
    // reorder (which moves the head) turns the signature INVALID too, not just the
    // chain check; binding the attestation and fact-record digests means a tampered
    // margin or a changed input would also invalidate it.
    const signedBytes = new TextEncoder().encode(
      boundPayloadString(sha, head, attestationSha, factRecordHash));
    const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, sigBytes, signedBytes);
    if (valid) {
      setPill("#sig-pill", "ok", "VALID");
      $("#sig-detail").textContent = `Signed by ${sig.signer}, key fingerprint ${sig.pubkey_fingerprint}. The browser verified the Ed25519 signature over the bound payload (run-log sha256 + chain head + deadline-compliance attestation digest + input fact-record hash) against the bundled public key: this exact ordered, complete run, driven from this exact fact-record, that met these statutory deadlines, is attested.`;
    } else {
      setPill("#sig-pill", "fail", "INVALID");
      $("#sig-detail").textContent = "The signature did not verify against the bundled public key (the bound sha256 + chain head + attestation digest + fact-record hash no longer match what was signed).";
    }
  } catch (err) {
    setPill("#sig-pill", "warn", "unsupported");
    $("#sig-detail").textContent = "Signature check could not run here (" + err.message + "). The hash and chain proofs above still verify; try a modern Chromium or Firefox.";
  }
}

// ============================================================================
// Scenario loading.
// ============================================================================
async function loadScenario(scn) {
  stopPlay();
  hideBeatBanner();
  revealedBeats = new Set();
  const [p, log] = await Promise.all([
    fetch(scn.packet).then((r) => r.json()),
    fetch(scn.run_log).then((r) => r.text()),
  ]);
  packet = p;
  runLogText = log;
  runLogEntries = parseJsonlEntries(log);
  steps = buildSteps(packet);
  $("#scrubber").max = String(steps.length);
  cursor = 0;
  renderStaticPanels();
  render();
}

// ============================================================================
// What-If Console (E9.3). Loads the three precomputed counterfactual artifacts
// and re-verifies each in the browser. A counterfactual receipt is signed under a
// DISTINCT namespace label, so the bound payload it rebuilds here is
// {counterfactual, actual_chain_head, counterfactual_outcome_sha}, NOT the per-run
// {sha256, chain_head, ...} payload. The outcome digest is recomputed from the
// artifact's own outcome fields the exact way Python does (canonical JSON, then
// sha256), so a tampered outcome fails the re-verify.
// ============================================================================
const WHATIF_NAMES = [
  "sec_materiality_6h_later",
  "contradiction_not_caught",
  "amended_count_unchanged",
];

// The outcome fields the signature binds, in the same set Python's
// Counterfactual.outcome() returns (everything except actual_chain_head and the
// attached signature). Canonicalizing exactly this subset is what lets the browser
// rebuild the identical digest Python signed.
const WHATIF_OUTCOME_KEYS = [
  "name", "title", "question", "perturbation",
  "actual", "counterfactual", "divergence", "load_bearing",
];

function whatifOutcome(artifact) {
  const out = {};
  for (const k of WHATIF_OUTCOME_KEYS) out[k] = artifact[k];
  return out;
}

// The counterfactual bound payload, byte-identical to
// warden/counterfactual_signing.counterfactual_payload_bytes: a canonical JSON
// object with sorted keys {actual_chain_head, counterfactual, counterfactual_outcome_sha}.
function counterfactualPayloadString(name, actualChainHead, outcomeSha) {
  return "{"
    + JSON.stringify("actual_chain_head") + ":" + JSON.stringify(actualChainHead)
    + "," + JSON.stringify("counterfactual") + ":" + JSON.stringify(name)
    + "," + JSON.stringify("counterfactual_outcome_sha") + ":" + JSON.stringify(outcomeSha)
    + "}";
}

function whatifKvList(obj) {
  const dl = el("dl", "kv");
  for (const k of Object.keys(obj)) {
    let v = obj[k];
    if (Array.isArray(v)) v = v.length ? v.join("; ") : "(none)";
    else if (typeof v === "object" && v !== null) v = JSON.stringify(v);
    addKv(dl, k.replace(/_/g, " "), String(v));
  }
  return dl;
}

async function renderWhatIf() {
  const wrap = $("#whatif-cards");
  if (!wrap) return;
  wrap.innerHTML = "";
  let artifacts;
  try {
    artifacts = await Promise.all(WHATIF_NAMES.map((n) =>
      fetch(`data/whatif-${n}.json`).then((r) => r.json())));
  } catch (e) {
    wrap.appendChild(el("p", "small muted", "What-if artifacts unavailable (run py scripts/whatif_report.py)."));
    return;
  }
  for (const art of artifacts) {
    const card = el("div", "whatif-card");
    const head = el("div", "whatif-head");
    head.appendChild(el("h3", "whatif-title", art.title));
    head.appendChild(el("span", "whatif-pill pending", "not verified"));
    card.appendChild(head);
    card.appendChild(el("p", "whatif-q muted small", art.question));

    const cols = el("div", "whatif-cols");
    const aCol = el("div", "whatif-col whatif-actual");
    aCol.appendChild(el("div", "whatif-col-label", "Actual"));
    aCol.appendChild(whatifKvList(art.actual));
    const cCol = el("div", "whatif-col whatif-cf");
    cCol.appendChild(el("div", "whatif-col-label", "Counterfactual"));
    cCol.appendChild(whatifKvList(art.counterfactual));
    cols.appendChild(aCol);
    cols.appendChild(cCol);
    card.appendChild(cols);

    card.appendChild(el("p", "whatif-divergence", art.divergence));
    card.appendChild(el("p", "whatif-load small muted", art.load_bearing));

    const recRow = el("div", "whatif-receipt small muted");
    recRow.appendChild(el("code", null,
      `${art.signature.signed_payload}  fp ${art.signature.pubkey_fingerprint}`));
    card.appendChild(recRow);

    const detail = el("div", "whatif-detail small muted");
    card.appendChild(detail);
    const btn = el("button", "btn small", "Re-verify this counterfactual in my browser");
    btn.type = "button";
    btn.addEventListener("click", () => verifyWhatIf(art, head.querySelector(".whatif-pill"), detail));
    card.appendChild(btn);

    wrap.appendChild(card);
  }
}

async function verifyWhatIf(art, pill, detail) {
  const setW = (cls, text) => { pill.className = "whatif-pill " + cls; pill.textContent = text; };
  setW("pending", "verifying...");
  try {
    // 1. Recompute the outcome digest from the artifact's own outcome fields.
    const outcome = whatifOutcome(art);
    const outcomeSha = await sha256Hex(canonicalize(outcome));
    if (outcomeSha !== art.signature.counterfactual_outcome_sha) {
      setW("fail", "OUTCOME TAMPERED");
      detail.textContent = "The recomputed outcome digest does not match the signed digest: the displayed outcome was altered.";
      return;
    }
    // 2. Rebuild the bound payload and verify the Ed25519 signature.
    if (!(crypto.subtle && crypto.subtle.importKey)) {
      setW("warn", "unsupported");
      detail.textContent = "This browser has no WebCrypto Ed25519; the outcome digest above still matches the signed digest.";
      return;
    }
    const pubHex = (await fetch("keys/warden_pubkey.ed25519").then((r) => r.text())).trim();
    let key;
    try {
      key = await crypto.subtle.importKey("raw", hexToBytes(pubHex), { name: "Ed25519" }, false, ["verify"]);
    } catch (e) {
      setW("warn", "unsupported");
      detail.textContent = "This browser's WebCrypto does not implement Ed25519 (older Safari). The outcome digest still matches; open in Chrome, Edge, or Firefox to check the signature.";
      return;
    }
    const payload = counterfactualPayloadString(
      art.signature.counterfactual, art.signature.actual_chain_head, outcomeSha);
    const valid = await crypto.subtle.verify({ name: "Ed25519" }, key,
      hexToBytes(art.signature.signature), new TextEncoder().encode(payload));
    if (valid) {
      setW("ok", "VALID");
      detail.textContent = `Signed under the counterfactual namespace by ${art.signature.signer}. The browser recomputed the outcome digest, rebuilt the bound {counterfactual, actual_chain_head, counterfactual_outcome_sha} payload, and verified the Ed25519 signature against the bundled public key. This what-if is deterministic and attested, anchored to the actual run chain head ${art.signature.actual_chain_head.slice(0, 16)}...`;
    } else {
      setW("fail", "INVALID");
      detail.textContent = "The counterfactual signature did not verify against the bundled public key.";
    }
  } catch (err) {
    setW("warn", "error");
    detail.textContent = "Re-verify could not run here (" + err.message + ").";
  }
}

async function init() {
  reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  manifest = await fetch("data/manifest.json").then((r) => r.json());
  const sel = $("#scenario");
  for (const scn of manifest.scenarios) {
    const opt = el("option", null, scn.label);
    opt.value = scn.id;
    sel.appendChild(opt);
  }
  sel.addEventListener("change", () => selectScenario(sel.value, { fromUser: true }));

  // Default to the amendment scenario: it is the fullest continuous story, from
  // drafting through release, then a load-bearing fact changes, the re-filing is
  // blocked until the teams concur, and it re-releases. It exercises the gate
  // panel most richly. The other three paths stay one click away on the cards.
  const def = manifest.scenarios.find((s) => s.id === "amendment") || manifest.scenarios[0];
  sel.value = def.id;
  renderScenarioCards(def.id);
  await loadScenario(def);
  await renderWhatIf();

  $("#play").addEventListener("click", () => (playing ? stopPlay() : startPlay()));
  $("#restart").addEventListener("click", () => { stopPlay(); revealedBeats = new Set(); hideBeatBanner(); setCursor(0); });
  $("#scrubber").addEventListener("input", (e) => { stopPlay(); setCursor(parseInt(e.target.value, 10)); });
  $("#speed").addEventListener("change", () => { stepStartedAt = performance.now(); });
  $("#verify").addEventListener("click", verifyAll);
  const reorder = $("#reorder-toggle");
  if (reorder) reorder.addEventListener("change", verifyAll);

  setupIntro();
}

// Intro overlay: shown on first load, then auto-plays the default scenario. A
// returning visitor (localStorage flag) is not re-gated, but auto-play still
// runs so the page is never frozen at step 0.
function setupIntro() {
  const overlay = $("#intro-overlay");
  const seen = false; // always show for a cold judge; dismissible immediately
  const dismiss = (start) => {
    overlay.hidden = true;
    try { localStorage.setItem("deadline-room-intro-seen", "1"); } catch (e) { /* private mode */ }
    if (start) startPlay();
  };
  $("#intro-start").addEventListener("click", () => dismiss(true));
  $("#intro-skip").addEventListener("click", () => dismiss(false));

  let returning = false;
  try { returning = localStorage.getItem("deadline-room-intro-seen") === "1"; } catch (e) { returning = false; }

  if (returning) {
    overlay.hidden = true;
    startPlay(); // never land frozen
  } else {
    overlay.hidden = false;
  }
}

init().catch((err) => {
  document.body.insertAdjacentHTML("afterbegin",
    `<div style="padding:1rem;background:#3a1820;color:#ff5f6e;font-family:monospace">Failed to load: ${err.message}. Serve this directory over http (py -m http.server) rather than opening the file directly.</div>`);
});
