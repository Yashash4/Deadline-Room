// The approve-and-release screen: a front end over the REAL two-key release gate.
//
// This script collects two distinct human sign-offs and asks the server, which
// holds the unchanged warden.release_gate.TwoKeyReleaseGate, whether a branch may
// release. It NEVER decides release in the browser: every released/withheld verdict
// rendered here is exactly what the gate returned. The browser only posts a
// sign-off and re-renders the gate's own decision, so the two-key invariant that
// guards warden/release_gate.py guards this screen too.

const $ = (id) => document.getElementById(id);

const ROLE_LABELS = {
  head_of_ir: "Head of Investor Relations",
  general_counsel: "General Counsel",
};

function render(state) {
  const released = state.released;
  $("lock").innerHTML = released ? "&#128275;" : "&#128274;"; // open vs closed padlock
  const pill = $("state-pill");
  pill.textContent = released ? "released" : "withheld";
  pill.className = "pill " + (released ? "released" : "withheld");
  $("reason").textContent = state.reason;

  const have = new Set(state.have_roles);
  const keys = $("keys");
  keys.innerHTML = "";
  for (const role of state.required_roles) {
    const li = document.createElement("li");
    const present = have.has(role);
    const who = (state.signoffs.find((s) => s.role === role) || {}).actor;
    li.innerHTML =
      `<span>${ROLE_LABELS[role] || role}</span>` +
      `<span class="key-state ${present ? "key-have" : "key-missing"}">` +
      (present ? `signed by ${who}` : "key not yet present") +
      `</span>`;
    keys.appendChild(li);
  }
}

async function loadState(branch) {
  const res = await fetch(`/api/release/${encodeURIComponent(branch)}`);
  if (!res.ok) throw new Error(`gate read failed (${res.status})`);
  return res.json();
}

async function sign() {
  $("err").textContent = "";
  const branch = $("branch").value.trim();
  const role = $("role").value;
  const actor = $("actor").value.trim();
  if (!branch) { $("err").textContent = "Enter a filing branch."; return; }
  if (!actor) { $("err").textContent = "Enter your name to sign."; return; }
  const body = {
    correlation_id: branch,
    role,
    actor,
    ts: new Date().toISOString(),
  };
  const res = await fetch("/api/release/signoff", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    $("err").textContent = detail.detail || `sign-off refused (${res.status})`;
    return;
  }
  render(await res.json());
}

async function resetBranch() {
  $("err").textContent = "";
  const branch = $("branch").value.trim();
  if (!branch) { $("err").textContent = "Enter a filing branch."; return; }
  const res = await fetch(`/api/release/reset/${encodeURIComponent(branch)}`, {
    method: "POST",
  });
  if (!res.ok) { $("err").textContent = `reset failed (${res.status})`; return; }
  render(await res.json());
}

async function refresh() {
  $("err").textContent = "";
  const branch = $("branch").value.trim();
  if (!branch) return;
  try {
    render(await loadState(branch));
  } catch (e) {
    $("err").textContent = String(e.message || e);
  }
}

$("sign").addEventListener("click", sign);
$("reset").addEventListener("click", resetBranch);
$("branch").addEventListener("change", refresh);
refresh();
