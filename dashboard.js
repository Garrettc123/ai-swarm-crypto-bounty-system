"use strict";
const element = id => document.getElementById(id);
let rows = [];
function node(tag, value, klass) {
  const e = document.createElement(tag);
  e.textContent = value == null ? "" : String(value);
  if (klass) e.className = klass;
  return e;
}
function render() {
  const search = element("search").value.trim().toLowerCase();
  const skill = element("skill").value;
  const minimum = Number(element("minimum").value);
  const filtered = rows.filter(row => {
    const haystack = String(row.title || "").toLowerCase() + " " +
                     String(row.repository || "").toLowerCase();
    return haystack.includes(search) &&
      (!skill || (row.matched_keywords || []).includes(skill)) &&
      Number(row.priority_score || 0) >= minimum;
  });
  const target = element("candidates");
  target.replaceChildren();
  element("shown").textContent = String(filtered.length) + " showing / " +
    String(rows.length) + " indexed; not confirmed paid opportunities";
  if (!filtered.length) {
    target.append(node("div", rows.length ?
      "No candidates match these filters." :
      "No candidates are currently indexed. This is not proof that no bounties exist.",
      "placeholder"));
    return;
  }
  for (const row of filtered) {
    const card = node("article", "", "candidate");
    const left = node("div", "");
    left.append(node("span", row.repository || "Unknown repository", "repo"));
    left.append(node("h3", row.title || "Untitled issue"));
    for (const skillName of (row.matched_keywords || [])) {
      left.append(node("span", skillName, "tag"));
    }
    left.append(node("span", "Reward unverified", "tag warn"));
    if (row.status === "blocked_for_review") {
      left.append(node("span", "BLOCKED FOR REVIEW · DO NOT CLAIM", "tag warn"));
    }
    if (row.possibly_mirrored) left.append(node("span", "Possible mirror", "tag warn"));
    if (row.source_stale) left.append(node("span", "Stale observation", "tag warn"));
    left.append(node("p", (row.priority_reasons || []).join(" · "), "reason"));
    const right = node("div", "", "actions");
    const scoreWrap = node("div", "");
    scoreWrap.append(node("div", row.priority_score ?? "—", "score"));
    scoreWrap.append(node("span", "REVIEW PRIORITY / 100", "score-label"));
    right.append(scoreWrap);
    try {
      const url = new URL(row.url);
      if (url.protocol === "https:" && url.hostname === "github.com" &&
          !url.username && !url.password) {
        const link = node("a", "Review source", "source-link");
        link.href = url.href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        right.append(link);
      }
    } catch (_) {
      // Untrusted malformed URLs never become clickable.
    }
    card.append(left, right);
    target.append(card);
  }
}
async function load() {
  element("refresh").disabled = true;
  try {
    const [stateResponse, issuesResponse] = await Promise.all([
      fetch("/status", {cache: "no-store"}),
      fetch("/bounties?limit=100", {cache: "no-store"})
    ]);
    if (!stateResponse.ok || !issuesResponse.ok) throw Error("Bad source response");
    const status = await stateResponse.json();
    const payload = await issuesResponse.json();
    rows = Array.isArray(payload.items) ? payload.items : [];
    element("count").textContent = String(status.candidate_count ?? "—");
    element("source").textContent = String(status.scan_state || "unknown").toUpperCase();
    element("updated").textContent = status.last_success_at
      ? "Last response: " + new Date(status.last_success_at).toLocaleString()
      : "No successful source response yet";
    element("receipts").textContent = status.receipt_chain_valid ? "INTACT" : "CHECK";
    element("health").textContent = status.scan_state === "ok"
      ? "Source search succeeded; review eligibility independently"
      : "Source degraded or initializing; do not rely on freshness";
    element("errors").textContent = (status.source_errors || []).length
      ? String(status.source_errors.length) + " source query error(s). Details: Sources."
      : "No query errors were reported for the last scan.";
    const delta = status.last_changes || {};
    element("changes").textContent = "Scan changes: " +
      String(delta.new_candidates ?? 0) + " newly observed, " +
      String(delta.still_listed ?? 0) + " retained, " +
      String(delta.no_longer_listed ?? 0) + " no longer listed. " +
      "Disappearance does not mean the task was completed or paid.";
    render();
  } catch (_) {
    element("health").textContent = "Service unavailable or response invalid";
    element("source").textContent = "ERROR";
    element("shown").textContent = "Unable to load live candidate data.";
    element("candidates").replaceChildren(node("div",
      "No current source response. Do not act on stale browser data.", "placeholder"));
  } finally {
    element("refresh").disabled = false;
  }
}
for (const id of ["search", "skill", "minimum"]) {
  element(id).addEventListener("input", render);
}
element("refresh").addEventListener("click", load);
load();
setInterval(load, 90000);
