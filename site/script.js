/* Dietrich · Instrument Workbench — simulation logic.
   Every action is simulated against sanitized fixtures; nothing is
   read, written, or sent anywhere. Mirrors the real app copy style. */

const fixtures = {
  soft: {
    name: "board_report.xlsx",
    kind: "XLSX",
    sub: "worksheet locks",
    dot: "warn",
    heading: "Soft structure locks",
    pill: "3 flags set",
    state: "info",
    signed: "no",
    lede: "3 structure locks across 2 kinds (worksheet, workbook). These are application flags — not encryption.",
    findings: [
      ["Soft hits", "2 worksheet · 1 workbook", "warn"],
      ["Open password", "Not required", "ok"],
      ["Signed", "No", "ok"],
      ["IRM / Purview", "None detected", "ok"],
      ["Format", "Excel workbook (OOXML)", "neutral"],
    ],
    next: "Unlock a side-by-side working copy. The original stays unchanged.",
    unlock: "Removed 3 soft-protection flags → board_report_unprotected.xlsx",
    unlockFindings: [
      ["Removed", "2 worksheet · 1 workbook", "ok"],
      ["Format", "Excel workbook (OOXML)", "neutral"],
    ],
    export: "No password hash is available for soft protection.",
  },
  signed: {
    name: "signed_budget.xlsx",
    kind: "XLSX",
    sub: "signed package",
    dot: "lock",
    heading: "Digitally signed package",
    pill: "Signature parts",
    state: "warning",
    signed: "yes",
    lede: "Signature parts detected. Unlock fails closed unless signature stripping is explicitly enabled.",
    findings: [
      ["Soft hits", "None", "ok"],
      ["Open password", "Not required", "ok"],
      ["Signed", "Yes", "warn"],
      ["IRM / Purview", "None detected", "ok"],
      ["Format", "Excel workbook (OOXML)", "neutral"],
    ],
    next: 'Enable "Strip signatures" in Advanced for an unsigned working copy.',
    unlock: "Unsigned working copy → signed_budget_unprotected.xlsx",
    unlockFindings: [
      ["Signatures", "Stripped (unsigned copy)", "warn"],
      ["Format", "Excel workbook (OOXML)", "neutral"],
    ],
    export: "No password hash is available for a signed package.",
  },
  encrypted: {
    name: "vault_notes.xlsx",
    kind: "XLSX",
    sub: "open password",
    dot: "lock",
    heading: "Open password required",
    pill: "Encrypted",
    state: "warning",
    signed: "unknown",
    lede: "Agile open-password encryption. Soft-only mode will fail on this file.",
    findings: [
      ["Open password", "Required (agile)", "signal"],
      ["Encryption cost", "spin=100000 · high", "warn"],
      ["Hashcat mode", "9600", "neutral"],
      ["IRM / Purview", "None detected", "ok"],
      ["Format", "Encrypted Office file", "neutral"],
    ],
    next: "Enter a password in Advanced, or provide a wordlist / mask for bounded local recovery.",
    unlock: "Password recovery would run locally with explicit candidate limits",
    unlockFindings: [
      ["Recovery", "Bounded · ≤ 5,000,000 candidates", "neutral"],
      ["Hashcat mode", "9600", "neutral"],
    ],
    export: "A mode-9600 hash record would be available in the Python application",
  },
  pdf: {
    name: "permissions.pdf",
    kind: "PDF",
    sub: "owner restrictions",
    dot: "warn",
    heading: "PDF owner restrictions",
    pill: "2 restrictions",
    state: "info",
    signed: "no",
    lede: "Printing and editing permissions are restricted. This is not the same as open encryption.",
    findings: [
      ["Owner restrictions", "Printing · editing", "warn"],
      ["Open password", "Not required", "ok"],
      ["Signed", "No", "ok"],
      ["IRM / Purview", "None detected", "ok"],
      ["Format", "PDF", "neutral"],
    ],
    next: "Unlock strips restrictions into a side-by-side copy when the file is openable.",
    unlock: "Stripped 2 permission restrictions → permissions_unprotected.pdf",
    unlockFindings: [
      ["Removed", "Printing · editing restrictions", "ok"],
      ["Format", "PDF", "neutral"],
    ],
    export: "Hash export is not needed for this openable PDF fixture.",
  },
};

const $ = (s) => document.querySelector(s);
let selected = "soft";
let busy = false;
let operationFocus = null;
let tick = 0;

const SIM_DELAY = 550;

function outputName(name) {
  const dot = name.lastIndexOf(".");
  return `${name.slice(0, dot)}_unprotected${name.slice(dot)}`;
}

function timestamp() {
  tick += 1;
  return `00:00:${String(tick).padStart(2, "0")}`;
}

function log(message, tone = "muted") {
  const item = document.createElement("li");
  item.className = `log-entry log-entry--${tone}`;
  const time = document.createElement("time");
  time.textContent = timestamp();
  const text = document.createElement("span");
  text.textContent = message;
  item.append(time, text);
  $("#activity-log").append(item);
  item.scrollIntoView({ block: "nearest" });
}

function setBusy(on) {
  if (on && !busy) operationFocus = document.activeElement;
  busy = on;
  $("#session-state").textContent = on ? "Working" : "Ready";
  $("#session-state").classList.toggle("is-busy", on);
  $("#rail-status").textContent = on ? "Working · no network" : "Ready · no network";
  $("#dossier").classList.toggle("is-busy", on);
  document.querySelectorAll(".fixture, input, #inspect, #unlock, #export, #reset").forEach((control) => { control.disabled = on; });
  $("#dossier").setAttribute("aria-busy", String(on));
  if (!on) {
    const previous = operationFocus;
    operationFocus = null;
    if (document.activeElement === document.body && previous?.isConnected && !previous.disabled) {
      previous.focus({ preventScroll: true });
    }
  }
}

function renderDossier({ pill, heading, lede, findings, next, state, signed }) {
  const dossier = $("#dossier");
  dossier.dataset.state = state;
  $("#status-pill").textContent = pill;
  $("#dossier-heading").textContent = heading;
  $("#dossier-lede").textContent = lede;
  $("#meta-signed").textContent = signed;
  $("#meta-irm").textContent = "active";

  const grid = $("#findings");
  grid.replaceChildren();
  if (findings && findings.length) {
    for (const [label, value, tone] of findings) {
      const cell = document.createElement("div");
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = value;
      dd.dataset.tone = tone;
      cell.append(dt, dd);
      grid.append(cell);
    }
    grid.hidden = false;
  } else {
    grid.hidden = true;
  }
  $("#next-step-text").textContent = next;
}

function renderFixtures() {
  const list = $("#fixture-list");
  list.replaceChildren();
  for (const [key, f] of Object.entries(fixtures)) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "fixture";
    btn.dataset.fixture = key;
    btn.setAttribute("aria-pressed", String(key === selected));

    const name = document.createElement("span");
    name.className = "fixture-name";
    name.textContent = f.name;

    const status = document.createElement("span");
    status.className = "fixture-status";
    const dot = document.createElement("span");
    dot.className = `dot dot--${f.dot}`;
    dot.setAttribute("aria-hidden", "true");
    status.append(dot);

    const sub = document.createElement("span");
    sub.className = "fixture-sub";
    sub.textContent = f.sub;

    btn.append(name, status, sub);
    btn.addEventListener("click", () => selectFixture(key));
    list.append(btn);
  }
}

function selectFixture(key, announce = true) {
  if (busy) return;
  selected = key;
  const f = fixtures[key];
  document.querySelectorAll(".fixture").forEach((btn) =>
    btn.setAttribute("aria-pressed", String(btn.dataset.fixture === key))
  );
  $("#input-path").textContent = `fixtures/${f.name}`;
  $("#output-path").textContent = `fixtures/${outputName(f.name)}`;
  $("#file-kind").textContent = f.kind;
  renderDossier({
    pill: "Idle",
    heading: "Ready to inspect",
    lede: "Sanitized fixture selected. No file has been opened.",
    findings: null,
    next: "Run the simulated inspection.",
    state: "idle",
    signed: "—",
  });
  if (announce) log(`fixture selected · ${f.name} · no file opened`);
}

function simulate(action, run) {
  if (busy) return;
  setBusy(true);
  log(`${action} · simulating fixture result…`);
  window.setTimeout(() => {
    setBusy(false);
    run();
  }, SIM_DELAY);
}

function inspect() {
  const f = fixtures[selected];
  simulate("inspect", () => {
    renderDossier({
      pill: f.pill,
      heading: f.heading,
      lede: f.lede,
      findings: f.findings,
      next: f.next,
      state: f.state,
      signed: f.signed,
    });
    log(`inspect ok · ${f.name} · simulated, no command run`, "muted");
  });
}

function unlock() {
  if (busy) return;
  const f = fixtures[selected];
  if (selected === "signed" && !$("#strip-signatures").checked) {
    renderDossier({
      pill: "Blocked",
      heading: "Option required",
      lede: "This signed fixture fails closed. Enable “Strip signatures” in Advanced to continue the simulation.",
      findings: f.findings,
      next: "Open Advanced and enable Strip signatures.",
      state: "error",
      signed: f.signed,
    });
    log("unlock blocked · strip signatures not enabled · no command run", "error");
    return;
  }
  simulate("unlock", () => {
    renderDossier({
      pill: "Working copy",
      heading: "Simulated unlock complete",
      lede: `${f.unlock}. No file was created or changed.`,
      findings: f.unlockFindings,
      next: "Working copy would sit side-by-side; original unchanged.",
      state: "ok",
      signed: f.signed,
    });
    log(`unlock ok · ${outputName(f.name)} · simulated, no command run`, "ok");
  });
}

function exportHash() {
  const f = fixtures[selected];
  simulate("export hash", () => {
    renderDossier({
      pill: "Hash export",
      heading: "Simulated hash export",
      lede: `${f.export}. No hash was generated or downloaded.`,
      findings: selected === "encrypted" ? f.findings : null,
      next: "The real CLI prints a hash line; this demo generates and saves nothing.",
      state: selected === "encrypted" ? "ok" : "idle",
      signed: f.signed,
    });
    log(`export · ${f.export}`, selected === "encrypted" ? "ok" : "muted");
  });
}

function reset() {
  if (busy) return;
  tick = 0;
  document.querySelectorAll("input").forEach((input) => {
    if (input.type === "checkbox") input.checked = input.defaultChecked;
    else input.value = input.defaultValue;
  });
  $("#advanced").open = false;
  $("#activity-log").replaceChildren();
  log("demo reset · fixture data only · no commands run");
  selectFixture("soft", false);
}

function help() {
  const dialog = $("#help");
  if (typeof dialog.showModal === "function") dialog.showModal();
}

const keyboardActions = new Map([
  ["i", inspect],
  ["u", unlock],
  ["e", exportHash],
  ["r", reset],
  ["?", help],
]);

document.addEventListener("keydown", (event) => {
  if ([event.altKey, event.ctrlKey, event.metaKey].some(Boolean)) return;
  if (event.target.matches("input, summary, textarea")) return;
  if ($("#help").open) return;
  const action = keyboardActions.get(event.key.toLowerCase()) ?? (event.key === "?" ? help : null);
  if (action) {
    event.preventDefault();
    action();
  }
});

$("#inspect").addEventListener("click", inspect);
$("#unlock").addEventListener("click", unlock);
$("#export").addEventListener("click", exportHash);
$("#reset").addEventListener("click", reset);

renderFixtures();
selectFixture("soft", false);
