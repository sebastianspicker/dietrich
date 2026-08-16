const fixtures = {
  soft: {
    name: "board_report.xlsx",
    kind: "XLSX",
    heading: "STRUCTURE LOCKS FOUND",
    meta: "SIGNED  NO\nIRM GATE  CLEAR",
    state: "ok",
    body: "Format · Excel workbook (OOXML)\nProtection · 2 worksheet locks · 1 workbook lock\nNext · Unlock a side-by-side working copy.",
    unlock: "simulated result · would remove 3 soft-protection flags from a working copy",
    export: "simulated result · no password hash is available for soft protection",
  },
  signed: {
    name: "signed_budget.xlsx",
    kind: "XLSX",
    heading: "SIGNED PACKAGE",
    meta: "SIGNED  YES\nIRM GATE  CLEAR",
    state: "warning",
    body: "Format · Excel workbook (OOXML)\nProtection · digital signature parts detected\nNext · Enable Strip signatures to simulate an unsigned working copy.",
    unlock: "simulated result · would create an unsigned side-by-side working copy",
    export: "simulated result · no password hash is available for a signed package",
  },
  encrypted: {
    name: "vault_notes.xlsx",
    kind: "XLSX",
    heading: "OPEN PASSWORD REQUIRED",
    meta: "SIGNED  UNKNOWN\nIRM GATE  CLEAR",
    state: "warning",
    body: "Format · Encrypted Office file\nEncryption · Agile open-password protection · hashcat mode 9600\nNext · A real run would require an explicit password or bounded recovery method.",
    unlock: "simulated result · password recovery would run locally with explicit limits",
    export: "simulated result · would export a sanitized mode-9600 hash record locally",
  },
  pdf: {
    name: "permissions.pdf",
    kind: "PDF",
    heading: "OWNER RESTRICTIONS FOUND",
    meta: "SIGNED  NO\nIRM GATE  CLEAR",
    state: "ok",
    body: "Format · PDF\nProtection · printing and editing permissions restricted\nNext · Unlock would write an unencrypted side-by-side copy when authorized.",
    unlock: "simulated result · would strip PDF permission restrictions from a working copy",
    export: "simulated result · hash export is not needed for this openable PDF fixture",
  },
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
let selected = "soft";
let tick = 0;
const fixtureMap = new Map(Object.entries(fixtures));

function fixtureFor(key) {
  return fixtureMap.get(key) ?? fixtures.soft;
}

function outputName(name) {
  const dot = name.lastIndexOf(".");
  return `${name.slice(0, dot)}_unprotected${name.slice(dot)}`;
}

function timestamp() {
  tick += 1;
  return `00:00:${String(tick).padStart(2, "0")}`;
}

function log(message) {
  const item = document.createElement("li");
  const time = document.createElement("time");
  time.textContent = timestamp();
  item.append(time, document.createTextNode(message));
  $("#activity-log").append(item);
  item.scrollIntoView({ block: "nearest" });
}

function setDossier({ heading, meta, body, state }) {
  $("#dossier-heading").textContent = heading;
  $("#dossier-meta").innerText = meta;
  $("#dossier-body").innerText = body;
  $("#dossier").className = `dossier state-${state}`;
}

function selectFixture(key, announce = true) {
  selected = key;
  const fixture = fixtureFor(key);
  $$(".fixture").forEach((button) => {
    const active = button.dataset.fixture === key;
    button.classList.toggle("is-selected", active);
    button.setAttribute("aria-pressed", String(active));
  });
  $("#input-path").textContent = `fixtures/${fixture.name}`;
  $("#output-path").textContent = `fixtures/${outputName(fixture.name)}`;
  $("#file-kind").textContent = fixture.kind;
  setDossier({
    heading: "READY TO INSPECT",
    meta: "SIGNED  -\nIRM GATE  ACTIVE",
    body: "Sanitized fixture selected.\nNext · Run the simulated inspection.",
    state: "info",
  });
  if (announce) log(` fixture selected · ${fixture.name} · no file opened`);
}

function inspect() {
  const fixture = fixtureFor(selected);
  setDossier(fixture);
  log(` simulated inspect · ${fixture.name} · no command run`);
}

function unlock() {
  const fixture = fixtureFor(selected);
  if (selected === "signed" && !$("#strip-signatures").checked) {
    setDossier({
      heading: "OPTION REQUIRED",
      meta: fixture.meta,
      body: "This signed fixture fails closed.\nEnable Strip signatures in Advanced to continue the simulation.",
      state: "error",
    });
    log(" simulated unlock blocked · Strip signatures is not enabled · no command run");
    return;
  }
  setDossier({
    heading: "SIMULATED WORKING COPY",
    meta: fixture.meta,
    body: `${fixture.unlock}\nOutput · fixtures/${outputName(fixture.name)}\nNo file was created or changed.`,
    state: "ok",
  });
  log(` ${fixture.unlock} · no command run`);
}

function exportHash() {
  const fixture = fixtureFor(selected);
  setDossier({
    heading: "SIMULATED HASH EXPORT",
    meta: fixture.meta,
    body: `${fixture.export}\nNo hash was generated or downloaded.`,
    state: selected === "encrypted" ? "ok" : "info",
  });
  log(` ${fixture.export} · no command run`);
}

function reset() {
  tick = 0;
  $("#overwrite").checked = false;
  $("#strip-signatures").checked = false;
  $("#activity-log").innerHTML = "<li><time>00:00:00</time> demo reset · fixture data only · no commands run</li>";
  selectFixture("soft", false);
}

function runKeyboardAction(key) {
  const action = keyboardActions.get(key);
  if (!action) return false;
  action();
  return true;
}

function shouldIgnoreKeydown(event) {
  const hasModifier = [event.altKey, event.ctrlKey, event.metaKey].some(Boolean);
  return hasModifier || event.target.matches("input, summary");
}

const keyboardActions = new Map([
  ["i", inspect],
  ["u", unlock],
  ["e", exportHash],
  ["r", reset],
]);

$$(".fixture").forEach((button) => button.addEventListener("click", () => selectFixture(button.dataset.fixture)));
$("#inspect").addEventListener("click", inspect);
$("#unlock").addEventListener("click", unlock);
$("#export").addEventListener("click", exportHash);
$("#reset").addEventListener("click", reset);

document.addEventListener("keydown", (event) => {
  if (shouldIgnoreKeydown(event)) return;
  if (runKeyboardAction(event.key.toLowerCase())) event.preventDefault();
});
