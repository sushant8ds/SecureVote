/* global forge */

const LS = {
  voterTok: "sv_voter_token",
  voterId: "sv_voter_id",
  voterKey: "sv_voter_priv_pem",
  adminTok: "sv_admin_token",
  adminUser: "sv_admin_username",
};

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

/* ---------- Small DOM helpers ---------- */

/** Build an element. Children are appended as text unless they are nodes, so nothing needs escaping. */
function h(tag, props, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v === true) n.setAttribute(k, "");
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.toggle("is-error", err);
  t.classList.remove("hidden");
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.add("hidden"), err ? 6000 : 4000);
}

/** Disable a button while an async action runs, so it cannot be triggered twice. */
async function busy(btn, fn) {
  if (btn) btn.setAttribute("aria-busy", "true");
  try {
    return await fn();
  } finally {
    if (btn) btn.removeAttribute("aria-busy");
  }
}

/** Ask for confirmation in a modal. Resolves true only if the confirm button was pressed. */
function confirmDialog({ title, body, confirmLabel = "Confirm", danger = false }) {
  const dlg = $("#dialog");
  if (!dlg || typeof dlg.showModal !== "function") {
    return Promise.resolve(window.confirm(title));
  }
  $("#dialog-title").textContent = title;
  $("#dialog-body").replaceChildren(...[body].flat().map((b) => (b.nodeType ? b : h("p", null, b))));
  const ok = $("#dialog-ok");
  ok.textContent = confirmLabel;
  ok.className = danger ? "btn btn-danger" : "btn btn-primary";
  dlg.returnValue = "cancel";
  return new Promise((resolve) => {
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true });
    dlg.showModal();
    $("#dialog-cancel").focus();
  });
}

function fmtDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;

/** Time of day with seconds for today, otherwise the full date: alerts need to be precise. */
function fmtWhen(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  if (d.toDateString() === new Date().toDateString()) {
    return d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" });
  }
  return fmtDate(iso);
}

const isoNow = (offsetMs = 0) => new Date(Date.now() + offsetMs).toISOString().replace(/\.\d{3}Z$/, "Z");

const SCOPE = { class: "Class election", department: "Department election", campus: "Campus-wide election" };

function localToIsoZ(val) {
  const d = new Date(val);
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/* ---------- API ---------- */

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  const voter = localStorage.getItem(LS.voterTok);
  const admin = localStorage.getItem(LS.adminTok);
  if (opts.role === "admin" && admin) headers.Authorization = `Bearer ${admin}`;
  else if (opts.role === "voter" && voter) headers.Authorization = `Bearer ${voter}`;
  else if (opts.auth === "voter" && voter) headers.Authorization = `Bearer ${voter}`;
  else if (opts.auth === "admin" && admin) headers.Authorization = `Bearer ${admin}`;
  else if (voter && opts.auth !== "none" && opts.role !== "admin") headers.Authorization = `Bearer ${voter}`;

  const init = {
    method: opts.method || "GET",
    headers,
  };
  if (opts.json !== undefined) init.body = JSON.stringify(opts.json);
  else if (opts.body !== undefined) init.body = opts.body;

  const r = await fetch(path, init);
  const text = await r.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { detail: text || r.statusText };
  }
  if (!r.ok) {
    const msg = data.detail || (typeof data === "string" ? data : JSON.stringify(data));
    const msgStr = typeof msg === "string" ? msg : JSON.stringify(msg);
    const voterAuthSent =
      voter &&
      (opts.auth === "voter" || opts.role === "voter" || (opts.auth !== "none" && opts.auth !== "admin" && opts.role !== "admin"));
    const adminAuthSent = admin && (opts.role === "admin" || opts.auth === "admin");
    if (voterAuthSent && (r.status === 401 || (r.status === 403 && msgStr.includes("voter roster")))) {
      clearVoterSession();
      updateNav();
      showView("login");
    }
    if (adminAuthSent && r.status === 401) {
      localStorage.removeItem(LS.adminTok);
      localStorage.removeItem(LS.adminUser);
      updateNav();
      showView("login");
      throw new Error("Your administrator session has expired. Sign in again.");
    }
    throw new Error(msgStr);
  }
  return data;
}

/* ---------- Cryptography (runs in the browser) ---------- */

function derToPem(buf, label) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin).replace(/(.{64})/g, "$1\n").trim();
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----\n`;
}

/**
 * Generate the voter signing key pair in this browser (WebCrypto) so the private key never
 * reaches the server. Returns null when WebCrypto is unavailable (e.g. plain HTTP on a
 * non-localhost host); callers then fall back to a server-generated key.
 */
async function generateVoterKeyPair() {
  if (!(window.crypto && window.crypto.subtle)) return null;
  try {
    const kp = await window.crypto.subtle.generateKey(
      { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const priv = await window.crypto.subtle.exportKey("pkcs8", kp.privateKey);
    const pub = await window.crypto.subtle.exportKey("spki", kp.publicKey);
    return { privatePem: derToPem(priv, "PRIVATE KEY"), publicPem: derToPem(pub, "PUBLIC KEY") };
  } catch {
    return null;
  }
}

/** RSA-OAEP (SHA-256) encryption of {"contestant_id": N} to the election's public key. */
function encryptBallot(contestantId, electionPubPem) {
  const plain = JSON.stringify({ contestant_id: contestantId });
  const pk = forge.pki.publicKeyFromPem(electionPubPem);
  const encrypted = pk.encrypt(forge.util.encodeUtf8(plain), "RSA-OAEP", {
    md: forge.md.sha256.create(),
    mgf1: { md: forge.md.sha256.create() },
  });
  return forge.util.encode64(encrypted);
}

/** RSA-PSS (SHA-256, 32-byte salt) signature over "ciphertext|timestamp" with a voter private key. */
function signBallot(encryptedB64, ts, privPem) {
  const sk = forge.pki.privateKeyFromPem(privPem);
  const md = forge.md.sha256.create();
  md.update(encryptedB64 + "|" + ts, "utf8");
  // Options object (forge 1.x): legacy 3-arg form mapped md/mgf/salt wrong and broke with "r.start is not a function".
  const pss = forge.pss.create({
    md: forge.md.sha256.create(),
    mgf: forge.mgf.mgf1.create(forge.md.sha256.create()),
    saltLength: 32,
  });
  return forge.util.encode64(sk.sign(md, pss));
}

function encryptAndSignVote(contestantId, electionPubPem, voterPrivPem) {
  const encryptedB64 = encryptBallot(contestantId, electionPubPem);
  const ts = isoNow();
  return { encryptedB64, signatureB64: signBallot(encryptedB64, ts, voterPrivPem), ts };
}

/** SHA-256 of the ciphertext bytes: the same integrity hash the server stores next to the ballot. */
function ballotFingerprint(encryptedB64) {
  const md = forge.md.sha256.create();
  md.update(forge.util.decode64(encryptedB64));
  return md.digest().toHex();
}

/* ---------- Views and header ---------- */

let currentView = "login";

function showView(name) {
  $$(".view").forEach((v) => v.classList.add("hidden"));
  $(`#view-${name}`).classList.remove("hidden");
  currentView = name;
  // Keep the view in the address bar so a second window can open straight onto /#lab or /#admin.
  if (["voter", "admin", "lab"].includes(name)) history.replaceState(null, "", `#${name}`);
  else if (location.hash) history.replaceState(null, "", location.pathname);
  updateNav();
  window.scrollTo(0, 0);
}

function clearVoterSession() {
  voterSession = null;
  localStorage.removeItem(LS.voterTok);
  localStorage.removeItem(LS.voterId);
  localStorage.removeItem(LS.voterKey);
  pendingVoterPasswordAfterRegister = null;
  lastReceipt = null;
  resetVoterOtpUi();
}

function signOut() {
  clearVoterSession();
  localStorage.removeItem(LS.adminTok);
  localStorage.removeItem(LS.adminUser);
  $("#form-voter-login").reset();
  $("#form-admin-login").reset();
  updateNav();
  showView("login");
  refreshAdminSetupUi();
  toast("You are signed out");
}

function updateNav() {
  const nav = $("#nav-auth");
  const vt = localStorage.getItem(LS.voterTok);
  const at = localStorage.getItem(LS.adminTok);
  nav.replaceChildren();
  const link = (label, view, fn) =>
    h("button", { type: "button", class: "btn-link", "aria-current": view && view === currentView ? "page" : null, onclick: fn }, label);
  if (vt) {
    nav.append(
      link("Elections", "voter", () => {
        showView("voter");
        loadVoterDashboard();
      }),
    );
  }
  if (at) {
    nav.append(
      link("Administration", "admin", () => {
        showView("admin");
        loadAdminDashboard();
      }),
    );
  }
  if (vt || at) {
    nav.append(
      link("Security lab", "lab", () => {
        showView("lab");
        loadLab();
      }),
      link("Sign out", null, signOut),
    );
  }
}

const LOCK_ICON =
  '<svg viewBox="0 0 16 16" aria-hidden="true"><rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/></svg>';

/* Shows whether this page (and every API call) travels over TLS. */
function showTransportBadge() {
  const b = $("#conn-badge");
  if (!b) return;
  const secure = location.protocol === "https:";
  b.innerHTML = secure ? LOCK_ICON : "";
  b.append(secure ? "Encrypted connection" : "Connection is not encrypted");
  b.title = secure
    ? "Passwords, one-time codes, session tokens and ballots are encrypted in transit with TLS."
    : "Start the server with `python run.py` and open the https:// address.";
  b.classList.toggle("is-insecure", !secure);
  b.classList.remove("hidden");
}

/* ---------- Identity fields (registration and one-time verification) ---------- */

// Verhoeff tables: the 12th Aadhaar digit is a Verhoeff check digit, so typos are caught before sending.
const VH_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VH_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

function verhoeffValid(digits) {
  let c = 0;
  [...digits].reverse().forEach((ch, i) => {
    c = VH_D[c][VH_P[i % 8][Number(ch)]];
  });
  return c === 0;
}

/** Problem with an Aadhaar number as typed, or "" if it is well formed. */
function aadhaarProblem(raw) {
  const d = String(raw || "").replace(/\D/g, "");
  if (d.length !== 12) return "An Aadhaar number has 12 digits.";
  if (/^[01]/.test(d) || !verhoeffValid(d)) return "That is not a valid Aadhaar number. Check it for a typo.";
  return "";
}

const formatAadhaar = (v) => v.replace(/\D/g, "").slice(0, 12).replace(/(\d{4})(?=\d)/g, "$1 ");

const ID_COPY = {
  aadhaar: { label: "Aadhaar number", hint: "12 digits, as printed on the card.", placeholder: "1234 5678 9012", mode: "numeric", max: 14 },
  college_id: { label: "College ID number", hint: "As printed on your college ID card.", placeholder: "01FE23BCS000", mode: "text", max: 20 },
};

function bindIdentityFields(form) {
  const num = form.querySelector("input[name=id_number]");
  const dob = form.querySelector("input[name=date_of_birth]");
  const type = () => form.querySelector("input[name=id_type]:checked").value;
  if (dob) dob.max = new Date().toISOString().slice(0, 10);
  const apply = () => {
    const c = ID_COPY[type()];
    form.querySelector("[data-id-label]").textContent = c.label;
    form.querySelector("[data-id-hint]").textContent = c.hint;
    num.placeholder = c.placeholder;
    num.inputMode = c.mode;
    num.maxLength = c.max;
    num.setCustomValidity("");
  };
  form.querySelectorAll("input[name=id_type]").forEach((r) =>
    r.addEventListener("change", () => {
      num.value = "";
      apply();
      num.focus();
    }),
  );
  num.addEventListener("input", () => {
    num.setCustomValidity("");
    if (type() === "aadhaar") num.value = formatAadhaar(num.value);
  });
  form.addEventListener("reset", () => setTimeout(apply));
  apply();
}

/** Identity details from a form, or null after pointing at a malformed Aadhaar number. */
function readIdentity(form) {
  const fd = new FormData(form);
  const idType = String(fd.get("id_type"));
  const num = form.querySelector("input[name=id_number]");
  if (idType === "aadhaar") {
    const problem = aadhaarProblem(num.value);
    if (problem) {
      num.setCustomValidity(problem);
      num.reportValidity();
      return null;
    }
  }
  return {
    id_type: idType,
    id_number: String(fd.get("id_number") || "").trim(),
    full_name: String(fd.get("full_name") || "").trim(),
    date_of_birth: String(fd.get("date_of_birth") || ""),
  };
}

$$(".id-fieldset").forEach((fs) => bindIdentityFields(fs.closest("form")));

/* ---------- Sign in ---------- */

let voterOtpPending = false;
/** Cleared after voter JWT login succeeds or on sign-out / leaving register. */
let pendingVoterPasswordAfterRegister = null;

function setLoginRole(role) {
  $$(".seg").forEach((s) => {
    const on = s.dataset.tab === role;
    s.classList.toggle("is-active", on);
    s.setAttribute("aria-selected", on ? "true" : "false");
  });
  $("#form-voter-login").classList.toggle("hidden", role !== "voter");
  $("#form-admin-login").classList.toggle("hidden", role !== "admin");
  $("#register-prompt").classList.toggle("hidden", role !== "voter");
  $("#login-lede").textContent =
    role === "voter"
      ? "Vote in student elections with your university email."
      : "Manage elections, voter access and results.";
  if (role === "admin") refreshAdminSetupUi();
}

$$(".seg").forEach((s) => s.addEventListener("click", () => setLoginRole(s.dataset.tab)));

async function refreshAdminSetupUi() {
  const banner = $("#admin-first-run-banner");
  if (!banner) return;
  try {
    const st = await api("/api/admin/setup-status", { auth: "none" });
    banner.classList.toggle("hidden", !st.needs_first_admin);
  } catch {
    banner.classList.add("hidden");
  }
}

/** Second sign-in step: the password was accepted and a one-time code was sent. */
function showOtpStep(email, data) {
  voterOtpPending = true;
  setLoginRole("voter");
  $("#login-title").textContent = "Check your email";
  $("#login-lede").classList.add("hidden");
  $("#role-switch").classList.add("hidden");
  $("#register-prompt").classList.add("hidden");
  $("#login-step-credentials").classList.add("hidden");
  $("#login-step-otp").classList.remove("hidden");
  $("#otp-sent-to").textContent = email;
  const secs = Number(data.expires_in_seconds) || 0;
  $("#otp-expiry").textContent = secs ? `It expires in ${plural(Math.round(secs / 60), "minute")}.` : "";
  const demo = $("#otp-demo");
  demo.classList.toggle("hidden", !data.dev_otp);
  $("#otp-demo-code").textContent = data.dev_otp || "";
  const otpIn = $("#form-voter-login").querySelector("input[name=otp]");
  otpIn.disabled = false;
  otpIn.value = "";
  otpIn.focus();
}

function resetVoterOtpUi() {
  voterOtpPending = false;
  $("#login-title").textContent = "Sign in";
  $("#login-lede").classList.remove("hidden");
  $("#role-switch").classList.remove("hidden");
  $("#register-prompt").classList.remove("hidden");
  $("#login-step-credentials").classList.remove("hidden");
  $("#login-step-otp").classList.add("hidden");
  $("#otp-demo").classList.add("hidden");
  const otpIn = $("#form-voter-login").querySelector("input[name=otp]");
  otpIn.value = "";
  otpIn.disabled = true;
}

$("#otp-demo-fill").addEventListener("click", () => {
  const otpIn = $("#form-voter-login").querySelector("input[name=otp]");
  otpIn.value = $("#otp-demo-code").textContent;
  otpIn.focus();
});

$("#otp-back").addEventListener("click", () => {
  pendingVoterPasswordAfterRegister = null;
  resetVoterOtpUi();
  const pw = $("#form-voter-login").querySelector("input[name=password]");
  pw.value = "";
  pw.focus();
});

$("#link-register").addEventListener("click", () => {
  resetVoterOtpUi();
  showView("register");
  $("#form-register").querySelector("input[name=voter_id]").focus();
});

$("#link-back-login").addEventListener("click", () => {
  pendingVoterPasswordAfterRegister = null;
  resetVoterOtpUi();
  showView("login");
});

$("#btn-go-admin-setup").addEventListener("click", () => showView("admin-setup"));
$("#link-admin-setup-back").addEventListener("click", () => {
  showView("login");
  refreshAdminSetupUi();
});

$("#form-admin-first").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await busy(e.submitter, async () => {
    try {
      await api("/api/admin/register-first", {
        method: "POST",
        auth: "none",
        json: { username: fd.get("username"), password: fd.get("password") },
      });
      e.target.reset();
      showView("login");
      setLoginRole("admin");
      toast("Administrator created. You can sign in now.");
    } catch (err) {
      toast(err.message, true);
    }
  });
});

async function restoreSigningKeyFromPassword(password) {
  const kp = await generateVoterKeyPair();
  const data = await api("/api/voter/restore-signing-key", {
    method: "POST",
    role: "voter",
    json: { password, ...(kp ? { public_key_pem: kp.publicPem } : {}) },
  });
  localStorage.setItem(LS.voterKey, kp ? kp.privatePem : data.voter_private_key_pem);
  updateVoterKeyBanner();
}

function updateVoterKeyBanner(scrollTo = false) {
  const banner = $("#voter-key-banner");
  const missing = localStorage.getItem(LS.voterTok) && !localStorage.getItem(LS.voterKey);
  banner.classList.toggle("hidden", !missing);
  if (missing && scrollTo) {
    banner.scrollIntoView({ behavior: "smooth", block: "center" });
    banner.querySelector("input").focus({ preventScroll: true });
  }
}

$("#form-voter-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const fd = new FormData(form);
  const vid = String(fd.get("voter_id") || "").trim().toLowerCase();
  const password = fd.get("password");
  const otp = voterOtpPending ? String(fd.get("otp") || "").trim() : "";
  await busy(e.submitter, async () => {
    try {
      const prevId = String(localStorage.getItem(LS.voterId) || "").trim();
      if (prevId !== vid) {
        localStorage.removeItem(LS.voterKey);
      }
      const data = await api("/api/login", {
        method: "POST",
        json: { voter_id: vid, password, ...(otp ? { otp } : {}) },
        auth: "none",
      });
      if (data && data.otp_required === true) {
        showOtpStep(vid, data);
        return;
      }
      if (!data.access_token) {
        toast("Sign-in did not complete. Try again.", true);
        return;
      }
      localStorage.setItem(LS.voterTok, data.access_token);
      localStorage.setItem(LS.voterId, vid);
      pendingVoterPasswordAfterRegister = null;
      let restoreErr = null;
      if (!localStorage.getItem(LS.voterKey)) {
        try {
          await restoreSigningKeyFromPassword(password);
        } catch (err) {
          restoreErr = err;
        }
      }
      form.reset();
      resetVoterOtpUi();
      updateNav();
      showView("voter");
      loadVoterDashboard();
      if (restoreErr) toast(restoreErr.message, true);
    } catch (err) {
      const msg = String(err.message || "");
      // The code is no longer usable: go back so the next "Continue" requests a fresh one.
      if (voterOtpPending && /Request a new OTP/i.test(msg)) {
        resetVoterOtpUi();
        toast(msg.replace(/Request a new OTP\.?/i, "Continue again to get a new code."), true);
        return;
      }
      toast(msg, true);
    }
  });
});

$("#form-restore-key").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await busy(e.submitter, async () => {
    try {
      await restoreSigningKeyFromPassword(fd.get("password"));
      e.target.reset();
      toast("New signing key saved in this browser");
      loadElections();
    } catch (err) {
      toast(err.message, true);
    }
  });
});

$("#form-admin-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const username = String(fd.get("username") || "").trim();
  await busy(e.submitter, async () => {
    try {
      const data = await api("/api/admin/login", {
        method: "POST",
        json: { username, password: fd.get("password") },
        auth: "none",
      });
      localStorage.setItem(LS.adminTok, data.access_token);
      localStorage.setItem(LS.adminUser, username);
      e.target.reset();
      updateNav();
      showView("admin");
      loadAdminDashboard();
    } catch (err) {
      toast(err.message, true);
    }
  });
});

/** Put the sign-in form into a known state with the email filled in. */
function goToVoterSignIn(email) {
  resetVoterOtpUi();
  showView("login");
  setLoginRole("voter");
  const form = $("#form-voter-login");
  form.querySelector("input[name=voter_id]").value = email;
  const pw = form.querySelector("input[name=password]");
  pw.value = "";
  pw.focus();
}

$("#form-register").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const voterId = String(fd.get("voter_id") || "").trim().toLowerCase();
  const password = fd.get("password");
  const identity = readIdentity(e.target);
  if (!identity) return;
  await busy(e.submitter, async () => {
    try {
      const kp = await generateVoterKeyPair();
      const data = await api("/api/register", {
        method: "POST",
        json: { voter_id: voterId, password, ...identity, ...(kp ? { public_key_pem: kp.publicPem } : {}) },
        auth: "none",
      });
      localStorage.setItem(LS.voterKey, kp ? kp.privatePem : data.voter_private_key_pem);
      localStorage.setItem(LS.voterId, String(data.voter_id || "").trim());
      pendingVoterPasswordAfterRegister = String(password);
      e.target.reset();
      // Go straight to the verification step so the new voter does not type the password twice.
      let step1 = null;
      try {
        step1 = await api("/api/login", { method: "POST", json: { voter_id: voterId, password }, auth: "none" });
      } catch {
        step1 = null;
      }
      goToVoterSignIn(voterId);
      if (step1 && step1.otp_required === true) {
        $("#form-voter-login").querySelector("input[name=password]").value = pendingVoterPasswordAfterRegister;
        showOtpStep(voterId, step1);
        toast("Account created. Enter the code to finish.");
      } else {
        pendingVoterPasswordAfterRegister = null;
        toast("Account created. Sign in to continue.");
      }
    } catch (err) {
      pendingVoterPasswordAfterRegister = null;
      const msg = String(err.message || "");
      if (msg.includes("already registered")) {
        goToVoterSignIn(voterId);
        toast("This email already has an account. Sign in with your password.");
        return;
      }
      toast(msg, true);
    }
  });
});

/* ---------- Voter: elections ---------- */

/** Shown once after a vote is cast, above the election list. */
let lastReceipt = null;

function vTab(name) {
  $$(".tab[data-vtab]").forEach((b) => b.classList.toggle("is-active", b.dataset.vtab === name));
  $("#v-panel-elections").classList.toggle("hidden", name !== "elections");
  $("#v-panel-results").classList.toggle("hidden", name !== "results");
  if (name === "elections") return loadElections();
  return loadResults();
}

$$(".tab[data-vtab]").forEach((b) => b.addEventListener("click", () => vTab(b.dataset.vtab)));

/** Server's view of the signed-in voter: name from the roster and identity status. */
let voterSession = null;

async function refreshVoterSession() {
  try {
    voterSession = await api("/api/voter/session", { auth: "voter" });
  } catch {
    voterSession = null;
  }
  const id = localStorage.getItem(LS.voterId);
  const s = voterSession;
  const who = s && s.full_name ? `${s.full_name} (${id})` : id;
  const how = s && s.identity_verified ? ` · Identity verified with ${s.identity_method === "aadhaar" ? "Aadhaar" : "college ID"}` : "";
  $("#voter-welcome").textContent = who ? `Signed in as ${who}${how}` : "";
  $("#voter-id-banner").classList.toggle("hidden", !s || s.identity_verified);
}

async function loadVoterDashboard() {
  updateVoterKeyBanner();
  await refreshVoterSession();
  await vTab("elections");
}

$("#form-verify-identity").addEventListener("submit", async (e) => {
  e.preventDefault();
  const identity = readIdentity(e.target);
  if (!identity) return;
  await busy(e.submitter, async () => {
    try {
      await api("/api/voter/verify-identity", { method: "POST", role: "voter", json: identity });
      e.target.reset();
      toast("Identity verified. You can request access to elections now.");
      await refreshVoterSession();
      loadElections();
    } catch (err) {
      toast(err.message, true);
    }
  });
});

/** Where an election belongs in the voter's list, and what they can do with it. */
function electionState(e) {
  const now = Date.now();
  const over = e.closed || now > Date.parse(e.ends_at);
  const upcoming = !over && now < Date.parse(e.starts_at);
  const reg = e.my_registration_status;
  const when = over ? `Closed ${fmtDate(e.ends_at)}` : upcoming ? `Opens ${fmtDate(e.starts_at)}` : `Closes ${fmtDate(e.ends_at)}`;
  const base = { over, upcoming, when };

  if (e.my_voted) return { ...base, group: "past", status: ["ok", "You voted"] };
  if (over) return { ...base, group: "past", status: ["muted", e.results_announced ? "Results published" : "Closed"] };
  if (reg === "rejected") return { ...base, group: "past", status: ["danger", "Access declined"] };
  if (reg === "pending") return { ...base, group: "waiting", status: ["warn", "Waiting for approval"] };
  if (reg === "approved") {
    if (upcoming) return { ...base, group: "waiting", status: ["muted", "Approved. Voting has not opened"] };
    if (!e.contestant_count) return { ...base, group: "waiting", status: ["muted", "No candidates yet"] };
    return { ...base, group: "vote", action: "vote" };
  }
  return { ...base, group: "join", action: "request" };
}

const GROUPS = [
  ["vote", "Ready for your vote"],
  ["join", "Open elections"],
  ["waiting", "Waiting"],
  ["past", "Completed"],
];

async function loadElections() {
  const panel = $("#v-panel-elections");
  let elections;
  try {
    ({ elections } = await api("/api/elections", { auth: "voter" }));
  } catch (err) {
    panel.replaceChildren(h("p", { class: "empty" }, err.message));
    return;
  }
  const out = [];
  if (lastReceipt) {
    out.push(
      h(
        "div",
        { class: "callout callout-success" },
        h("p", null, h("strong", null, "Your vote was recorded."), ` ${lastReceipt.title}`),
        h("code", { class: "receipt", title: "SHA-256 of your encrypted ballot" }, `Ballot fingerprint ${lastReceipt.fingerprint}`),
      ),
    );
    lastReceipt = null;
  }
  if (!elections.length) {
    out.push(h("p", { class: "empty" }, "There are no elections yet. New ones will appear here."));
    panel.replaceChildren(...out);
    return;
  }
  const byGroup = {};
  for (const e of elections) {
    const st = electionState(e);
    (byGroup[st.group] ||= []).push([e, st]);
  }
  for (const [key, title] of GROUPS) {
    const items = byGroup[key];
    if (!items) continue;
    out.push(
      h(
        "section",
        { class: "group" },
        h("h2", { class: "group-title" }, title),
        h("ul", null, items.map(([e, st]) => electionRow(e, st))),
      ),
    );
  }
  panel.replaceChildren(...out);
}

function electionRow(e, st) {
  const side = h("div", { class: "row-side" });
  const row = h(
    "li",
    { class: "row" },
    h(
      "div",
      { class: "row-main" },
      h("h3", null, e.title),
      h("p", { class: "meta" }, [SCOPE[e.category] || e.category, plural(e.contestant_count, "candidate"), st.when].join(" · ")),
    ),
    side,
  );

  if (st.status) side.append(h("span", { class: `status status-${st.status[0]}` }, st.status[1]));
  if (st.group === "past" && e.results_announced) {
    side.append(h("button", { type: "button", class: "btn-link", onclick: () => vTab("results") }, "See results"));
  }

  if (st.action === "request") {
    const btn = h("button", { type: "button", class: "btn btn-small" }, "Request access");
    btn.addEventListener("click", () =>
      busy(btn, async () => {
        try {
          await api(`/api/elections/${e.id}/register`, { method: "POST", role: "voter" });
          toast("Request sent. An administrator will review it.");
          loadElections();
        } catch (err) {
          toast(err.message, true);
        }
      }),
    );
    side.append(btn);
  }

  if (st.action === "vote") {
    const btn = h("button", { type: "button", class: "btn btn-primary btn-small", "aria-expanded": "false" }, "Vote");
    let panel = null;
    btn.addEventListener("click", async () => {
      if (panel) {
        panel.remove();
        panel = null;
        btn.textContent = "Vote";
        btn.className = "btn btn-primary btn-small";
        btn.setAttribute("aria-expanded", "false");
        return;
      }
      panel = h("div", { class: "row-panel" }, h("p", { class: "meta" }, "Loading candidates…"));
      row.append(panel);
      btn.textContent = "Close";
      btn.className = "btn btn-small";
      btn.setAttribute("aria-expanded", "true");
      try {
        const detail = await api(`/api/elections/${e.id}/detail`, { auth: "voter" });
        if (panel) panel.replaceChildren(ballotForm(e, detail, () => btn.click()));
      } catch (err) {
        if (panel) panel.replaceChildren(h("p", { class: "meta" }, err.message));
      }
    });
    side.append(btn);
  }
  return row;
}

function ballotForm(e, detail, onCancel) {
  if (!detail.public_key_pem || !detail.contestants.length) {
    return h("p", { class: "meta" }, "This election can't accept votes right now.");
  }
  const name = `choice-${e.id}`;
  const submit = h("button", { type: "submit", class: "btn btn-primary", disabled: true }, "Review vote");
  const form = h(
    "form",
    null,
    h("p", { class: "ballot-title" }, "Choose one candidate"),
    h("p", { class: "ballot-help" }, "You can vote once in this election. Your choice can't be changed afterwards."),
    h(
      "div",
      { class: "options", role: "radiogroup" },
      detail.contestants.map((c) =>
        h(
          "label",
          { class: "option" },
          h("input", { type: "radio", name, value: String(c.id), required: true }),
          h("img", { src: c.image_url, alt: "" }),
          h("span", { class: "option-name" }, c.name),
        ),
      ),
    ),
    h(
      "div",
      { class: "ballot-actions" },
      submit,
      h("button", { type: "button", class: "btn", onclick: onCancel }, "Cancel"),
    ),
  );
  form.addEventListener("change", () => {
    submit.disabled = !form.querySelector("input:checked");
  });
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const picked = form.querySelector("input:checked");
    if (!picked) return;
    const contestant = detail.contestants.find((c) => String(c.id) === picked.value);
    castVote(e, contestant, detail, submit);
  });
  return form;
}

async function castVote(e, contestant, detail, btn) {
  const priv = localStorage.getItem(LS.voterKey);
  if (!priv) {
    toast("This browser has no signing key. Create a new one first.", true);
    updateVoterKeyBanner(true);
    return;
  }
  const ok = await confirmDialog({
    title: "Cast this vote?",
    body: [
      h("p", null, "You are voting for ", h("strong", null, contestant.name), " in ", h("strong", null, e.title), "."),
      h("p", null, "Your ballot is encrypted and signed on this device. It can't be changed after it is cast."),
    ],
    confirmLabel: "Cast vote",
  });
  if (!ok) return;
  await busy(btn, async () => {
    try {
      const { encryptedB64, signatureB64, ts } = encryptAndSignVote(contestant.id, detail.public_key_pem, priv);
      await api(`/api/elections/${e.id}/vote`, {
        method: "POST",
        role: "voter",
        json: {
          voter_id: localStorage.getItem(LS.voterId),
          encrypted_vote: encryptedB64,
          signature: signatureB64,
          timestamp: ts,
        },
      });
      lastReceipt = { title: e.title, fingerprint: ballotFingerprint(encryptedB64) };
      await loadElections();
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (err) {
      toast(err.message, true);
    }
  });
}

/* ---------- Voter: results ---------- */

async function loadResults() {
  const panel = $("#v-panel-results");
  try {
    const { elections } = await api("/api/elections", { auth: "voter" });
    const done = elections.filter((e) => e.results_announced);
    if (!done.length) {
      panel.replaceChildren(
        h("p", { class: "empty" }, "No results have been published yet. They appear here after an election is closed and counted."),
      );
      return;
    }
    const blocks = [];
    for (const e of done) {
      blocks.push(resultBlock(await api(`/api/elections/${e.id}/results`, { auth: "voter" })));
    }
    panel.replaceChildren(...blocks);
  } catch (err) {
    panel.replaceChildren(h("p", { class: "empty" }, err.message));
  }
}

function resultBlock(res) {
  const total = res.total_valid_votes || 0;
  const top = Math.max(0, ...res.contestants.map((c) => c.votes));
  const leaders = res.contestants.filter((c) => top > 0 && c.votes === top);
  const ranked = [...res.contestants].sort((a, b) => b.votes - a.votes);
  return h(
    "section",
    { class: "result" },
    h(
      "div",
      { class: "result-head" },
      h("h2", null, res.title),
      h("p", { class: "meta" }, [SCOPE[res.category] || res.category, total ? plural(total, "valid vote") : "No valid votes were cast"].join(" · ")),
    ),
    ranked.map((c) => {
      const pct = total ? Math.round((c.votes / total) * 100) : 0;
      const leading = leaders.includes(c);
      const fill = h("span");
      fill.style.width = `${pct}%`;
      return h(
        "div",
        { class: `result-row${leading ? " is-leading" : ""}` },
        h("img", { class: "result-photo", src: c.image_url, alt: "" }),
        h(
          "div",
          null,
          h(
            "div",
            { class: "result-line" },
            h(
              "span",
              { class: "result-name" },
              c.name,
              leading && h("span", { class: "result-tag" }, leaders.length > 1 ? "Tied" : "Winner"),
            ),
            h("span", { class: "result-count" }, `${plural(c.votes, "vote")} · ${pct}%`),
          ),
          h("div", { class: "bar" }, fill),
        ),
      );
    }),
  );
}

/* ---------- Admin ---------- */

function aTab(name) {
  $$(".tab[data-atab]").forEach((b) => b.classList.toggle("is-active", b.dataset.atab === name));
  for (const p of ["elections", "requests", "alerts", "roster", "create"]) {
    $(`#a-panel-${p}`).classList.toggle("hidden", p !== name);
  }
  loadAdminSummary();
  pollAlerts(true);
  if (name === "elections") return loadAdminElections();
  if (name === "requests") return loadRequests();
  if (name === "alerts") return loadAlerts();
  if (name === "roster") return loadRoster();
  initCreateForm();
  return undefined;
}

$$(".tab[data-atab]").forEach((b) => b.addEventListener("click", () => aTab(b.dataset.atab)));

const activeAdminTab = () => ($(".tab[data-atab].is-active") || {}).dataset?.atab;

async function loadAdminDashboard() {
  const un = localStorage.getItem(LS.adminUser);
  $("#admin-welcome-line").textContent = un ? `Signed in as ${un}` : "";
  await aTab("elections");
}

/* ---------- Admin: security alerts (live) ---------- */

const SEVERITY = { high: "High", medium: "Medium", low: "Low" };
/** "<id>:<last_seen_at>" of the newest alert already shown, so only new activity pops up. */
let lastAlertStamp = null;

/**
 * Ask the server for the alert summary. Runs every few seconds while the admin screen is open, so an
 * attack made from another window or device shows up here within moments.
 */
async function pollAlerts(quiet = false) {
  if (!localStorage.getItem(LS.adminTok) || currentView !== "admin" || document.hidden) return;
  let s;
  try {
    s = await api("/api/admin/alerts/summary", { role: "admin" });
  } catch {
    return;
  }
  const n = s.unacknowledged;
  const badge = $("#badge-alerts");
  badge.textContent = String(n);
  badge.classList.toggle("hidden", n === 0);
  const banner = $("#admin-alert-banner");
  banner.classList.toggle("hidden", n === 0);
  if (n && s.latest) {
    const who = s.latest.actor ? ` (${s.latest.actor})` : "";
    $("#admin-alert-text").replaceChildren(
      h("strong", null, `${plural(n, "security alert")} to review.`),
      ` Latest: ${s.latest.title}${who}, ${fmtWhen(s.latest.last_seen_at)}.`,
    );
  }
  const stamp = s.latest ? `${s.latest.id}:${s.latest.last_seen_at}` : "";
  if (!quiet && lastAlertStamp !== null && stamp && stamp !== lastAlertStamp) {
    showAlertPop(s.latest);
    if (activeAdminTab() === "alerts") loadAlerts();
  }
  lastAlertStamp = stamp;
}

setInterval(() => pollAlerts(false), 4000);
document.addEventListener("visibilitychange", () => pollAlerts(false));

function showAlertPop(a) {
  const pop = $("#alert-pop");
  pop.className = `alert-pop sev-${a.severity}`;
  $("#alert-pop-title").textContent = a.count > 1 ? `${a.title} (×${a.count})` : a.title;
  $("#alert-pop-detail").textContent = a.detail;
  clearTimeout(pop._h);
  pop._h = setTimeout(() => pop.classList.add("hidden"), 9000);
}

const reviewAlerts = () => {
  $("#alert-pop").classList.add("hidden");
  aTab("alerts");
  $(".tabs").scrollIntoView({ behavior: "smooth", block: "start" });
};
$("#alert-pop-review").addEventListener("click", reviewAlerts);
$("#admin-alert-review").addEventListener("click", reviewAlerts);

async function loadAlerts() {
  const panel = $("#a-panel-alerts");
  let data;
  try {
    data = await api("/api/admin/alerts", { role: "admin" });
  } catch (err) {
    panel.replaceChildren(h("p", { class: "empty" }, err.message));
    return;
  }
  if (!data.alerts.length) {
    panel.replaceChildren(
      h(
        "p",
        { class: "empty" },
        "No security alerts. Attacks the server stops, and runs from the security lab, appear here as they happen.",
      ),
    );
    return;
  }
  const ack = async (path, btn) =>
    busy(btn, async () => {
      try {
        await api(path, { method: "POST", role: "admin" });
        await loadAlerts();
        pollAlerts(true);
      } catch (err) {
        toast(err.message, true);
      }
    });
  const bar = h(
    "div",
    { class: "panel-bar" },
    h("p", { class: "meta" }, data.unacknowledged ? `${plural(data.unacknowledged, "alert")} to review` : "All alerts reviewed"),
  );
  if (data.unacknowledged) {
    const all = h("button", { type: "button", class: "btn btn-small" }, "Mark all reviewed");
    all.addEventListener("click", () => ack("/api/admin/alerts/ack-all", all));
    bar.append(all);
  }
  const items = data.alerts.map((a) => {
    const side = h("div", { class: "alert-side" });
    if (a.acknowledged) side.append(h("span", { class: "status" }, "Reviewed"));
    else {
      const b = h("button", { type: "button", class: "btn btn-small" }, "Mark reviewed");
      b.addEventListener("click", () => ack(`/api/admin/alerts/${a.id}/ack`, b));
      side.append(b);
    }
    const when = a.count > 1 ? `${fmtWhen(a.created_at)} – ${fmtWhen(a.last_seen_at)}` : fmtWhen(a.last_seen_at);
    return h(
      "li",
      { class: `alert-item sev-${a.severity}${a.acknowledged ? " is-reviewed" : ""}` },
      h(
        "div",
        { class: "alert-main" },
        h(
          "p",
          { class: "alert-line" },
          h("span", { class: `sev sev-${a.severity}` }, SEVERITY[a.severity] || a.severity),
          h("strong", null, a.title),
          a.count > 1 && h("span", { class: "alert-count" }, `×${a.count}`),
        ),
        h("p", { class: "alert-detail" }, a.detail),
        h("p", { class: "meta" }, [when, a.actor, a.source_ip, `Detected by ${a.detected_by}`].filter(Boolean).join(" · ")),
      ),
      side,
    );
  });
  panel.replaceChildren(bar, h("ul", { class: "alert-list" }, items));
}

/* ---------- Admin: voter roster ---------- */

async function loadRoster() {
  const host = $("#roster-list");
  let data;
  try {
    data = await api("/api/admin/roster", { role: "admin" });
  } catch (err) {
    host.replaceChildren(h("p", { class: "empty" }, err.message));
    return;
  }
  if (!data.entries.length) {
    host.replaceChildren(h("p", { class: "empty" }, "The roster is empty, so nobody can register. Add students below or in config/voter_roster.csv."));
    return;
  }
  const rows = data.entries.map((e) => {
    let account;
    if (e.identity_verified) {
      account = h("span", { class: "status status-ok" }, `Verified · ${e.identity_method === "aadhaar" ? "Aadhaar" : "College ID"}`);
    } else if (e.registered) account = h("span", { class: "status status-warn" }, "Not verified");
    else account = h("span", { class: "status" }, "No account yet");
    const actions = h("td", { class: "actions" });
    if (!e.registered) {
      const rm = h("button", { type: "button", class: "btn-link btn-link-danger" }, "Remove");
      rm.addEventListener("click", async () => {
        const ok = await confirmDialog({
          title: "Remove from roster?",
          body: [h("p", null, h("strong", null, e.full_name), ` (${e.email}) will no longer be able to register.`)],
          confirmLabel: "Remove",
          danger: true,
        });
        if (!ok) return;
        try {
          await api(`/api/admin/roster/${encodeURIComponent(e.email)}`, { method: "DELETE", role: "admin" });
          toast(`${e.full_name} removed from the roster`);
          loadRoster();
        } catch (err) {
          toast(err.message, true);
        }
      });
      actions.append(rm);
    }
    return h(
      "tr",
      null,
      h("td", null, h("span", { class: "cell-title" }, e.full_name), h("span", { class: "cell-sub" }, e.email)),
      h(
        "td",
        null,
        e.aadhaar && h("span", { class: "id-chip" }, `Aadhaar ${e.aadhaar}`),
        e.college_id && h("span", { class: "id-chip" }, `College ID ${e.college_id}`),
      ),
      h("td", null, account),
      actions,
    );
  });
  host.replaceChildren(
    h("p", { class: "meta panel-intro" }, "Registration is compared with these records. ID numbers are stored as keyed hashes; only the last four digits are kept for display."),
    h(
      "div",
      { class: "table-wrap" },
      h(
        "table",
        null,
        h("thead", null, h("tr", null, h("th", null, "Student"), h("th", null, "ID cards on record"), h("th", null, "Account"), h("th", { class: "actions" }))),
        h("tbody", null, rows),
      ),
    ),
  );
}

$("#form-roster-add").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const fd = new FormData(form);
  const aadhaar = String(fd.get("aadhaar") || "").trim();
  const collegeId = String(fd.get("college_id") || "").trim();
  if (!aadhaar && !collegeId) {
    toast("Give an Aadhaar number, a college ID, or both", true);
    return;
  }
  if (aadhaar && aadhaarProblem(aadhaar)) {
    form.aadhaar.setCustomValidity(aadhaarProblem(aadhaar));
    form.aadhaar.reportValidity();
    return;
  }
  await busy(e.submitter, async () => {
    try {
      await api("/api/admin/roster", {
        method: "POST",
        role: "admin",
        json: {
          email: fd.get("email"),
          full_name: fd.get("full_name"),
          date_of_birth: fd.get("date_of_birth"),
          aadhaar: aadhaar || null,
          college_id: collegeId || null,
        },
      });
      toast(`${fd.get("full_name")} added to the roster`);
      form.reset();
      loadRoster();
    } catch (err) {
      toast(err.message, true);
    }
  });
});
$("#form-roster-add").aadhaar.addEventListener("input", (e) => {
  e.target.setCustomValidity("");
  e.target.value = formatAadhaar(e.target.value);
});

async function loadAdminSummary() {
  const host = $("#admin-stats");
  try {
    const s = await api("/api/admin/dashboard-summary", { role: "admin" });
    const stat = (label, value) => h("div", null, h("dt", null, label), h("dd", null, value));
    host.replaceChildren(
      stat("Requests waiting", s.pending_approvals),
      stat("Elections", s.elections_total),
      stat("Open for voting", s.elections_open),
      stat("Ballots cast", s.votes_recorded),
      stat("Results published", s.results_published),
    );
    const badge = $("#badge-approvals");
    badge.textContent = String(s.pending_approvals);
    badge.classList.toggle("hidden", s.pending_approvals === 0);
  } catch (err) {
    host.replaceChildren();
  }
}

async function loadAdminElections() {
  const panel = $("#a-panel-elections");
  let elections;
  try {
    ({ elections } = await api("/api/admin/election-stats", { role: "admin" }));
  } catch (err) {
    panel.replaceChildren(h("p", { class: "empty" }, err.message));
    return;
  }
  if (!elections.length) {
    panel.replaceChildren(
      h(
        "p",
        { class: "empty" },
        "No elections yet. ",
        h("button", { type: "button", class: "btn-link", onclick: () => aTab("create") }, "Create the first one"),
      ),
    );
    return;
  }
  const rows = elections.map((e) => {
    const actions = h("td", { class: "actions" });
    let status;
    if (!e.closed) {
      status = h("span", { class: "status status-ok" }, "Open");
      const btn = h("button", { type: "button", class: "btn btn-small" }, "Close voting");
      btn.addEventListener("click", async () => {
        const ok = await confirmDialog({
          title: "Close voting?",
          body: [
            h("p", null, h("strong", null, e.title), ` has ${plural(e.ballots_cast, "ballot")} so far.`),
            h("p", null, "No more votes will be accepted, and the election can't be reopened."),
          ],
          confirmLabel: "Close voting",
          danger: true,
        });
        if (!ok) return;
        busy(btn, async () => {
          try {
            await api(`/api/admin/elections/${e.id}/close`, { method: "POST", role: "admin" });
            toast("Voting closed. You can publish the results now.");
            loadAdminElections();
            loadAdminSummary();
          } catch (err) {
            toast(err.message, true);
          }
        });
      });
      actions.append(btn);
    } else if (!e.results_announced) {
      status = h("span", { class: "status status-warn" }, "Closed, not counted");
      const btn = h("button", { type: "button", class: "btn btn-primary btn-small" }, "Count and publish");
      btn.addEventListener("click", async () => {
        const ok = await confirmDialog({
          title: "Count and publish results?",
          body: [
            h("p", null, `Each of the ${plural(e.ballots_cast, "ballot")} in `, h("strong", null, e.title), " is verified and decrypted, then the totals become visible to everyone."),
          ],
          confirmLabel: "Publish results",
        });
        if (!ok) return;
        busy(btn, async () => {
          try {
            const res = await api(`/api/admin/elections/${e.id}/publish-results`, { method: "POST", role: "admin" });
            const rejected = (res.integrity_failures || []).length;
            toast(
              `Results published: ${plural(res.total_valid_votes, "valid ballot")}` +
                (rejected ? `, ${rejected} rejected` : ""),
            );
            loadAdminElections();
            loadAdminSummary();
          } catch (err) {
            toast(err.message, true);
          }
        });
      });
      actions.append(btn);
    } else {
      status = h("span", { class: "status" }, "Results published");
    }
    return h(
      "tr",
      null,
      h("td", null, h("span", { class: "cell-title" }, e.title), h("span", { class: "cell-sub" }, SCOPE[e.category] || e.category)),
      h("td", { class: "num" }, e.contestant_count),
      h("td", { class: "num" }, e.ballots_cast),
      h("td", null, status),
      actions,
    );
  });
  panel.replaceChildren(
    h(
      "div",
      { class: "table-wrap" },
      h(
        "table",
        null,
        h(
          "thead",
          null,
          h(
            "tr",
            null,
            h("th", null, "Election"),
            h("th", { class: "num" }, "Candidates"),
            h("th", { class: "num" }, "Ballots"),
            h("th", null, "Status"),
            h("th", { class: "actions" }, h("span", { class: "hidden" }, "Actions")),
          ),
        ),
        h("tbody", null, rows),
      ),
    ),
  );
}

async function loadRequests() {
  const panel = $("#a-panel-requests");
  let data;
  try {
    data = await api("/api/admin/registrations?status_filter=pending", { role: "admin" });
  } catch (err) {
    panel.replaceChildren(h("p", { class: "empty" }, err.message));
    return;
  }
  if (!data.registrations.length) {
    panel.replaceChildren(h("p", { class: "empty" }, "No requests are waiting. Voters appear here when they ask to join an election."));
    return;
  }
  const decide = (r, verb, btn) =>
    busy(btn, async () => {
      try {
        await api(`/api/admin/registrations/${r.id}/${verb}`, { method: "POST", role: "admin" });
        toast(verb === "approve" ? `${r.voter_id} can now vote` : `Request from ${r.voter_id} declined`);
        loadRequests();
        loadAdminSummary();
      } catch (err) {
        toast(err.message, true);
      }
    });
  const rows = data.registrations.map((r) => {
    const approve = h("button", { type: "button", class: "btn btn-primary btn-small" }, "Approve");
    const decline = h("button", { type: "button", class: "btn btn-small" }, "Decline");
    approve.addEventListener("click", () => decide(r, "approve", approve));
    decline.addEventListener("click", () => decide(r, "reject", decline));
    return h(
      "tr",
      null,
      h("td", null, h("span", { class: "cell-title" }, r.full_name || r.voter_id), r.full_name && h("span", { class: "cell-sub" }, r.voter_id)),
      h(
        "td",
        null,
        r.identity_verified_at
          ? [h("span", { class: "status status-ok" }, "Verified"), h("span", { class: "cell-sub" }, `${r.identity_label} ${r.identity_masked || ""}`)]
          : h("span", { class: "status status-warn" }, "Not verified"),
      ),
      h("td", null, r.election_title),
      h("td", null, fmtDate(r.created_at)),
      h("td", { class: "actions" }, approve, decline),
    );
  });
  panel.replaceChildren(
    h(
      "div",
      { class: "table-wrap" },
      h(
        "table",
        null,
        h(
          "thead",
          null,
          h(
            "tr",
            null,
            h("th", null, "Voter"),
            h("th", null, "Identity"),
            h("th", null, "Election"),
            h("th", null, "Requested"),
            h("th", { class: "actions" }),
          ),
        ),
        h("tbody", null, rows),
      ),
    ),
  );
}

/* ---------- Admin: new election ---------- */

function addContestantRow() {
  const node = $("#tpl-contestant-row").content.cloneNode(true);
  const row = node.querySelector(".contestant-row");
  row.querySelector(".rm-row").addEventListener("click", () => {
    if ($$(".contestant-row").length <= 1) {
      toast("An election needs at least one candidate", true);
      return;
    }
    row.remove();
  });
  $("#contestant-rows").appendChild(row);
  return row;
}

$("#btn-add-contestant").addEventListener("click", () => addContestantRow().querySelector(".c-name").focus());

function initCreateForm() {
  const form = $("#form-create-election");
  if (!$$(".contestant-row").length) {
    addContestantRow();
    addContestantRow();
  }
  if (!form.starts_at.value) {
    const pad = (n) => String(n).padStart(2, "0");
    const local = (d) =>
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    form.starts_at.value = local(new Date());
    form.ends_at.value = local(new Date(Date.now() + 7 * 86400000));
  }
}

$("#form-create-election").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const names = [];
  const files = [];
  for (const r of $$(".contestant-row", form)) {
    names.push(r.querySelector(".c-name").value.trim());
    files.push(r.querySelector(".c-photo").files[0]);
  }
  if (new Date(form.ends_at.value) <= new Date(form.starts_at.value)) {
    toast("Voting must close after it opens", true);
    form.ends_at.focus();
    return;
  }
  const big = files.find((f) => f && f.size > 2 * 1024 * 1024);
  if (big) {
    toast(`${big.name} is larger than 2 MB`, true);
    return;
  }
  const fd = new FormData();
  fd.append("title", form.title.value.trim());
  fd.append("category", form.category.value);
  fd.append("starts_at", localToIsoZ(form.starts_at.value));
  fd.append("ends_at", localToIsoZ(form.ends_at.value));
  fd.append("contestant_names", JSON.stringify(names));
  files.forEach((file) => fd.append("photos", file));

  await busy(e.submitter, async () => {
    try {
      await api("/api/admin/elections", { method: "POST", role: "admin", body: fd });
      form.reset();
      $("#contestant-rows").replaceChildren();
      toast("Election created");
      loadAdminSummary();
      aTab("elections");
    } catch (err) {
      toast(err.message, true);
    }
  });
});

/* ---------- Security lab ---------- */

/**
 * Like api(), but never throws on an HTTP error and has no side effects (no sign-out on 401):
 * the lab expects to be rejected and wants to show the exact status and message.
 */
async function rawApi(path, { method = "GET", json, role } = {}) {
  const headers = {};
  if (json !== undefined) headers["Content-Type"] = "application/json";
  const vt = localStorage.getItem(LS.voterTok);
  const at = localStorage.getItem(LS.adminTok);
  const tok = role === "voter" ? vt : role === "admin" ? at : role === "any" ? vt || at : null;
  if (tok) headers.Authorization = `Bearer ${tok}`;
  const r = await fetch(path, { method, headers, body: json !== undefined ? JSON.stringify(json) : undefined });
  let data = {};
  try {
    data = await r.json();
  } catch {
    /* empty body */
  }
  const detail = typeof data.detail === "string" ? data.detail : data.detail ? JSON.stringify(data.detail) : r.statusText;
  return { ok: r.ok, status: r.status, data, detail };
}

const short = (s, n = 56) => (s.length > n ? `${s.slice(0, n)}…` : s);

const lab = { elections: [], targetId: null };
const labTarget = () => lab.elections.find((e) => String(e.id) === String(lab.targetId)) || null;

function needVoterTarget({ voted = false, key = false } = {}) {
  if (!localStorage.getItem(LS.voterTok)) return "Sign in as a voter in this browser to run this attack.";
  const t = labTarget();
  if (!t) return "Needs an open election that this voter is approved for. Request access and approve it first.";
  if (voted && !t.my_voted) return `Vote in “${t.title}” first. This attack then tries to vote a second time.`;
  if (key && !localStorage.getItem(LS.voterKey)) return "This browser has no signing key for the voter. Create one on the Elections page.";
  return null;
}

/** Shared ending for attacks 1–3: show the server's answer. */
function verdict(log, r, expected, explain) {
  if (r.ok) {
    log("Server response", "exposed", [`${r.status}: the server accepted the ballot.`]);
    return "exposed";
  }
  log("Server response", "blocked", [
    `${r.status} ${r.detail}`,
    r.status === expected ? explain : "Rejected by an earlier check before this defence was reached.",
  ]);
  return "blocked";
}

async function labBallotSetup(log) {
  const t = labTarget();
  const d = await api(`/api/elections/${t.id}/detail`, { auth: "voter" });
  const c = d.contestants[0];
  const enc = encryptBallot(c.id, d.public_key_pem);
  log("Build a real encrypted ballot", "info", [`Vote for ${c.name} in “${t.title}”, encrypted with the election's RSA-OAEP key.`], short(enc, 88));
  return { t, enc };
}

const ATTACKS = [
  {
    key: "forged",
    title: "Forged signature",
    story: "Submit a ballot signed with a key that isn't the voter's, hoping the server only checks that a signature is present.",
    defence: "RSA-PSS verification against the voter's registered public key",
    blocker: () => needVoterTarget(),
    async run(log) {
      const { t, enc } = await labBallotSetup(log);
      const kp = await generateVoterKeyPair();
      if (!kp) throw new Error("This browser can't generate keys (WebCrypto is unavailable).");
      const ts = isoNow();
      const sig = signBallot(enc, ts, kp.privatePem);
      log("Sign it with the attacker's own key", "info", ["A fresh RSA-2048 key pair made in this browser, not the voter's registered key."], short(sig, 88));
      const r = await rawApi(`/api/elections/${t.id}/vote`, {
        method: "POST",
        role: "voter",
        json: { voter_id: localStorage.getItem(LS.voterId), encrypted_vote: enc, signature: sig, timestamp: ts },
      });
      return verdict(log, r, 409, "The signature does not verify with the voter's public key, so the ballot was discarded before storage. The administrator has been alerted.");
    },
  },
  {
    key: "replay",
    title: "Replayed or backdated ballot",
    story: "Send a correctly signed ballot whose timestamp is two hours old, as if it had been captured earlier and replayed.",
    defence: "Server clock plus a 5-minute limit on the signed timestamp",
    blocker: () => needVoterTarget({ key: true }),
    async run(log) {
      const { t, enc } = await labBallotSetup(log);
      const ts = isoNow(-2 * 3600 * 1000);
      const sig = signBallot(enc, ts, localStorage.getItem(LS.voterKey));
      log("Sign it with the voter's real key, dated two hours ago", "info", [`Timestamp ${ts}. The signature itself is valid.`]);
      const r = await rawApi(`/api/elections/${t.id}/vote`, {
        method: "POST",
        role: "voter",
        json: { voter_id: localStorage.getItem(LS.voterId), encrypted_vote: enc, signature: sig, timestamp: ts },
      });
      return verdict(log, r, 422, "The signed time is checked against the server's clock, so an old ballot can't be replayed. The administrator has been alerted.");
    },
  },
  {
    key: "double",
    title: "Second vote",
    story: "Cast a fresh, validly signed ballot in an election this voter has already voted in.",
    defence: "One ballot per voter per election, enforced in the database",
    blocker: () => needVoterTarget({ voted: true, key: true }),
    async run(log) {
      const { t, enc } = await labBallotSetup(log);
      const ts = isoNow();
      const sig = signBallot(enc, ts, localStorage.getItem(LS.voterKey));
      log("Sign it properly with the voter's key", "info", ["Everything about this ballot is valid except that the voter has already voted."]);
      const r = await rawApi(`/api/elections/${t.id}/vote`, {
        method: "POST",
        role: "voter",
        json: { voter_id: localStorage.getItem(LS.voterId), encrypted_vote: enc, signature: sig, timestamp: ts },
      });
      return verdict(log, r, 403, "A ballot from this voter is already stored for this election (and the database has a unique constraint). The administrator has been alerted.");
    },
  },
  {
    key: "otp",
    title: "Guessing the login code",
    story: "With a stolen password, guess the 6-digit code instead of reading the victim's email.",
    defence: "The code is burned after 5 wrong tries",
    form: true,
    blocker(ui) {
      if (!ui.email.value.trim() || !ui.password.value) return "Enter a voter's email and password on this card (pretend they were stolen).";
      return null;
    },
    async run(log, ui) {
      const email = ui.email.value.trim().toLowerCase();
      const password = ui.password.value;
      const first = await rawApi("/api/login", { method: "POST", json: { voter_id: email, password } });
      if (!first.ok || !first.data.otp_required) throw new Error(`Sign-in with that password failed: ${first.status} ${first.detail}`);
      log("Sign in with the stolen password", "info", [
        "Password accepted. The server sends a 6-digit code to the voter's email.",
        "The attacker can't read that inbox, so they guess.",
      ]);
      const real = first.data.dev_otp;
      const lines = [];
      let last = null;
      for (let i = 1; i <= 5; i++) {
        let guess;
        do guess = String(Math.floor(Math.random() * 1e6)).padStart(6, "0");
        while (guess === real);
        last = await rawApi("/api/login", { method: "POST", json: { voter_id: email, password, otp: guess } });
        lines.push(`Guess ${i}: ${guess} → ${last.status} ${last.detail}`);
      }
      log("Guess the code five times", "info", lines);
      if (real) {
        const r = await rawApi("/api/login", { method: "POST", json: { voter_id: email, password, otp: real } });
        log("Now try the real code", r.ok ? "exposed" : "blocked", [
          r.ok ? "The real code still worked." : `${r.status} ${r.detail}`,
          r.ok ? "" : "After 5 misses the code is destroyed, so even a lucky later guess is useless. The odds of hitting it in 5 tries are 5 in a million. The administrator has been alerted.",
        ].filter(Boolean));
        return r.ok ? "exposed" : "blocked";
      }
      return /Too many/.test(last.detail) ? "blocked" : "exposed";
    },
  },
  {
    key: "sniff",
    title: "Sniffing campus Wi-Fi",
    story: "Record the bytes of a login as they cross the network and search them for the password.",
    defence: "TLS 1.3 with forward-secret key exchange (ECDHE) and AES-GCM",
    endpoint: "/api/lab/sniff",
  },
  {
    key: "tls",
    title: "Fake server or old protocol",
    story: "Force the connection down to TLS 1.1, or run an impostor server with its own certificate.",
    defence: "TLS 1.2 minimum and certificates checked against the SecureVote CA",
    endpoint: "/api/lab/tls",
  },
  {
    key: "db",
    title: "Stolen database file",
    story: "Copy voting.db and attack it offline: open election keys, decrypt ballots, crack passwords, read ID numbers.",
    defence: "AES-256-GCM election keys, bcrypt passwords, HMAC-protected ID numbers, secrets kept outside the database",
    endpoint: "/api/lab/db-theft",
  },
];

function labStepEl(s) {
  return h(
    "li",
    { class: `lab-step is-${s.status}` },
    h("p", { class: "lab-step-title" }, s.title),
    (s.lines || []).map((l) => h("p", { class: "lab-step-line" }, l)),
    s.code && h("pre", { class: "lab-code" }, s.code),
  );
}

function setLabStatus(ui, kind, text) {
  ui.status.className = `status${kind ? ` status-${kind}` : ""}`;
  ui.status.textContent = text;
}

function renderLab() {
  const list = $("#lab-list");
  if (list.childElementCount) return;
  ATTACKS.forEach((a, i) => {
    const ui = {};
    ui.status = h("span", { class: "status" }, "Not run");
    ui.btn = h("button", { type: "button", class: "btn btn-small" }, "Run attack");
    ui.note = h("p", { class: "lab-note hidden" });
    ui.log = h("ol", { class: "lab-log hidden" });
    let form = null;
    if (a.form) {
      ui.email = h("input", { type: "email", autocomplete: "off", placeholder: "voter@umsystem.edu" });
      ui.password = h("input", { type: "password", autocomplete: "off" });
      form = h(
        "div",
        { class: "lab-form" },
        h("label", { class: "field" }, h("span", { class: "field-label" }, "Victim's email"), ui.email),
        h("label", { class: "field" }, h("span", { class: "field-label" }, "Stolen password"), ui.password),
      );
    }
    a.ui = ui;
    ui.btn.addEventListener("click", () => runAttack(a));
    list.append(
      h(
        "li",
        { class: "lab-card", id: `lab-${a.key}` },
        h(
          "div",
          { class: "lab-head" },
          h("span", { class: "lab-num" }, String(i + 1)),
          h("div", { class: "lab-titles" }, h("h2", null, a.title), h("p", { class: "lab-story" }, a.story)),
          h("div", { class: "lab-side" }, ui.status, ui.btn),
        ),
        h("p", { class: "lab-defence" }, h("span", null, "Defence"), a.defence),
        form,
        ui.note,
        ui.log,
      ),
    );
  });
}

async function runAttack(a) {
  const ui = a.ui;
  const why = a.blocker ? a.blocker(ui) : null;
  if (why) {
    ui.note.textContent = why;
    ui.note.classList.remove("hidden");
    setLabStatus(ui, "warn", "Can't run yet");
    return "skipped";
  }
  ui.note.classList.add("hidden");
  ui.log.replaceChildren();
  ui.log.classList.remove("hidden");
  setLabStatus(ui, null, "Running…");
  const log = (title, status = "info", lines = [], code = null) => ui.log.append(labStepEl({ title, status, lines, code }));
  let outcome = "error";
  await busy(ui.btn, async () => {
    try {
      if (a.endpoint) {
        const r = await rawApi(a.endpoint, { method: "POST", role: "any" });
        if (!r.ok) throw new Error(`${r.status} ${r.detail}`);
        r.data.steps.forEach((s) => ui.log.append(labStepEl(s)));
        if (r.data.outcome === "error") throw new Error(r.data.summary);
        outcome = r.data.outcome;
      } else {
        outcome = await a.run(log, ui);
      }
    } catch (err) {
      log("The attack could not run", "warn", [err.message]);
      outcome = "error";
    }
  });
  if (outcome === "blocked") setLabStatus(ui, "ok", "Stopped");
  else if (outcome === "exposed") setLabStatus(ui, "danger", "Not stopped");
  else setLabStatus(ui, "warn", "Didn't run");
  return outcome;
}

async function loadLab() {
  renderLab();
  const otp = ATTACKS.find((a) => a.key === "otp").ui;
  if (!otp.email.value) otp.email.value = localStorage.getItem(LS.voterId) || "";
  const sel = $("#lab-target");
  const hint = $("#lab-target-hint");
  lab.elections = [];
  if (localStorage.getItem(LS.voterTok)) {
    try {
      const { elections } = await api("/api/elections", { auth: "voter" });
      const now = Date.now();
      lab.elections = elections.filter(
        (e) => e.my_registration_status === "approved" && !e.closed && now >= Date.parse(e.starts_at) && now <= Date.parse(e.ends_at),
      );
    } catch {
      /* shown as "no target" below */
    }
  }
  const keep = lab.targetId;
  sel.replaceChildren(
    ...lab.elections.map((e) => h("option", { value: String(e.id) }, `${e.title} · ${e.my_voted ? "already voted" : "not voted yet"}`)),
  );
  if (!lab.elections.length) sel.append(h("option", { value: "" }, "No open election to target"));
  sel.disabled = !lab.elections.length;
  lab.targetId = lab.elections.some((e) => String(e.id) === String(keep)) ? keep : lab.elections[0]?.id ?? null;
  if (lab.targetId != null) sel.value = String(lab.targetId);
  const who = localStorage.getItem(LS.voterId);
  hint.textContent = !localStorage.getItem(LS.voterTok)
    ? "Attacks 1–3 act as a signed-in voter. Sign in as a voter in this browser to run them; attacks 4–7 work from any session."
    : lab.elections.length
      ? `Attacks 1–3 act as ${who}. Rejected ballots never use up the real vote.`
      : `Attacks 1–3 act as ${who}, who has no approved, open election. Request access and approve it in Administration.`;
}

$("#lab-target").addEventListener("change", (e) => {
  lab.targetId = e.target.value || null;
});

$("#lab-run-all").addEventListener("click", async (e) => {
  const btn = e.currentTarget;
  await busy(btn, async () => {
    const tally = { blocked: 0, exposed: 0, other: 0 };
    for (const a of ATTACKS) {
      const o = await runAttack(a);
      if (o === "blocked") tally.blocked++;
      else if (o === "exposed") tally.exposed++;
      else tally.other++;
    }
    const parts = [`${tally.blocked} stopped`];
    if (tally.exposed) parts.push(`${tally.exposed} not stopped`);
    if (tally.other) parts.push(`${tally.other} couldn't run`);
    toast(`Attacks finished: ${parts.join(", ")}`, tally.exposed > 0);
  });
});

/* ---------- Start: verify the stored session with the server before trusting it ---------- */

/** Open the view named in the address bar (#voter, #admin, #lab) if this session may see it. */
async function openFromHash() {
  const want = location.hash.slice(1);
  const vt = localStorage.getItem(LS.voterTok);
  const at = localStorage.getItem(LS.adminTok);
  if (want === "lab" && (vt || at)) {
    showView("lab");
    await loadLab();
    return true;
  }
  if (want === "admin" && at) {
    showView("admin");
    await loadAdminDashboard();
    return true;
  }
  if (want === "voter" && vt) {
    showView("voter");
    await loadVoterDashboard();
    return true;
  }
  return false;
}

window.addEventListener("hashchange", () => {
  if (location.hash.slice(1) !== currentView) openFromHash();
});

(async function boot() {
  showTransportBadge();
  updateNav();
  const vt = localStorage.getItem(LS.voterTok);
  const at = localStorage.getItem(LS.adminTok);
  if (vt) {
    try {
      await api("/api/voter/session", { auth: "voter" });
    } catch {
      /* api() already cleared the session and showed the sign-in view */
    }
  }
  if (await openFromHash()) return;
  const voterOk = Boolean(localStorage.getItem(LS.voterTok));
  if (voterOk) {
    showView("voter");
    await loadVoterDashboard();
    return;
  }
  if (at) {
    showView("admin");
    await loadAdminDashboard();
    return;
  }
  showView("login");
  refreshAdminSetupUi();
})();
