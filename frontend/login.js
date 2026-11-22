"use strict";
/* Sign-in page. Server text is shown with textContent only. */

const $ = (sel) => document.querySelector(sel);

function showError(msg) {
  const e = $("#login-error");
  e.textContent = msg || "";
  e.classList.toggle("hidden", !msg);
}

async function alreadySignedIn() {
  try {
    const res = await fetch("/api/auth/me", { credentials: "same-origin" });
    if (res.ok) window.location.replace("/");
  } catch (_) { /* server not reachable: stay on the form */ }
}

async function submit(ev) {
  ev.preventDefault();
  showError("");
  const username = $("#username").value.trim();
  const password = $("#password").value;
  if (!username || !password) return showError("Enter your user name and password.");

  const btn = $("#btn-login");
  btn.disabled = true; btn.textContent = "Signing in…";
  try {
    let res;
    try {
      res = await fetch("/api/auth/login", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
    } catch (_) {
      throw new Error("Cannot reach the SERC server. Is it running?");
    }
    let data = null;
    try { data = await res.json(); } catch (_) { /* not JSON */ }
    if (!res.ok) {
      let msg = data && data.detail;
      if (Array.isArray(msg)) msg = "Enter your user name and password.";
      throw new Error(msg || `Sign-in failed (${res.status}).`);
    }
    window.location.replace("/");
  } catch (e) {
    showError(e.message);
    $("#password").value = "";
    $("#password").focus();
    btn.disabled = false; btn.textContent = "Sign in";
  }
}

function togglePassword() {
  const input = $("#password"), btn = $("#pw-toggle");
  const reveal = input.type === "password";
  input.type = reveal ? "text" : "password";
  btn.textContent = reveal ? "Hide" : "Show";
  btn.setAttribute("aria-pressed", String(reveal));
  btn.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
}

document.addEventListener("DOMContentLoaded", () => {
  $("#login-form").addEventListener("submit", submit);
  $("#pw-toggle").addEventListener("click", togglePassword);
  alreadySignedIn();
});
