"use strict";
/* SERC theme controller (light / dark).
   Load this in <head> WITHOUT defer so the right theme is applied before first paint (no flash).
   - First visit: always light, regardless of the operating-system setting.
   - After the user clicks the toggle: their choice is remembered in localStorage.
   - Any element with [data-theme-toggle] becomes a toggle button. */
(function () {
  var KEY = "serc-theme";
  var root = document.documentElement;
  var COLORS = { light: "#f7f5fc", dark: "#0f0e17" };

  function stored() {
    try { var v = localStorage.getItem(KEY); return v === "light" || v === "dark" ? v : null; }
    catch (_) { return null; }
  }
  function remember(v) { try { localStorage.setItem(KEY, v); } catch (_) { /* private mode: ignore */ } }
  function current() { return root.getAttribute("data-theme") === "dark" ? "dark" : "light"; }

  function syncButtons(theme) {
    var next = theme === "dark" ? "light" : "dark";
    var btns = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < btns.length; i++) {
      btns[i].setAttribute("aria-label", "Switch to " + next + " theme");
      btns[i].setAttribute("title", "Switch to " + next + " theme");
      btns[i].setAttribute("aria-pressed", String(theme === "dark"));
    }
  }

  function apply(theme) {
    root.setAttribute("data-theme", theme);
    root.style.colorScheme = theme;
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", COLORS[theme]);
    syncButtons(theme);
  }

  function animateSwitch() {
    root.classList.add("theme-transition");
    window.setTimeout(function () { root.classList.remove("theme-transition"); }, 400);
  }

  // 1. Apply immediately (script runs in <head>)
  apply(stored() || "light");

  // 2. Wire up buttons once the DOM exists
  document.addEventListener("DOMContentLoaded", function () {
    syncButtons(current());
    var btns = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener("click", function () {
        var next = current() === "dark" ? "light" : "dark";
        animateSwitch(); apply(next); remember(next);
      });
    }
  });

  // 3. Always print on white paper, then restore the user's theme
  var before = null;
  window.addEventListener("beforeprint", function () { before = current(); apply("light"); });
  window.addEventListener("afterprint", function () { if (before) apply(before); before = null; });
})();
