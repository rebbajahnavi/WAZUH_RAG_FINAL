"use strict";
/* Slide-away top bar: hides when you scroll down, returns when you scroll up.
   Always visible at the very top of the page, and while a control inside it has keyboard focus. */
(function () {
  var bar = document.querySelector(".topbar");
  if (!bar) return;

  var THRESHOLD = 8;      // ignore tiny scroll jitters (px)
  var REVEAL_TOP = 90;    // always show when this close to the top (px)
  var lastY = window.scrollY, ticking = false;

  function update() {
    var y = Math.max(window.scrollY, 0), delta = y - lastY;
    if (y < REVEAL_TOP) bar.classList.remove("is-hidden");
    else if (delta > THRESHOLD) bar.classList.add("is-hidden");      // scrolling down
    else if (delta < -THRESHOLD) bar.classList.remove("is-hidden");  // scrolling up
    if (Math.abs(delta) > THRESHOLD || y < REVEAL_TOP) lastY = y;
    ticking = false;
  }

  window.addEventListener("scroll", function () {
    if (!ticking) { ticking = true; window.requestAnimationFrame(update); }
  }, { passive: true });

  // keyboard users: tabbing into the bar brings it back
  bar.addEventListener("focusin", function () { bar.classList.remove("is-hidden"); });
})();
