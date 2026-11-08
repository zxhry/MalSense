// MalSense theme switch: light <-> dark. The choice is remembered in this browser.
// (The <head> of base.html already applied the saved theme before the page was drawn, so there is no flash.)
//
// Animation when the sun/moon button is clicked: a smooth fade from one theme to the other (about 0.45 s).
//   - Chrome / Edge: the whole page cross-fades (View Transitions API) - background included
//   - other browsers: the colours fade
//   - "reduce motion" switched on in the device settings: instant switch, no animation
(function () {
  var root = document.documentElement;

  function set(t) {
    root.setAttribute("data-theme", t);
    try { localStorage.setItem("ms-theme", t); } catch (e) { /* private window: just don't remember */ }
    document.querySelectorAll(".themebtn").forEach(function (b) {
      var next = t === "light" ? "dark" : "light";
      b.setAttribute("aria-label", "Switch to " + next + " theme");
      b.title = "Switch to " + next + " theme";
    });
  }

  function switchTheme(btn) {
    var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
    var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (reduce) { set(next); return; }

    // fallback: smooth colour fade
    if (!document.startViewTransition) {
      root.classList.add("theme-fade");
      set(next);
      setTimeout(function () { root.classList.remove("theme-fade"); }, 450);
      return;
    }

    // whole-page cross-fade (the speed is set in themes.css)
    document.startViewTransition(function () { set(next); });
  }

  document.querySelectorAll(".themebtn").forEach(function (b) {
    b.addEventListener("click", function () { switchTheme(b); });
  });
  set(root.getAttribute("data-theme") || "dark");   // dark is the default
})();
