// MalSense loading screen: shown while a page loads and when leaving a page (link click / form submit).
(function () {
  const el = document.getElementById("ms-loader");
  if (!el) return;

  function show() { el.classList.remove("is-leaving"); el.classList.add("is-on"); }
  function hide() {
    if (!el.classList.contains("is-on")) return;
    el.classList.add("is-leaving");
    setTimeout(() => el.classList.remove("is-on", "is-leaving"), 350);
  }
  window.showLoader = show;                      // pages can call this before form.submit()
  window.hideLoader = hide;

  // Page finished loading -> hide. Also hide when coming back with the Back button (page cache).
  if (document.readyState === "complete") hide(); else window.addEventListener("load", hide);
  window.addEventListener("pageshow", e => { if (e.persisted) hide(); });

  // Links that download a file keep you on the same page, so they must not show the loader.
  const DOWNLOAD = /\/report\/\d+\.(pdf|docx)$|\/download$/;

  document.addEventListener("click", e => {
    const a = e.target.closest("a[href]");
    if (!a || e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    if (a.target && a.target !== "_self") return;
    if (a.hasAttribute("download") || a.hasAttribute("data-no-loader")) return;
    const url = new URL(a.href, location.href);
    if (url.origin !== location.origin || DOWNLOAD.test(url.pathname)) return;
    if (url.pathname === location.pathname && url.search === location.search && url.hash) return;  // same-page #anchor
    show();
  });

  document.addEventListener("submit", e => {
    if (e.defaultPrevented || e.target.hasAttribute("data-no-loader")) return;
    show();
  });
})();
