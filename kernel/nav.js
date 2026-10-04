// Shared cross-module navigation bar. The server injects a <script src="/nav.js">
// into every viewer's page; this fetches /nav (every viewer registered on the
// shared hub) and renders a sticky bar at the top so you can jump between tools.
// All tools live on one port now, so each link is just /<prefix>/ (absolute, so it
// is unaffected by the page's <base>); the current tool is the first path segment.
(function () {
  function curPrefix() {
    var m = location.pathname.replace(/^\/+/, "").split("/");
    return m[0] || "";
  }
  function build(j) {
    var apps = (j && j.apps) || [];
    var cur = curPrefix();
    var bar = document.getElementById("regviz-nav");
    if (!bar) {
      bar = document.createElement("nav");
      bar.id = "regviz-nav";
      document.body.insertBefore(bar, document.body.firstChild);
    }
    bar.innerHTML = "";
    var brand = document.createElement("a");
    brand.className = "rvnav-brand";
    brand.href = "/";
    brand.textContent = "kernel viewers";
    bar.appendChild(brand);

    if (!apps.length) {
      var none = document.createElement("span");
      none.className = "rvnav-empty";
      none.textContent = "（無其他模組）";
      bar.appendChild(none);
      return;
    }
    apps.forEach(function (a) {
      var link = document.createElement("a");
      link.className = "rvnav-item" + (a.prefix === cur ? " cur" : "");
      link.href = "/" + a.prefix + "/";
      link.innerHTML =
        '<span class="rvnav-label">' + (a.label || a.prefix) + "</span>" +
        '<span class="rvnav-port">' + a.prefix + "</span>";
      bar.appendChild(link);
    });
  }

  function refresh() {
    fetch("/nav", { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(build)
      .catch(function () {});
  }

  function start() {
    refresh();
    // Re-poll occasionally so modules started/stopped later appear or drop off.
    setInterval(refresh, 5000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
