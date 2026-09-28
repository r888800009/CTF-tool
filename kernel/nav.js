// Shared cross-module navigation bar. The server injects a <script src="/nav.js">
// into every viewer's page; this fetches /nav (the list of regviz-family web views
// currently running in the same gdb process) and renders a sticky bar at the top
// so you can jump between the loaded modules. Links use the browser's own hostname
// so they work whether you reached the page over loopback or a LAN address.
(function () {
  function build(j) {
    var apps = (j && j.apps) || [];
    var bar = document.getElementById("regviz-nav");
    if (!bar) {
      bar = document.createElement("nav");
      bar.id = "regviz-nav";
      document.body.insertBefore(bar, document.body.firstChild);
    }
    bar.innerHTML = "";
    var brand = document.createElement("span");
    brand.className = "rvnav-brand";
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
      link.className = "rvnav-item" + (a.prefix === j.current ? " cur" : "");
      link.href = location.protocol + "//" + location.hostname + ":" + a.port + "/";
      link.innerHTML =
        '<span class="rvnav-label">' + (a.label || a.prefix) + "</span>" +
        '<span class="rvnav-port">:' + a.port + "</span>";
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
