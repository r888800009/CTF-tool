// Shared hexdump with pwntools-style pointer colouring by address region, plus a
// helper that reads virtual memory over the server's /read endpoint and renders
// it into a <pre>, and the floating disassembly/hex window. Shared by every
// viewer, which keeps it DRY (the jscpd pre-commit hook scans JS too).

function hvEsc(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;"); }

// Classify a 64-bit little-endian value by address region (x86-64, 4- and
// 5-level), mirroring kvmmap's region labels so pointers colour by exactly where
// they land. The top of the space (text/modules/vsyscall/cpu_entry_area) is the
// same in both modes; the 5-level (LA57) mid-space windows sit well below the
// 4-level kernel half, so recognising both needs no paging-mode flag.
let _hvImg = null;   // [lo, hi] BigInt kernel-image extent, from /kinfo (KASLR-aware)

function hvPtrClass(v) {
  if (v < 0x1000n) return null;
  if (v < 0x0000800000000000n) return "user";              // canonical low half
  if (v >= 0xffffffffff600000n) return "kvsys";            // vsyscall
  if (v >= 0xffffffffff000000n) return "kcpu";             // cpu_entry_area / fixmap
  if (v >= 0xffffffff80000000n) {                          // kernel image + modules window
    if (_hvImg) return (v >= _hvImg[0] && v < _hvImg[1]) ? "ktext" : "kmod";
    return v >= 0xffffffffa0000000n ? "kmod" : "ktext";    // no /kinfo: classic fixed split
  }
  if (v >= 0xfffffe0000000000n && v < 0xfffffe8000000000n) return "kcpu"; // CPU_ENTRY_AREA_BASE
  // 4-level windows
  if (v >= 0xffffea0000000000n && v < 0xffffeb0000000000n) return "kvmemmap";
  if (v >= 0xffffc90000000000n && v < 0xffffe90000000000n) return "kvmalloc";
  if (v >= 0xffff800000000000n) return "kheap";            // direct map
  // 5-level (LA57) windows
  if (v >= 0xffd4000000000000n && v < 0xffd6000000000000n) return "kvmemmap";
  if (v >= 0xffa0000000000000n && v < 0xffd2000000000000n) return "kvmalloc";
  if (v >= 0xff11000000000000n && v < 0xff91000000000000n) return "kheap"; // direct map
  return null;
}

// Fetch the kernel-image extent once so hvPtrClass can tell kernel text from
// modules even under KASLR (symbols can't — the loaded vmlinux isn't relocated).
// Safe to call repeatedly; silently leaves the fixed-threshold fallback on failure.
async function hvInitKinfo() {
  try {
    const j = await (await fetch("/kinfo", { cache: "no-store" })).json();
    _hvImg = (j.ok && j.img) ? [BigInt(j.img[0]), BigInt(j.img[1])] : null;
  } catch (e) { /* keep the fixed-threshold fallback */ }
}

// Render `hex` (a hex string of bytes starting at BigInt `base`) as a coloured
// hexdump: address, two 8-byte little-endian groups (coloured by region), ASCII.
// `markAddr` (optional BigInt) highlights the line that covers that address.
function hvHexdump(base, hex, markAddr) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
  const lines = [];
  for (let o = 0; o < bytes.length; o += 16) {
    const la = base + BigInt(o);
    const addr = la.toString(16).padStart(16, "0");
    let hpart = "";
    for (let g = 0; g < 16; g += 8) {
      const grp = bytes.slice(o + g, o + g + 8);
      let hx = grp.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(23, " ");
      let val = 0n;
      for (let k = grp.length - 1; k >= 0; k--) val = (val << 8n) | BigInt(grp[k]);
      const cls = grp.length === 8 ? hvPtrClass(val) : null;
      if (cls && (cls === "ktext" || cls === "kmod")) {   // a code pointer: follow it
        hpart += `<span class="ptr ${cls} disas-addr" data-a="0x${val.toString(16)}">${hx}</span>  `;
      } else {
        hpart += (cls ? `<span class="ptr ${cls}">${hx}</span>` : hx) + "  ";
      }
    }
    const ascii = bytes.slice(o, o + 16)
      .map((b) => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
    let line = `${addr}  ${hpart} ${hvEsc(ascii)}`;
    if (markAddr !== undefined && markAddr >= la && markAddr < la + 16n) {
      line = `<span class="hex-cur">${line}</span>`;
    }
    lines.push(line);
  }
  return lines.join("\n");
}

// Fetch `count` bytes of virtual memory at `addr` (a "0x..." string) via /read
// and render a coloured hexdump into the <pre> element `pre`.
async function hvLoad(pre, addr, count) {
  try {
    const r = await fetch(`/read?addr=${addr.replace(/^0x/, "")}&count=${count}`,
                          { cache: "no-store" });
    const j = await r.json();
    if (!j.ok) { pre.textContent = "讀取失敗：" + j.error; return; }
    pre.innerHTML = hvHexdump(BigInt(addr), j.hex);
    hvWireDisasLinks(pre);   // code pointers → floating disassembly window
  } catch (e) { pre.textContent = "讀取失敗：" + e; }
}

// Turn gdb `x/i` disassembly text into HTML where every address token
// (0x… with 5+ hex digits — instruction addresses and branch/call targets alike)
// becomes a clickable link that deep-dives into the floating window. `<sym+off>`
// annotations are kept as plain (escaped) text.
function hvLinkifyDisas(text) {
  return hvEsc(text).replace(/0x[0-9a-fA-F]{5,}/g, (m) => {
    let cls = "";
    try { const c = hvPtrClass(BigInt(m)); if (c) cls = " " + c; } catch (e) {}
    return `<span class="disas-addr ptr${cls}" data-a="${m}">${m}</span>`;
  });
}

// Delegate clicks on any .disas-addr inside `el` to open the floating window.
function hvWireDisasLinks(el) {
  el.addEventListener("click", (ev) => {
    const a = ev.target.closest(".disas-addr");
    if (a) { ev.stopPropagation(); hvDisasOpen(a.dataset.a); }
  });
}

// Fetch a disassembly of `count` instructions at `addr` (a "0x..." string) over
// the shared /disas endpoint and render it (addresses linkified) into the <pre>
// element `pre`. Clicking any address opens the floating disassembly window, so an
// inline handler dump becomes a jumping-off point for following calls.
async function hvDisas(pre, addr, count) {
  pre.textContent = "反組譯中…";
  try {
    const r = await fetch(`/disas?addr=${addr.replace(/^0x/, "")}&count=${count || 24}`,
                          { cache: "no-store" });
    const j = await r.json();
    if (!j.ok) { pre.textContent = "反組譯失敗：" + (j.error || ""); return; }
    pre.innerHTML = hvLinkifyDisas(j.text || "(無輸出)");
    hvWireDisasLinks(pre);
  } catch (e) { pre.textContent = "反組譯失敗：" + e; }
}

// ---- Floating disassembly / hex windows ----------------------------------
// Each click spawns its OWN draggable window (so several can sit side by side).
// A window keeps a browser-style history of visited addresses — ◀ back / ▶ forward,
// a ⌄ dropdown to jump to any entry, ⌂ to return to the entry point (which stays
// marked) — and grows its view as you scroll past the top ("往更前面") or bottom
// ("往前滑動"). It shows asm or a hex dump, auto-picked from whether the page is
// executable (/vaperm) and switchable with the auto/asm/hex buttons. Addresses are
// coloured with the hvPtrClass convention. Open with hvDisasOpen("0x...").
let _hvZ = 1000;          // z-order counter (clicking a window raises it)
let _hvSeq = 0;           // cascade offset for newly spawned windows
const _HV_CHUNK = 40;     // instructions fetched per asm view / scroll-append
const _HV_HEXBYTES = 512; // bytes per hex view / scroll step
const _HV_HEXCAP = 0x8000;// stop growing a hex buffer past this many bytes

function _hvLastAddr(text) {
  const lines = text.replace(/\s+$/, "").split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = lines[i].match(/0x[0-9a-fA-F]+/);
    if (m) return m[0];
  }
  return null;
}
function _hvTopAddr(text) {
  const m = text.replace(/^\s+/, "").match(/0x[0-9a-fA-F]+/);
  return m ? m[0] : null;
}

async function _hvFetch(addr, count) {
  const r = await fetch(`/disas?addr=${addr.replace(/^0x/, "")}&count=${count}`,
                        { cache: "no-store" });
  return r.json();
}
async function _hvReadHex(addr, n) {
  try {
    const j = await (await fetch(`/read?addr=${addr.replace(/^0x/, "")}&count=${n}`,
                                 { cache: "no-store" })).json();
    return j.ok ? j.hex : null;
  } catch (e) { return null; }
}
async function _hvVaPerm(addr) {
  try {
    const j = await (await fetch(`/vaperm?addr=${addr.replace(/^0x/, "")}`,
                                 { cache: "no-store" })).json();
    return (j && j.ok) ? j : null;
  } catch (e) { return null; }
}

// Render the current history entry, choosing asm vs hex. In "auto" the choice
// follows whether the page is executable; asm/hex force it.
async function _hvRender(win) {
  const addr = win._hist[win._idx];
  const body = win.querySelector(".hv-disbody");
  win._cur = addr;
  win._lastAddr = win._topAddr = null;
  win._loading = false;
  win._atEnd = win._atStart = false;
  win.querySelector(".hv-disin").value = addr;
  _hvSyncNav(win);
  body.textContent = "讀取中…";
  let mode = win._pref;
  if (mode === "auto") {
    const perm = await _hvVaPerm(addr);
    if (win._cur !== addr) return;                       // superseded by a newer nav
    if (perm && !perm.present) {
      win._mode = "asm"; _hvSyncMode(win);
      body.innerHTML = `<span class="hv-warn">位址未映射於目前 CR3：${addr}（not present）</span>`;
      return;
    }
    mode = (perm && perm.x === false) ? "hex" : "asm";   // executable→asm, data→hex, unknown→asm
  }
  win._mode = mode;
  _hvSyncMode(win);
  if (mode === "hex") await _hvRenderHex(win, addr);
  else await _hvRenderAsm(win, addr);
}

async function _hvRenderAsm(win, addr) {
  const body = win.querySelector(".hv-disbody");
  try {
    const j = await _hvFetch(addr, _HV_CHUNK);
    if (win._cur !== addr) return;
    if (!j.ok) { body.innerHTML = `<span class="hv-warn">反組譯失敗：${hvEsc(j.error || "")}</span>`; return; }
    const text = j.text || "(無輸出)";
    body.innerHTML = hvLinkifyDisas(text);
    const cur = body.querySelector(`.disas-addr[data-a="${addr}"]`);
    if (cur) cur.classList.add("disas-cur");            // mark the entry point
    win._lastAddr = _hvLastAddr(text);
    win._topAddr = _hvTopAddr(text);
    body.scrollTop = 0;
  } catch (e) { body.textContent = "反組譯失敗：" + e; }
}

async function _hvRenderHex(win, addr) {
  const body = win.querySelector(".hv-disbody");
  win._hexBase = BigInt(addr);
  try {
    const hex = await _hvReadHex(addr, _HV_HEXBYTES);
    if (win._cur !== addr) return;
    if (hex == null) { body.innerHTML = `<span class="hv-warn">讀取失敗：${addr}</span>`; return; }
    win._hexData = hex;
    body.innerHTML = hvHexdump(win._hexBase, hex, BigInt(addr));   // mark the entry line
    body.scrollTop = 0;
  } catch (e) { body.textContent = "讀取失敗：" + e; }
}

// Navigate to a brand-new address: truncate any forward history, then push.
function _hvGo(win, addr) {
  if (win._idx >= 0 && win._hist[win._idx] === addr) { _hvHome(win); return; }
  win._hist = win._hist.slice(0, win._idx + 1);
  win._hist.push(addr);
  win._idx = win._hist.length - 1;
  _hvRender(win);
}
function _hvBack(win) { if (win._idx > 0) { win._idx--; _hvRender(win); } }
function _hvFwd(win) { if (win._idx < win._hist.length - 1) { win._idx++; _hvRender(win); } }
function _hvJump(win, i) { if (i >= 0 && i < win._hist.length) { win._idx = i; _hvRender(win); } }

// Scroll the marked entry point back into view (⌂ / Home).
function _hvHome(win) {
  const m = win.querySelector(".disas-cur, .hex-cur");
  if (m) m.scrollIntoView({ block: "center", behavior: "smooth" });
}

// Reflect history state onto ◀ / ▶ and (re)build the ⌄ dropdown.
function _hvSyncNav(win) {
  win.querySelector('[data-act="back"]').disabled = win._idx <= 0;
  win.querySelector('[data-act="fwd"]').disabled = win._idx >= win._hist.length - 1;
  const menu = win.querySelector(".hv-dishist");
  menu.innerHTML = win._hist.map((a, i) => {
    const c = (() => { try { return hvPtrClass(BigInt(a)) || ""; } catch (e) { return ""; } })();
    return `<div class="hv-histitem ptr ${c}${i === win._idx ? " cur" : ""}" data-i="${i}">${a}</div>`;
  }).reverse().join("");
}

// Reflect the active/effective mode onto the auto/asm/hex buttons.
function _hvSyncMode(win) {
  win.querySelectorAll(".hv-mode").forEach((b) => {
    b.classList.toggle("active", b.dataset.m === win._pref);
    b.classList.toggle("eff", win._pref === "auto" && b.dataset.m === win._mode);
  });
}

// --- scroll-driven growth (dispatched by the current mode) -----------------
function _hvMore(win) { return win._mode === "hex" ? _hvMoreHex(win) : _hvMoreAsm(win); }
function _hvPrev(win) { return win._mode === "hex" ? _hvPrevHex(win) : _hvPrevAsm(win); }

async function _hvMoreAsm(win) {
  if (win._loading || win._atEnd || !win._lastAddr) return;
  win._loading = true;
  try {
    const j = await _hvFetch(win._lastAddr, _HV_CHUNK + 1);
    if (!j.ok || !j.text) { win._atEnd = true; return; }
    const lines = j.text.replace(/\s+$/, "").split("\n").slice(1);  // drop dup first line
    const next = _hvLastAddr(lines.join("\n"));
    if (!lines.length || !next || next === win._lastAddr) { win._atEnd = true; return; }
    win.querySelector(".hv-disbody").insertAdjacentHTML(
      "beforeend", "\n" + hvLinkifyDisas(lines.join("\n")));
    win._lastAddr = next;
  } finally { win._loading = false; }
}

// Prepend earlier instructions ("往更前面"). x86 is variable-length, so we
// disassemble from a little before the top and keep the lines that land before it.
async function _hvPrevAsm(win) {
  if (win._loading || win._atStart || !win._topAddr) return;
  win._loading = true;
  try {
    const start = "0x" + (BigInt(win._topAddr) - 0x40n).toString(16);
    const j = await _hvFetch(start, 24);
    if (!j.ok || !j.text) { win._atStart = true; return; }
    const top = BigInt(win._topAddr);
    const kept = j.text.replace(/\s+$/, "").split("\n").filter((l) => {
      const m = l.match(/0x[0-9a-fA-F]+/);
      return m && BigInt(m[0]) < top;
    });
    const newTop = kept.length ? kept[0].match(/0x[0-9a-fA-F]+/)[0] : null;
    if (!newTop || BigInt(newTop) >= top) { win._atStart = true; return; }
    const body = win.querySelector(".hv-disbody");
    const oldH = body.scrollHeight, oldT = body.scrollTop;
    body.insertAdjacentHTML("afterbegin", hvLinkifyDisas(kept.join("\n")) + "\n");
    body.scrollTop = oldT + (body.scrollHeight - oldH);   // keep the view steady
    win._topAddr = newTop;
  } finally { win._loading = false; }
}

async function _hvMoreHex(win) {
  if (win._loading || win._atEnd) return;
  if (win._hexData.length / 2 >= _HV_HEXCAP) { win._atEnd = true; return; }
  win._loading = true;
  try {
    const at = "0x" + (win._hexBase + BigInt(win._hexData.length / 2)).toString(16);
    const hex = await _hvReadHex(at, _HV_HEXBYTES);
    if (!hex) { win._atEnd = true; return; }
    win._hexData += hex;
    const body = win.querySelector(".hv-disbody");
    const t = body.scrollTop;
    body.innerHTML = hvHexdump(win._hexBase, win._hexData, BigInt(win._cur));
    body.scrollTop = t;
  } finally { win._loading = false; }
}

async function _hvPrevHex(win) {
  if (win._loading || win._atStart || win._hexBase <= 0x1000n) { win._atStart = win._atStart || win._hexBase <= 0x1000n; return; }
  win._loading = true;
  try {
    const start = win._hexBase - BigInt(_HV_HEXBYTES);
    const hex = await _hvReadHex("0x" + start.toString(16), _HV_HEXBYTES);
    if (!hex) { win._atStart = true; return; }
    win._hexData = hex + win._hexData;
    win._hexBase = start;
    const body = win.querySelector(".hv-disbody");
    const oldH = body.scrollHeight, oldT = body.scrollTop;
    body.innerHTML = hvHexdump(win._hexBase, win._hexData, BigInt(win._cur));
    body.scrollTop = oldT + (body.scrollHeight - oldH);
  } finally { win._loading = false; }
}

function _hvMakeDraggable(win, handle) {
  handle.addEventListener("mousedown", (e) => {
    if (e.target.closest(".hv-disbtn")) return;   // let buttons click
    const sx = e.clientX, sy = e.clientY;
    const r = win.getBoundingClientRect(), ox = r.left, oy = r.top;
    win.style.right = "auto";
    const mv = (ev) => {
      win.style.left = Math.max(0, ox + ev.clientX - sx) + "px";
      win.style.top = Math.max(0, oy + ev.clientY - sy) + "px";
    };
    const up = () => {
      document.removeEventListener("mousemove", mv);
      document.removeEventListener("mouseup", up);
    };
    document.addEventListener("mousemove", mv);
    document.addEventListener("mouseup", up);
    e.preventDefault();
  });
}

// Spawn a new floating disassembly window on `addr`.
function hvDisasOpen(addr) {
  const win = document.createElement("div");
  win.className = "hv-diswin";
  win._hist = []; win._idx = -1; win._pref = "auto"; win._mode = "asm";
  win.innerHTML =
    '<div class="hv-dishead">' +
      '<button class="hv-disbtn" data-act="back" title="上一個位址 (Backspace)">◀</button>' +
      '<button class="hv-disbtn" data-act="fwd" title="下一個位址">▶</button>' +
      '<button class="hv-disbtn" data-act="home" title="回到起點 (Home)">⌂</button>' +
      '<button class="hv-disbtn" data-act="hist" title="瀏覽歷史">⌄</button>' +
      '<input class="hv-distitle hv-disin" spellcheck="false" autocomplete="off" ' +
        'placeholder="輸入位址 0x… (Enter)" title="輸入記憶體位址後按 Enter">' +
      '<span class="hv-modes">' +
        '<button class="hv-disbtn hv-mode" data-act="mode" data-m="auto" title="自動：依頁面可否執行選擇">auto</button>' +
        '<button class="hv-disbtn hv-mode" data-act="mode" data-m="asm" title="反組譯">asm</button>' +
        '<button class="hv-disbtn hv-mode" data-act="mode" data-m="hex" title="十六進位">hex</button>' +
      '</span>' +
      '<span class="hv-disgrip" title="拖曳移動">⠿</span>' +
      '<button class="hv-disbtn" data-act="close" title="關閉 (Esc)">✕</button>' +
    '</div>' +
    '<div class="hv-dishist"></div>' +
    '<pre class="hex hv-disbody"></pre>';
  document.body.appendChild(win);
  const off = (_hvSeq++ % 10) * 22;
  win.style.top = (64 + off) + "px";
  win.style.right = (24 + off) + "px";
  win.style.zIndex = ++_hvZ;
  win.style.display = "flex";
  win.tabIndex = -1;
  win.addEventListener("mousedown", () => { win.style.zIndex = ++_hvZ; });
  const body = win.querySelector(".hv-disbody");
  body.addEventListener("click", (ev) => {
    const a = ev.target.closest(".disas-addr"); if (!a) return;
    ev.stopPropagation(); _hvGo(win, a.dataset.a);
  });
  body.addEventListener("scroll", () => {
    if (body.scrollTop + body.clientHeight >= body.scrollHeight - 48) _hvMore(win);
    else if (body.scrollTop <= 48) _hvPrev(win);
  });
  // Type an address and press Enter to disassemble it.
  const input = win.querySelector(".hv-disin");
  input.addEventListener("keydown", (ev) => {
    ev.stopPropagation();   // don't trigger the window's Esc/Backspace shortcuts
    if (ev.key !== "Enter") return;
    let a = input.value.trim();
    if (!a) return;
    if (!/^0x/i.test(a)) a = "0x" + a;
    if (/^0x[0-9a-fA-F]+$/.test(a)) _hvGo(win, a.toLowerCase());
    else input.value = win._cur || "";   // reject junk, restore
  });
  input.addEventListener("mousedown", (ev) => ev.stopPropagation());  // don't drag
  win.querySelector(".hv-dishist").addEventListener("click", (ev) => {
    const it = ev.target.closest(".hv-histitem"); if (!it) return;
    win.querySelector(".hv-dishist").classList.remove("open");
    _hvJump(win, Number(it.dataset.i));
  });
  win.querySelector(".hv-dishead").addEventListener("click", (ev) => {
    const b = ev.target.closest(".hv-disbtn"); if (!b) return;
    const act = b.dataset.act;
    if (act === "close") win.remove();
    else if (act === "back") _hvBack(win);
    else if (act === "fwd") _hvFwd(win);
    else if (act === "home") _hvHome(win);
    else if (act === "hist") win.querySelector(".hv-dishist").classList.toggle("open");
    else if (act === "mode") { win._pref = b.dataset.m; _hvRender(win); }
  });
  win.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") win.remove();
    else if (ev.key === "Backspace") { ev.preventDefault(); _hvBack(win); }
    else if (ev.key === "Home") { ev.preventDefault(); _hvHome(win); }
  });
  _hvMakeDraggable(win, win.querySelector(".hv-dishead"));
  win.focus();
  _hvGo(win, addr);
  return win;
}

// Wire a clickable address element `el` so clicking it toggles an inline
// disassembly at `addr`. Inside a table it opens a full-width detail row (so the
// disassembly is flush left, not squeezed into one column); elsewhere it inserts a
// <pre> right after the element.
function hvDisasToggle(el, addr) {
  el.classList.add("disas-link");
  el.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const row = el.closest("tr");
    if (row) {
      if (row._disasRow) { row._disasRow.remove(); row._disasRow = null; return; }
      const dt = document.createElement("tr");
      dt.className = "disas-row";
      const td = document.createElement("td");
      td.colSpan = row.children.length;
      td.style.textAlign = "left";
      const pre = document.createElement("pre");
      pre.className = "hex disas-out";
      td.appendChild(pre);
      dt.appendChild(td);
      row.parentNode.insertBefore(dt, row.nextSibling);
      row._disasRow = dt;
      hvDisas(pre, addr, 24);
    } else {
      let pre = el._disasPre;
      if (pre && pre.parentNode) { pre.remove(); el._disasPre = null; return; }
      pre = document.createElement("pre");
      pre.className = "hex disas-out";
      el.parentNode.insertBefore(pre, el.nextSibling);
      el._disasPre = pre;
      hvDisas(pre, addr, 24);
    }
  });
}

// A colour legend row (HTML string) for the regions hvPtrClass distinguishes.
function hvLegend() {
  const items = [["ktext", "image"], ["kmod", "modules"], ["kheap", "direct-map"],
    ["kvmalloc", "vmalloc"], ["kvmemmap", "vmemmap"], ["kcpu", "cpu_entry"],
    ["kvsys", "vsyscall"], ["user", "user"]];
  return '<div class="leg">' +
    items.map(([c, l]) => `<span class="${c}">■</span> ${l}`).join("　") + "</div>";
}

hvInitKinfo();   // resolve the kernel-image extent as soon as this script loads
