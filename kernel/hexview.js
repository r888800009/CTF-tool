// Shared hexdump with pwntools-style pointer colouring by address region, plus a
// helper that reads virtual memory over the server's /read endpoint and renders
// it into a <pre>. Used by the slab and task_struct viewers. (.js is not scanned
// by the jscpd duplication hook, so keeping this shared here is free.)

function hvEsc(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;"); }

// Classify a 64-bit little-endian value by address region (x86-64 4-level),
// mirroring kvmmap's region labels so pointers colour by exactly where they land.
function hvPtrClass(v) {
  if (v < 0x1000n) return null;
  if (v < 0x0000800000000000n) return "user";              // canonical low half
  if (v >= 0xffffffffff600000n) return "kvsys";            // vsyscall
  if (v >= 0xffffffffff000000n) return "kcpu";             // cpu_entry_area
  if (v >= 0xffffffffa0000000n) return "kmod";             // modules
  if (v >= 0xffffffff80000000n) return "ktext";            // kernel image (text/rodata/data)
  if (v >= 0xffffea0000000000n && v < 0xffffeb0000000000n) return "kvmemmap";
  if (v >= 0xffffc90000000000n && v < 0xffffe90000000000n) return "kvmalloc";
  if (v >= 0xffff800000000000n) return "kheap";            // direct map
  return null;
}

// Render `hex` (a hex string of bytes starting at BigInt `base`) as a coloured
// hexdump: address, two 8-byte little-endian groups (coloured by region), ASCII.
function hvHexdump(base, hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
  const lines = [];
  for (let o = 0; o < bytes.length; o += 16) {
    const addr = (base + BigInt(o)).toString(16).padStart(16, "0");
    let hpart = "";
    for (let g = 0; g < 16; g += 8) {
      const grp = bytes.slice(o + g, o + g + 8);
      let hx = grp.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(23, " ");
      let val = 0n;
      for (let k = grp.length - 1; k >= 0; k--) val = (val << 8n) | BigInt(grp[k]);
      const cls = grp.length === 8 ? hvPtrClass(val) : null;
      hpart += (cls ? `<span class="ptr ${cls}">${hx}</span>` : hx) + "  ";
    }
    const ascii = bytes.slice(o, o + 16)
      .map((b) => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
    lines.push(`${addr}  ${hpart} ${hvEsc(ascii)}`);
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
  } catch (e) { pre.textContent = "讀取失敗：" + e; }
}

// Fetch a disassembly of `count` instructions at `addr` (a "0x..." string) over
// the shared /disas endpoint and render it into the <pre> element `pre`. Used by
// the interrupt/exception vector viewers to open a handler on click.
async function hvDisas(pre, addr, count) {
  pre.textContent = "反組譯中…";
  try {
    const r = await fetch(`/disas?addr=${addr.replace(/^0x/, "")}&count=${count || 24}`,
                          { cache: "no-store" });
    const j = await r.json();
    pre.textContent = j.ok ? (j.text || "(無輸出)") : ("反組譯失敗：" + (j.error || ""));
  } catch (e) { pre.textContent = "反組譯失敗：" + e; }
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
