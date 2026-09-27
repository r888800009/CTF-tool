// AArch64 (ARM64) EL1 system-register schema, consumed by the shared regviz.html engine.
// Each entry: {name, desc, width?, addr?, flags?{bit:[mn,desc]},
//              fields?[{hi,lo,mn,desc,map?}], decode?(BigInt)->[[k,v],...]}.
window.REGVIZ_TITLE = "AArch64 EL1 System Registers";
window.REGS = [
  {
    name: "SCTLR_EL1", width: 64,
    desc: "System Control Register (EL1) — MMU, caches, alignment and pointer-auth controls.",
    flags: {
      0:  ["M", "MMU enable for EL1&0 stage 1 translation."],
      1:  ["A", "Alignment check enable."],
      2:  ["C", "Data/unified cacheability enable for EL1&0."],
      3:  ["SA", "Stack Alignment check enable at EL1."],
      4:  ["SA0", "Stack Alignment check enable at EL0."],
      5:  ["CP15BEN", "AArch32 CP15 barrier (DMB/DSB/ISB) enable."],
      6:  ["nAA", "Non-aligned access — 1 = allow unaligned LDAR/STLR etc."],
      7:  ["ITD", "AArch32 IT-block disable of deprecated encodings."],
      8:  ["SED", "AArch32 SETEND instruction disable."],
      9:  ["UMA", "User Mask Access — EL0 access to PSTATE.DAIF."],
      12: ["I", "Instruction cacheability enable for EL1&0."],
      13: ["EnDB", "Enable pointer authentication (APDBKey, data key B)."],
      14: ["DZE", "EL0 access to DC ZVA enable."],
      15: ["UCT", "EL0 access to CTR_EL0 enable."],
      16: ["nTWI", "Trap EL0 WFI — 0 = trap to EL1."],
      18: ["nTWE", "Trap EL0 WFE — 0 = trap to EL1."],
      19: ["WXN", "Write permission implies Execute-Never at EL1&0."],
      20: ["TSCXT", "Trap EL0 access to SCXTNUM_EL0 (0 = trap)."],
      21: ["IESB", "Implicit Error Synchronization event enable."],
      23: ["SPAN", "Set Privileged Access Never — 0 = set PSTATE.PAN on exception entry."],
      24: ["EOE", "Endianness of explicit data accesses at EL0."],
      25: ["EE", "Endianness of translation-table walks / data at EL1 (1 = big-endian)."],
      26: ["UCI", "EL0 access to DC/IC cache-maintenance instructions enable."],
      27: ["EnDA", "Enable pointer authentication (APDAKey, data key A)."],
      28: ["nTLSMD", "AArch32 no-Trap load/store multiple to Device memory."],
      29: ["LSMAOE", "AArch32 Load/Store Multiple Atomicity and Ordering enable."],
      30: ["EnIB", "Enable pointer authentication (APIBKey, instruction key B)."],
      31: ["EnIA", "Enable pointer authentication (APIAKey, instruction key A)."],
      35: ["BT0", "PACIxSP as BTI-compatible guarded landing pad at EL0."],
      36: ["BT1", "PACIxSP as BTI-compatible guarded landing pad at EL1."],
    },
  },
  {
    name: "TCR_EL1", width: 64,
    desc: "Translation Control Register (EL1) — region sizes, granules, cacheability and shareability.",
    flags: {
      7:  ["EPD0", "Disable translation-table walks for TTBR0_EL1 region."],
      22: ["A1", "TTBR1_EL1.ASID defines the ASID (0 = TTBR0)."],
      23: ["EPD1", "Disable translation-table walks for TTBR1_EL1 region."],
      36: ["AS", "ASID size (0 = 8-bit, 1 = 16-bit)."],
      37: ["TBI0", "Top Byte Ignored for TTBR0_EL1 addresses."],
      38: ["TBI1", "Top Byte Ignored for TTBR1_EL1 addresses."],
      39: ["HA", "Hardware Access flag update enable."],
      40: ["HD", "Hardware management of dirty state enable."],
    },
    fields: [
      { hi: 5,  lo: 0,  mn: "T0SZ", desc: "TTBR0 region size offset (VA size = 64 - T0SZ)." },
      { hi: 9,  lo: 8,  mn: "IRGN0", desc: "TTBR0 inner cacheability of walks." },
      { hi: 11, lo: 10, mn: "ORGN0", desc: "TTBR0 outer cacheability of walks." },
      { hi: 13, lo: 12, mn: "SH0", desc: "TTBR0 shareability of walks." },
      { hi: 15, lo: 14, mn: "TG0", desc: "TTBR0 granule size.", map: { "0": "4KB", "1": "64KB", "2": "16KB" } },
      { hi: 21, lo: 16, mn: "T1SZ", desc: "TTBR1 region size offset (VA size = 64 - T1SZ)." },
      { hi: 31, lo: 30, mn: "TG1", desc: "TTBR1 granule size.", map: { "1": "16KB", "2": "4KB", "3": "64KB" } },
      { hi: 34, lo: 32, mn: "IPS", desc: "Intermediate Physical Address Size." },
    ],
  },
  {
    name: "TTBR0_EL1", addr: true,
    desc: "Translation Table Base Register 0 (EL1) — low-VA (user) base and ASID.",
    decode: (v) => [
      ["BADDR (base)", "0x" + (v & ~0x1n & ((1n << 48n) - 1n)).toString(16)],
      ["ASID (bits 63:48)", "0x" + ((v >> 48n) & 0xFFFFn).toString(16)],
    ],
  },
  {
    name: "TTBR1_EL1", addr: true,
    desc: "Translation Table Base Register 1 (EL1) — high-VA (kernel) base and ASID.",
    decode: (v) => [
      ["BADDR (base)", "0x" + (v & ~0x1n & ((1n << 48n) - 1n)).toString(16)],
      ["ASID (bits 63:48)", "0x" + ((v >> 48n) & 0xFFFFn).toString(16)],
    ],
  },
  {
    name: "MAIR_EL1", addr: true,
    desc: "Memory Attribute Indirection Register (EL1) — 8 attribute bytes (Attr0..Attr7).",
    decode: (v) => {
      const names = {
        0x00: "Device-nGnRnE",
        0x44: "Normal Non-cacheable",
        0xff: "Normal WB RW-alloc",
      };
      const rows = [];
      for (let i = 0; i < 8; i++) {
        const b = Number((v >> BigInt(8 * i)) & 0xffn);
        const hex = "0x" + b.toString(16).padStart(2, "0");
        rows.push(["Attr" + i, names[b] ? hex + " (" + names[b] + ")" : hex]);
      }
      return rows;
    },
  },
  {
    name: "ESR_EL1", addr: true,
    desc: "Exception Syndrome Register (EL1) — exception class and syndrome of the taken exception.",
    decode: (v) => [
      ["EC (bits 31:26)", "0x" + ((v >> 26n) & 0x3Fn).toString(16)],
      ["IL (bit 25)", String((v >> 25n) & 1n)],
      ["ISS (bits 24:0)", "0x" + (v & 0x1FFFFFFn).toString(16)],
    ],
  },
  {
    name: "FAR_EL1", addr: true,
    desc: "Fault Address Register (EL1) — faulting virtual address of a synchronous exception.",
  },
  {
    name: "VBAR_EL1", addr: true,
    desc: "Vector Base Address Register (EL1) — base of the EL1 exception vector table.",
  },
  {
    name: "CPACR_EL1", width: 32,
    desc: "Architectural Feature Access Control Register (EL1) — SVE, FP/SIMD and trace access.",
    flags: {
      28: ["TTA", "Trap trace-register accesses from EL0/EL1."],
    },
    fields: [
      { hi: 17, lo: 16, mn: "ZEN", desc: "SVE (Z-register) access control for EL0/EL1." },
      { hi: 21, lo: 20, mn: "FPEN", desc: "FP/SIMD access control for EL0/EL1." },
    ],
  },
  {
    name: "CurrentEL", width: 4,
    desc: "Current Exception Level (bits 3:2 hold the level).",
    fields: [
      { hi: 3, lo: 2, mn: "EL", desc: "Current exception level.", map: { "0": "EL0", "1": "EL1", "2": "EL2", "3": "EL3" } },
    ],
    decode: (v) => [["EL", String((v >> 2n) & 3n)]],
  },
  {
    name: "DAIF", width: 16,
    desc: "Interrupt mask bits (PSTATE.DAIF). Same bit positions as in PSTATE/CPSR.",
    flags: {
      6: ["F", "FIQ mask."],
      7: ["I", "IRQ mask."],
      8: ["A", "SError/abort mask."],
      9: ["D", "Debug mask."],
    },
  },
  {
    name: "SPSR_EL1", addr: true,
    desc: "Saved Program Status Register (EL1) — PSTATE saved on exception entry to EL1.",
  },
  {
    name: "ELR_EL1", addr: true,
    desc: "Exception Link Register (EL1) — return address for the exception taken to EL1.",
  },
];
