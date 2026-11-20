# DiE-Helper

A fork of [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) (the [DIE-engine](https://github.com/horsicq/DIE-engine) GUI and console sources) that shows **how** an EXE or DLL is packed or obfuscated, and helps unpack it. All analysis is static: files are read, never run.

What it adds to DiE:
- **A Packing tab** next to the detection list: a verdict, a colour-coded section map (entropy, flags, entry point), ranked evidence with clickable hex/disassembly locations, and unpacking hints per packer.
- **Static unpacking**: DiE's built-in unpackers, a UPX header repair, an OEP finder, and a generic decompressor that rebuilds a PE. It restores UPX 5 files including relocations and imports.
- **Deobfuscation views**: recovered strings, API-hash resolution, and a .NET view for obfuscated names.
- **Tools**: PE edits on copies, HTML/Markdown/JSON reports, a custom-signature maker, batch scanning, and optional external tools (upx, de4dot).

Build: see [Build (Windows, MSVC)](#build-windows-msvc). Details of every feature are in the section below.

Detect It Easy is created and maintained by [horsicq](https://github.com/horsicq). This is an independent, unofficial fork that is not affiliated with the original project. The original MIT license and copyright are kept in [LICENSE](LICENSE).

---

## DiE Helper: the Packing tab

DiE says **what** packed or protected a file. This fork adds a **Packing** tab next to DiE's detection
list that shows **why** it was flagged and **how** an EXE/DLL is packed or obfuscated, plus how to unpack it.

### What the Packing tab shows
- **Tab title = verdict.** It's coloured so you can read it without opening the tab:
  - red: `Packing: UPX 5.30` or `Packing: likely packed`
  - orange: `Packing: none, anti-analysis` or `Packing: none, obfuscated`
  - green: `Packing: none`
- **Verdict line:**
  - *PACKED / PROTECTED: \<name\>* when DiE has a signature for the packer
  - *LIKELY PACKED - unknown packer* when it does not but the file evidence says so
  - an *OBFUSCATION: ...* / *ANTI-ANALYSIS: ...* line naming what was found
  - scores (packing, obfuscation/anti-analysis, 0-100), PE32/64, EXE/DLL, .NET, file entropy
- **Section map:** the PE layout drawn to scale.
  - Each section is coloured by entropy: blue data, green code, orange suspicious, red packed/encrypted.
  - Virtual-only sections (e.g. `UPX0`, the unpacking target) are hatched.
  - R/W/X flags are shown, with RWX marked `!`.
  - The overlay is included, and an **EP** marker points at the entry point.
  - Hover a section for its offsets, sizes and flags; click it to open DiE's **hex view** on that section.
  - Click EP to open the **disassembler** at the entry point.
- **Entry point line:** RVA, file offset, section and flags, the first EP bytes, and *disassemble* / *hex* links.
- **Ranked indicators** (strongest first; click the *Location* cell to open hex/disasm there):
  - **DiE's own detections**, including heuristic reasons and which signature file matched (main or custom DB)
  - **Packing:** high-entropy sections, EP in last / RWX / non-first section, virtual-only and empty sections,
    raw << virtual size, imports rebuilt at run time (LoadLibrary+GetProcAddress only), PUSHAD / `call $+5` stubs,
    unusual section names, high-entropy overlay
  - **Obfuscation:** dynamic API resolution, very few strings, elevated code entropy, decryption APIs,
    **obfuscated .NET type/method names** (invisible / look-alike / 1-letter names, read from CLI metadata)
  - **Anti-analysis:** anti-debug APIs, timing checks, injection APIs, **TLS callbacks** (code before EP), window/process enumeration
  - When the file is packed, facts that are just side effects of packing (few strings, GetProcAddress) are
    marked *expected while the file is packed* and do not count as obfuscation.
- **How to unpack** (collapsible): the hint for the detected packer from `helper/hints.json`.
  It covers what it does, the OEP pattern, what to try first, tools, pitfalls, notes, and DLL-specific advice for DLLs.
  - Unknown packers get the generic method.
  - Selecting another row in *Detections* shows that detection's hint.

Nothing is ever executed: all analysis is static, using DiE's own parsers (`XPE`, `XCLIAssembly`).

### Actions toolbar: static unpacking and deobfuscation (in the Packing tab)
All analysis is static: no sample is ever run. Every action reads the original and writes a new copy.
By default a *Save as* dialog asks where; **Options -> Helper -> Auto folder** writes results there without asking.
After a file action you can choose **Open in DiE**, **Compare before/after** (two section maps + scores) or **Show folder**.
Results appear as tabs next to *Indicators*; their *Location* cells open hex/disasm. An *Action log* tab records everything.

| Button | What it does |
|---|---|
| **Unpack \<packer\>** | DiE's built-in static unpackers (XStaticUnpacker): UPX, ASPack, FSG, MEW, NsPack, Petite, yC. Shown only when one recognises the file. |
| **Repair UPX** | Shown for tampered UPX. Restores renamed `UPX0/UPX1/UPX2` names and a wiped `UPX!` magic in a copy, then unpacks it. If the built-in unpacker still fails, it saves the repaired copy, which `upx -d` then unpacks (tested: original 0 files, repaired 1 file). |
| **Find OEP** | Walks the unpacking stub with DiE's disassembler and ranks original-entry-point candidates: pushad/popad + far jmp, push/ret, `mov reg,imm; jmp reg`, `jmp [mem]`, jumps into virtual-only sections, UPX/NsPack/ASPack tails. Each comes with a confidence and the reason. |
| **Decompress** | Unknown packers: tries NRV2B/D/E, LZMA, aPLib, zlib/deflate and LZNT1 on blobs the stub points at. Then either saves the raw data or **rebuilds a PE**: the data goes back into the image, spread over the following sections when needed, and the entry point is set to the best OEP. |
| **Strings** | Stack strings, XOR/ADD/ROL/rolling-XOR brute force, .NET user strings. |
| **API hashes** | ror13 / ror13+module / crc32 / djb2 / fnv1a / sdbm constants resolved against export names read from System32 DLLs. Also GetProcAddress/LoadLibrary call sites with their (stack-string) arguments. |
| **.NET** | Obfuscated type/method names with readable aliases, obfuscator markers (ConfuserEx, Dotfuscator, SmartAssembly, Babel, Agile.NET, .NET Reactor, ...), encrypted/high-entropy method bodies, user strings. |
| **PE tools** | Set entry point (pre-filled with the best OEP), rebuild imports (static), restore section flags (drop RWX), rename section, remove TLS callbacks, strip/save overlay, save section, fix checksum. |
| **More** | Extract embedded files (DiE's extractor), export report (HTML/Markdown/JSON), **make custom signature** (EP pattern with wildcards -> `db_custom/PE/<type>_<name>.2.sg`), **batch scan** a folder (table + CSV). |
| **Tools** | Optional external tools set in Options -> Helper: `upx -d`, `de4dot`, or a custom command line (`%in%` / `%out%`). They only ever see a copy. |

Known limits:
- DiE's built-in UPX unpacker does not handle UPX 5.x output. **Decompress -> Rebuild PE** does, statically, using what UPX stores in its own stream:
  - undoes the call/jump filter (0x14/0x16/0x24/0x26/0x36/0x46/0x49);
  - restores relocated addresses, 32- and 64-bit (UPX stores them big-endian, relative to the image);
  - rebuilds the import table from UPX's packed import list into a new `.idata` section, keeping the original IAT addresses;
  - restores the original section names and clears the leftover `UPX!` header.

  Tested on MSVC x86/x64 EXEs and DLLs packed with UPX 5.30: `.text`, `.data` and `.pdata` are byte-identical to the original, the imports are the same set, and DiE reports the compiler with no packer. Only the old import-table bytes in `.rdata` differ, because the table now lives in `.idata`. **Tools -> upx -d** remains an alternative.
- Rebuilt files are meant for static analysis. Imports are reconstructed only when the loader data is recognisable.
- .NET deobfuscation is read-only, since DiE has no metadata writer. Use the optional de4dot button to actually rename and clean.
- **Future:** emulated unpacking with the unicorn engine (run only the stub in a CPU emulator until the OEP, then dump). It is not built because it adds a dependency.

### Hints file
- `helper/hints.json` is installed as `<exe dir>\helper\hints.json`. It is plain JSON keyed by DiE detection name.
- Fields: `name`, `category`, `aliases`, `what_it_does`, `oep_pattern`, `try_first[]`, `tools[]`, `pitfalls[]`, `notes`, `dll_notes`.
- Lookup ignores case and version numbers and understands aliases (`Confuser` -> `ConfuserEx`, `Themida` -> `Themida/Winlicense`).
- **Options -> Helper** points DiE to another hints file and shows "N hints loaded" or the exact JSON error (line/column).
  The setting is stored in `helper.ini` next to `die.exe`; `die.ini` is untouched.

### My own signatures: `db_custom/`
- `db_custom/` (repo top level) is installed to `<exe dir>\db_custom`, which is DiE's built-in **custom database** path (Options -> Scan).
- It uses the same layout as `db/` (`PE/`, `ELF/`, ...). Never put an `_init` there.
- Example: `db_custom/PE/packer_UPX_renamed_sections.2.sg` detects UPX whose sections were renamed. It reports e.g.
  `UPX (renamed sections) (5.30) [sections: abc0,abc1]`, and stays silent on normal UPX.

### Updating the signature database without touching this work
The official DB lives in the submodule `dep/Detect-It-Easy` (`db/`). The Helper and custom signatures live outside it
(`helper/`, `db_custom/`, `src/gui/helper/`). To update, do any one of:
- click **Update database** in DiE, or run `die-update`. These only replace the main `db`, never `db_custom`.
- or drop a newer `db` folder into `dep/Detect-It-Easy/db` and rebuild/install (the build copies it next to `die.exe`).
- or replace `release\die_win64_qt6\db` directly.

### Build (Windows, MSVC)
1. Visual Studio 2022 with the C++ workload. Its bundled CMake + Ninja are used.
2. Qt 6 for MSVC: `pip install aqtinstall` then `python -m aqt install-qt windows desktop 6.8.3 win64_msvc2022_64 -O C:\Qt`.
3. `git clone --recursive` this repo, then run **`build_helper_win64.cmd`**.
   - Output: `release\die_win64_qt6\die.exe`.
   - The first build takes ~25 min (2900 steps, all cores). Later builds are incremental (seconds to a couple of minutes) because `_build\` is kept.
   - Other Qt location: `set QT_PREFIX_PATH=C:\Qt\6.x.y\msvc2022_64` first.
   - Do not add `include_directories()` / global flags under `src/gui`: the `die` target compiles all widget libraries directly, so it would rebuild ~1000 files.

Test samples: `_samples\build_samples.cmd` builds hello-world EXEs/DLLs (x86/x64), a .NET sample, an anti-debug/TLS
sample, a .NET sample with obfuscated names, UPX-packed copies, renamed/scrambled UPX and a fake "unknown packer".
They are for scanning only.

### Where the code is
| What | Where |
|---|---|
| Packing tab (verdict, map, indicators, hint) | `src/gui/helper/helperpackingview.*` |
| Section map widget | `src/gui/helper/helpersectionmap.*` |
| Evidence + indicators (no GUI, worker thread) | `src/gui/helper/helperevidence.*` |
| Actions toolbar (buttons, runner, result tabs, external tools, before/after) | `src/gui/helper/helperactions.*` |
| Verdict shared by the tab, reports and batch | `src/gui/helper/helperverdict.*` |
| Static unpack / PE surgery | `helperunpacker.*`, `helperpesurgery.*` |
| UPX finishing for Decompress -> Rebuild (filter, relocations, section names) | `helperupx.*` |
| OEP finder / decompressor / PE rebuild | `helperoepfinder.*`, `helperdecompressor.*`, `helperrebuild.*` |
| Strings / API hashes / .NET view | `helperstrings.*`, `helperapihash.*`, `helpernetinfo.*` |
| Report / signature maker / batch scan | `helperreport.*`, `helpersignaturemaker.*`, `helperbatch.*` |
| Hints loader / Options page / settings | `src/gui/helper/helperhints.*`, `helperoptionswidget.*`, `helpersettings.*` |
| Build list + install rules | `src/gui/helper/helper.cmake` |
| Hook points in existing files (marked `[Helper]`) | `dep/die_widget/die_widget.*` (signals `resultsReady`/`resultSelected`/`scanCleared`, `addResultTab`), `dep/FormatWidgets/formatswidget.*` (forwarding, getters), `src/gui/guimainwindow.*`, `src/gui/dialogoptions.*`, `src/gui/diegui.cmake` |

---

# Original DIE-engine README

[![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/horsicq/DIE-engine.svg)](http://ntinfo.biz)
[![GitHub All Releases](https://img.shields.io/github/downloads/horsicq/DIE-engine/total.svg)](http://ntinfo.biz)

GUI & console sources for Detect It Easy (DiE): https://github.com/horsicq/Detect-It-Easy/ . To support the original author, see the [Detect It Easy repository](https://github.com/horsicq/Detect-It-Easy).

## Optional PEiD engine

The PEiD scan engine is disabled by default. Enable it for a CMake build with
`-DWITH_PEID=ON`; this defines `USE_PEID`, compiles the XPEID/peid_widget
sources, exposes the PEiD controls, and installs the `peid` database directory.
Packaging scripts use the matching `X_WITH_PEID=ON` environment switch and
forward it to CMake. With the default `OFF`, PEiD code, controls, help entries,
and package files are omitted.

## Updating the signature database

`die-update` checks and installs the database published in the
`current-database` release. It uses the same `Scan/Die/Database/Main/Path` and
`Scan/Die/Database/Main/UpdateUrl` settings as Detect It Easy, leaves
`db_custom` untouched, stages and validates a new `db` before replacing the old
one, and writes `db/die-update.ini` only after the replacement succeeds.

```text
die-update --check             check only (exit 1 when an update is available)
die-update                     install an available update
die-update --help              list paths, sources, JSON and other options
diec --checkupdate [-D path]   run die-update --check and return its exit code
diec --update [-D path]        run die-update and return its exit code
```

The GUI provides **Update database** beside its other main-window actions. The
operation runs in a separate process and the scan database is reloaded after a
successful update. Portable copies read `die.ini` beside the programs; other
copies use the native `NTInfo/die` settings store. Read-only installations put
updates in the per-user database folder, which the Qt frontends prefer on the
next load.

## Special Thanks

- [PELock Software Protection & Reverse Engineering](https://www.pelock.com)

![alt text](https://github.com/horsicq/Detect-It-Easy/blob/master/docs/logo2.png "logo")


# Thanks to all the people who already contributed!

<a href="https://github.com/horsicq/DIE-engine/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=horsicq/DIE-engine" />
</a>


