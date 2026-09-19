# E-Waste — Complete Technical Reference

This document explains **everything** currently built in this codebase: every
data structure, every function, every decision branch, why each piece exists,
what real-world problem it solves, what bugs were found and fixed while
building it, and what is deliberately still missing. Read top to bottom and
you should understand the entire program with no gaps.

The codebase is one Rust binary (`src/main.rs`, ~3,460 lines) plus one
isolated module (`src/raw_write.rs`, ~450 lines). 126 automated tests, all
passing, zero of which touch a real disk.

---

## 1. What this program is, and is not

**Project:** PS 26149 — an NTRO forensic platform: secure drive erasure,
secure file erasure, and file recovery/carving, plus reporting. This codebase
is Module 1 (Secure Drive Eraser) only.

**What it can do right now, on real Windows hardware:**
- Enumerate every physical disk, partition, and BitLocker volume.
- Correctly identify which disk Windows is booted from.
- Decide, for every disk, whether it's safe to even consider as a wipe
  target, and separately, whether enough is known about it to trust a byte
  count.
- Walk an operator through explicitly selecting a disk, seeing exactly what
  would happen to it, typing back its serial number to confirm, and having
  that confirmation re-verified against a brand new snapshot of reality
  before being accepted.

**What it cannot do, at all, right now:** write a single byte to any disk.
There is no code path from anything in this program to an actual disk write.
The overwrite *logic* exists (`raw_write::overwrite`) but it is not connected
to anything — it has no caller anywhere in the codebase. Confirming an
operation ends with a message that says exactly that.

Think of it as: the entire front door, hallway, and vault door of a bank
vault have been built and tested, but there's no vault behind the door yet.

---

## 2. How data enters the program

The program never talks to disk hardware directly. Every fact it knows comes
from asking **PowerShell** a question and parsing the answer.

### The plumbing, bottom to top

```rust
fn execute_powershell(command: &str) -> Result<Output, Box<dyn std::error::Error>> {
    let command = format!(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; \
$OutputEncoding=[Text.Encoding]::UTF8; {command}"
    );
    Command::new(POWERSHELL_PATH)
        .args(["-NoProfile", "-Command", &command])
        .output()
        .map_err(|e| e.into())
}
```
Launches `powershell.exe` as a child process with the given command string.
Two things are forced up front:
- **UTF-8 output encoding.** Without this, PowerShell writes text in the
  console's legacy OEM/ANSI codepage, and any non-ASCII character (a path
  with an accented letter, say) would arrive corrupted.
- **`-NoProfile`** — skips the user's PowerShell profile script, so behavior
  doesn't depend on whatever customizations happen to be installed on the
  machine running this.

```rust
fn decode_powershell_stdout(bytes: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s.trim().to_string()),
        Err(_) => Err("PowerShell produced output that was not valid UTF-8".into()),
    }
}
```
Strict decode — not `from_utf8_lossy`. Lossy decoding silently replaces bad
bytes with `�` (U+FFFD), and a corrupted path could still accidentally
prefix-match some other, wrong disk later in the pipeline. Better to fail
loudly here than corrupt a path silently and misattribute data to the wrong
disk three functions later.

### The stderr trap — the single most important gotcha in this codebase

Windows CIM-backed cmdlets (`Get-CimInstance`, and several things built on
top of it like `Get-BitLockerVolume`) have a nasty failure mode: **they can
exit with code 0 (success) while the real error goes to stderr, and stdout
still prints a valid, empty `[]`.** From the code comment (verified on real
hardware, not theoretical):

> Verified on this machine — `Win32_ShadowCopy` failing with
> `WBEM_E_PROVIDER_LOAD_FAILURE` emits exactly the same `"[]"` as a system
> with no shadow copies. stdout alone cannot tell "failed" from "nothing
> found".

So every single query function in this codebase follows the same three-step
pattern:
```rust
let stdout = decode_powershell_stdout(&output.stdout)?;
let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
if !stderr.is_empty() {
    return Err(format!("PowerShell error: {}", stderr).into());
}
```
Check stderr **before** trusting stdout, every time. If this check were
missing anywhere, a broken query would look identical to "nothing found" —
which for a forensic tool is the worst possible failure mode (a false
all-clear).

### The three inventory queries

**`get_physical_disks()`** — the most important one, since almost everything
downstream keys off `PhysicalDisk`:
```powershell
Get-Disk | Select-Object Number,FriendlyName,SerialNumber,HealthStatus,
  OperationalStatus,IsBoot,IsSystem,
  @{N='SizeGB';E={[math]::Round($_.Size / 1GB, 2)}},
  Size,
  @{N='BusType';E={$_.BusType.ToString()}},
  @{N='MediaType';E={$_.MediaType.ToString()}},
  IsRemovable
```
Notice `BusType` and `MediaType` are wrapped in `.ToString()` inside a
calculated property (`@{N=...;E={...}}`). This is deliberate: these two
properties come back from `Get-Disk` as CIM enum objects, and depending on
the exact provider, `ConvertTo-Json` can serialize an unwrapped enum as a
raw integer instead of its friendly name (`"USB"` vs. `7`). Calling
`.ToString()` explicitly forces the friendly string every time. The same
trick is used for `Get-BitLockerVolume`'s `VolumeStatus`/`ProtectionStatus`/
`VolumeType`.

**`get_partitions()`** — disk number, drive letter, type, and every
"AccessPath" Windows knows for the partition (explained in depth in section
5's path-resolution write-up).

**`get_bitlocker_volumes()`** — mount point, protection/volume status,
encryption percentage, volume type, capacity.

All three are called exactly **once**, at the very top of `main()`, and the
`Result` values are reused for every report section after that. This
matters: if the tool re-queried mid-run, a disk could theoretically change
state between two report sections and the output would contradict itself.

### The System Usage queries (M-2 support data)

Five more, gathered together by `collect_system_usage()`, each independently
`Result`-wrapped so **one failing query degrades exactly one check**, not
the whole report:

- `get_pagefiles()` — queries *two* separate WMI classes
  (`Win32_PageFileUsage` for what's active right now, `Win32_PageFileSetting`
  for what's configured but maybe not yet active) and merges them, because
  neither alone is the full picture — an automatically-managed pagefile
  reports nothing under `Win32_PageFileSetting` until it's actually in use.
- `get_hibernation()` — reads the `HibernateEnabled` registry value plus
  `%SystemDrive%` in one shot, because `hiberfil.sys` always lives on the
  system drive and that's what needs correlating to a physical disk.
- `get_crash_dump()` — reads `CrashDumpEnabled`, `DumpFile`, `MinidumpDir`,
  and the rarely-used `DedicatedDumpFile` registry values.
- `get_shadow_copies()` — enumerates `Win32_ShadowCopy` instances.
- `get_executable_path()` — `std::env::current_exe()`, converted to a
  strict-UTF-8 string (a path with an unpaired UTF-16 surrogate — genuinely
  possible on Windows — becomes an error, not a mangled string that could
  silently prefix-match the wrong disk).

All five share one helper, `powershell_json()`, which applies the same
stderr-before-stdout discipline described above, plus a second guard: for
these five (unlike the three inventory queries), an **empty stdout is itself
treated as a failure**, because a genuinely-empty successful result would
normally still be `"[]"` from `ConvertTo-Json` — truly empty output means the
query never got that far.

---

## 3. Every data structure, field by field

### `PhysicalDisk`
```rust
struct PhysicalDisk {
    number: u32,                    // Get-Disk "Number" — the index key
    friendly_name: String,          // e.g. "CT500P3PSSD8"
    serial_number: Option<String>,  // absent on some virtual/exotic disks
    health_status: String,          // "Healthy", etc.
    operational_status: String,     // "Online", etc.
    is_boot: bool,
    is_system: bool,
    size_gb: f64,                   // rounded to 2 decimals — DISPLAY ONLY
    size_bytes: u64,                // exact, raw "Size" property
    bus_type: Option<String>,       // "SATA"/"USB"/"NVMe"/... or absent
    media_type: Option<String>,     // "HDD"/"SSD"/"Unspecified" or absent
    is_removable: Option<bool>,     // can be null even though IsBoot/IsSystem never are
}
```
Two fields deserve special attention because each one caused a real bug
during development (full story in section 11):

- **`size_bytes` exists *in addition to* `size_gb`** specifically because
  `size_gb` is lossy (rounded to 2 decimals) and can't be trusted for a real
  byte-exact plan.
- **`is_removable` is `Option<bool>`, not plain `bool`.** It looks like it
  should always be present (it's a boolean flag from the same cmdlet as
  `IsBoot`/`IsSystem`, which never come back null) — but on real hardware
  tested during this project, `Get-Disk` returned `null` for it, and the
  program crashed on deserialization until this was changed to `Option`.

### `Partition`
```rust
struct Partition {
    disk_number: u32,
    drive_letter: Option<char>,
    partition_type: String,             // "Basic", "System", "Reserved", "Recovery", ...
    access_paths: Option<Vec<String>>,  // every mount point Windows knows for this partition
}
```
`access_paths` is the important one — it's not just the drive letter. A
single partition can be reachable by its drive-letter root (`C:\`), its
volume GUID root (`\\?\Volume{...}\`), and any NTFS folder mount point, all
at once. This is what makes path-to-disk resolution possible for volumes
that have no drive letter at all (see section 5).

### `BitLockerVolume`
```rust
struct BitLockerVolume {
    mount_point: String,
    volume_status: Option<String>,       // None means "locked, can't tell"
    protection_status: String,           // "On" / "Off" / anything else = unrecognized
    encryption_percentage: Option<u32>,
    volume_type: String,
    capacity_gb: f64,
}
```

### The five System Usage structs
`PageFile { name, source }`, `Hibernation { enabled: Option<u32>,
system_drive: Option<String> }`, `CrashDump { enabled, dump_file,
minidump_dir, dedicated_dump_file: all Option }`, `ShadowCopy { id,
volume_name }`. Every field that *can* legitimately be absent or unreadable
is `Option`, on purpose — per the code's own comment:

> The `Option` fields below keep "Windows reported this value" distinguishable
> from "the value was absent or unreadable". The second case must surface as
> Unknown; it must never fall back to a default that reads as Safe.

`SystemUsage` just bundles all five query results together, each kept as its
own independent `Result` so one bad query can't contaminate the other four.

---

## 4. Layer 1 — Eligibility (the one hard rule)

```rust
enum Eligibility {
    Eligible,
    Blocked(String),
}

fn evaluate_eligibility(disk: &PhysicalDisk) -> Eligibility {
    if is_system_disk(disk) {
        return Eligibility::Blocked("system/boot disk".to_string());
    }
    Eligibility::Eligible
}

fn is_system_disk(disk: &PhysicalDisk) -> bool {
    disk.is_boot || disk.is_system
}
```

That's the entire function. Two lines of real logic. This is deliberate —
this is the single most important check in the whole program (it prevents
the tool from ever being pointed at the disk running the operating system
that's currently executing it), and it is kept as simple as it is
theoretically possible to be. There is no clever logic to get wrong here.

**This function used to be much bigger.** Before an architecture review this
session, it also contained BitLocker-protection checking — looping every
partition, matching it to a BitLocker volume, and returning `Blocked` if
protection was `On`, or `Unknown` (a third variant that no longer exists at
all) if anything about that correlation couldn't be determined. That's
covered fully in section 11's history — the short version is: encryption
status doesn't affect whether a full physical overwrite is safe, so blocking
on it here was solving the wrong problem in the wrong place. It moved to
Layer 2 (see below), and once it left, the `Unknown` variant of `Eligibility`
became literally impossible to produce, so it was deleted from the enum
entirely rather than left as dead code.

---

## 5. Layer 2 — Extended Pre-Flight (informational — cannot block anything)

Seven checks, each producing one `PreflightFinding`:
```rust
enum PreflightStatus { Safe, Unknown, Blocked }   // ordering IS the combine rule
enum PreflightCheck {
    Pagefile, Hibernation, CrashDump, ShadowCopy,
    ExecutableLocation, MediaDetection, BitLockerProtection,
}
struct PreflightFinding { check: PreflightCheck, status: PreflightStatus, detail: String }
struct PreflightReport { findings: Vec<PreflightFinding> }
```
`PreflightStatus` derives `Ord`, and the variant declaration order
(`Safe < Unknown < Blocked`) **is** the rule for combining many findings into
one overall verdict:
```rust
impl PreflightReport {
    fn status(&self) -> PreflightStatus {
        self.findings.iter().map(|f| f.status).max()
            .unwrap_or(PreflightStatus::Unknown)   // no findings = Unknown, not Safe
    }
}
```
One `Blocked` finding drags the whole report to `Blocked`, no matter how many
other checks say `Safe`. An empty report (a bug, since it should never
happen) defaults to `Unknown`, never to `Safe` — `max()` over an empty
iterator would otherwise implicitly favor the lowest variant, which is
exactly the wrong direction to fail in.

**Crucially: none of these seven checks can stop a disk from being planned
or confirmed.** They are reported for a human to read, and (once M1-10/M1-11
exist) as future input to sanitization-method selection. Only Layer 1
(above) and Layer 4 (confirmation, section 7) can actually refuse a disk.

### The shared machinery: `resolve_path_to_disks` and `classify_paths`

Four of the seven checks (Pagefile, Hibernation, Crash Dump, Executable
Location) boil down to the same question: *"does this specific file path
live on the target disk?"* That question is answered once, generically:

```rust
fn normalize_path(path: &str) -> String {
    let lowered = path.trim().to_lowercase().replace('/', "\\");
    format!("{}\\", lowered.trim_end_matches('\\'))
}
```
Makes `"C:"`, `"c:\"`, `"C:/"` and a volume-GUID root all compare equal —
Windows APIs are inconsistent about case and trailing separators, and this
tool must not let that inconsistency cause a real match to be missed.

```rust
fn resolve_path_to_disks(path: &str, partitions: &[Partition]) -> Vec<u32> {
    // ... finds every partition whose AccessPath is the LONGEST matching
    // prefix of `path`, across all partitions on all disks, and returns
    // every disk tied at that longest length.
}
```
**Worked example:** if a partition's access path is `C:\` and another
(mounted-folder) partition's access path is `C:\mnt\data\`, and the query
path is `C:\mnt\data\pagefile.sys` — the *longer* prefix (`C:\mnt\data\`)
wins, so the pagefile is correctly attributed to the mounted-folder
partition's disk, not the `C:\` disk. Matching only by drive letter would
get this wrong.

It returns **every** disk tied at the longest match, not just one — because
a dynamic mirrored/striped volume genuinely spans multiple physical disks
with the identical access path on each, and all of them really do hold the
data.

An **empty result** (no partition's access path is a prefix of the query
path at all) means "couldn't figure out where this lives" — never silently
treated as "not on the target disk."

```rust
fn classify_paths(check, disk_number, partitions, paths, safe_detail) -> PreflightFinding {
    // any path that resolves to disk_number -> Blocked
    // any path that resolves to nothing      -> Unknown
    // everything resolves, none on disk_number -> Safe
}
```

### The seven checks, individually

**Pagefile** — is Windows' virtual-memory swap file on this disk?
```rust
fn evaluate_pagefile(disk_number, partitions, usage) -> PreflightFinding {
    // usage.pagefiles is Err -> Unknown
    // empty list -> Safe ("no pagefile is in use or configured")
    // otherwise -> classify_paths() against every pagefile's path
}
```
Real risk this catches: wiping a *non-boot* disk that happens to host a
secondary pagefile (Windows supports per-drive pagefiles) while the OS is
still running, live, using it.

**Hibernation** — would resuming from hibernation depend on this disk?
```rust
fn evaluate_hibernation(...) {
    // query failed -> Unknown
    // HibernateEnabled absent -> Unknown (never *infer* off from absence)
    // HibernateEnabled == 0 -> Safe (disabled)
    // enabled but SystemDrive unknown -> Unknown
    // otherwise -> classify_paths() against the one hiberfil.sys path
}
```
Comment worth repeating: *"inferring the answer from the presence of
hiberfil.sys would be a heuristic, so it stays Unknown"* — the check refuses
to guess even when a shortcut answer might feel obviously right.

**Crash Dump** — similar shape, but can check up to three separate paths
(`DumpFile`, `MinidumpDir`, and the rare `DedicatedDumpFile`, which can point
kernel dumps at an entirely different volume than the system drive).

**Shadow Copies** — does this disk host VSS backup/restore-point data for
*any* volume (not just itself)? Genuinely independent information — shadow
copy storage location isn't intuitive and isn't necessarily the boot disk.

**Executable Location** — is the E-Waste binary itself currently running
from this disk?
```rust
classify_paths(ExecutableLocation, disk_number, partitions,
    &[("E-Waste executable", exe_path)],
    "E-Waste is not running from this disk")
```
Real risk: the tool destroying the very disk that holds its own running
process. That would be an absurd, but entirely possible, self-inflicted
failure without this check.

**Media Detection** — do we actually know this disk's bus/media type?
```rust
fn is_recognized_media_value(value: Option<&str>) -> bool {
    matches!(value, Some(v) if !v.is_empty() && v != "Unspecified" && v != "Unknown")
}
fn evaluate_media_detection(disk) -> PreflightFinding {
    if is_recognized_media_value(bus_type) && is_recognized_media_value(media_type) {
        Safe("bus type X / media type Y / removable: Z")
    } else {
        Unknown("bus type X / media type Y not fully recognized")
    }
}
```
Purely informational, purely for a human reading the report. Notice: this is
**not** what gates the Sanitization Plan's capacity trust (that's Layer 3,
next section, and uses a different, narrower signal — this distinction is
itself the outcome of a real bug fix, see section 11).

**BitLocker Protection** — is any volume on this disk encrypted and locked?
This is the most involved of the seven, because it has to correlate two
independently-fetched lists (`Partition`s and `BitLockerVolume`s) that don't
perfectly agree on formatting:

```rust
fn evaluate_bitlocker_protection(disk, disk_partitions, bitlocker) -> PreflightFinding {
    let volumes = match bitlocker { Ok(v) => v, Err(e) => return Unknown(...) };
    // checked BEFORE the partition loop -- a failed BitLocker query is
    // relevant to every disk, even one with zero lettered partitions

    for partition in disk_partitions {
        let Some(letter) = partition.drive_letter else {
            // letterless: EFI/Reserved/Recovery partitions are legitimately
            // letterless and hold no user data -- skip them (`continue`).
            // Anything else letterless -> Unknown (can't correlate it).
        };
        if !letter.is_ascii_alphabetic() {
            // A partition with NO letter at all serializes from
            // System.Char as "\u0000" and deserializes to Some('\0'),
            // NOT None -- it slips right past the check above unless this
            // second guard exists. -> Unknown.
        }
        let mount_point = format!("{}:", letter);
        let Some(volume) = volumes.iter().find(|v|
            v.mount_point.trim_end_matches('\\').eq_ignore_ascii_case(&mount_point)
        ) else {
            // Get-BitLockerVolume lists every fixed volume, protected or
            // not -- a lettered partition with NO entry at all is
            // anomalous. -> Unknown, never silently Safe.
        };
        match volume.protection_status.as_str() {
            "On" => return Blocked(...),
            "Off" => continue,   // keep checking the REST of this disk's partitions
            other => return Unknown(format!("unrecognized ProtectionStatus '{}'", other)),
        }
    }
    Safe("no partition on this disk is BitLocker-protected")
}
```
Notice the `eq_ignore_ascii_case` + `trim_end_matches('\\')` comparison —
`Get-Partition` might report a drive letter as lowercase `'c'` while
`Get-BitLockerVolume` reports its mount point as `"C:\"` with a trailing
backslash. An exact `==` here would silently miss the match and let an
actually-encrypted volume read as `Safe`.

**Why this whole function exists separately from `evaluate_eligibility`,
with identical logic:** this used to literally be inside eligibility, with
the power to `Block`/mark-`Unknown` the whole disk. It was pulled out,
unchanged in its internal logic, and repointed at a `PreflightFinding`
instead of an `Eligibility` — full story in section 11.

---

## 6. Layer 3 — Sanitization Plan (the dry-run)

```rust
const PLANNED_PATTERN: u8 = 0x00;
const PLANNED_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

const CAPACITY_TRUSTED_BUS_TYPES: &[&str] =
    &["SATA", "NVMe", "SAS", "ATA", "SCSI", "Fibre Channel", "RAID", "iSCSI"];

fn is_capacity_trusted_bus(bus_type: Option<&str>) -> bool {
    matches!(bus_type, Some(b) if CAPACITY_TRUSTED_BUS_TYPES.iter()
        .any(|known| b.eq_ignore_ascii_case(known)))
}

enum DiskPlan {
    Planned { total_bytes: u64, pattern: u8, chunk_size: usize },
    Skipped(String),
    PendingCapacityConfirmation(String),  // deliberately carries NO byte count
}

fn plan_for_disk(disk: &PhysicalDisk) -> DiskPlan {
    match evaluate_eligibility(disk) {
        Eligibility::Blocked(reason) => return DiskPlan::Skipped(reason),
        Eligibility::Eligible => {}
    }
    if !is_capacity_trusted_bus(disk.bus_type.as_deref()) {
        return DiskPlan::PendingCapacityConfirmation(format!(
            "bus type {} is not on the list of buses with trusted capacity reporting",
            disk.bus_type.as_deref().unwrap_or("(absent)")
        ));
    }
    DiskPlan::Planned { total_bytes: disk.size_bytes, pattern: PLANNED_PATTERN, chunk_size: PLANNED_CHUNK_SIZE }
}
```

Two gates, in order:
1. **Eligibility** (Layer 1) — not eligible → `Skipped`, stop.
2. **Capacity trust** — is the disk's *bus type* one of a fixed allowlist of
   buses that reliably report true device capacity? If not (USB, SD/MMC
   readers, or no bus type reported at all) → `PendingCapacityConfirmation`,
   **with no byte count attached to the value at all** — the enum variant
   itself carries only a text reason, not a number, so a distrusted size can
   never accidentally end up looking like part of a real plan.

This allowlist approach (list what's *trusted*, refuse everything else,
including "don't know") rather than a denylist (list what's *known bad*,
trust everything else by default) is the fail-closed choice: an
unrecognized or absent bus type is treated with the same suspicion as a
known-bad one, not assumed innocent.

**Why bus type, and not media type or "do we know anything about it":** this
is the direct result of a real design mistake caught and fixed mid-session
— full story in section 11. Short version: gating on whether `MediaType` was
populated would have also blocked a perfectly good internal SSD (whose
`MediaType` happened to also be blank on this test machine), for a reason
that had nothing to do with capacity trust at all.

---

## 7. Layer 4 — Confirmation gate (M1-5)

This is the only layer that requires the operator to do anything, and the
only thing after Layer 1 that can also refuse a disk outright.

### The two new pieces

```rust
struct BoundOperation<'a> {
    disk: &'a PhysicalDisk,   // the FRESH, re-verified disk — not the originally selected one
    plan: DiskPlan,           // guaranteed to be the Planned variant
}

fn confirm_and_bind<'a>(
    selected: &PhysicalDisk,
    confirmed_plan: &DiskPlan,
    entered_serial: &str,
    fresh_disks: &'a [PhysicalDisk],
) -> Result<BoundOperation<'a>, String> {
    // 1. confirmed_plan MUST be Planned (defense in depth — this function
    //    doesn't trust its caller's gating)
    if !matches!(confirmed_plan, DiskPlan::Planned { .. }) {
        return Err("cannot confirm an operation that was not Planned".to_string());
    }

    // 2. selected disk must actually have a usable serial number
    let expected_serial = match selected.serial_number.as_deref() {
        Some(serial) if !serial.trim().is_empty() => serial,
        _ => return Err(format!("disk {} has no usable serial number: cannot be confirmed", selected.number)),
    };

    // 3. EXACT, case-sensitive match against what the operator typed.
    //    A blank line (cancel) can never coincidentally equal a real serial.
    if entered_serial.trim() != expected_serial {
        return Err("confirmation did not match the disk's serial number".to_string());
    }

    // 4. re-verify identity against a BRAND NEW inventory snapshot
    let fresh = verify_target_before_operation(selected, fresh_disks)?;

    // 5. THE KEY NEW CHECK: re-derive the plan from scratch and require it
    //    to be structurally IDENTICAL to what was shown at confirmation time
    let fresh_plan = plan_for_disk(fresh);
    if fresh_plan != *confirmed_plan {
        return Err("the plan for this disk has changed since confirmation -- aborting; re-run to reconfirm".to_string());
    }

    Ok(BoundOperation { disk: fresh, plan: fresh_plan })
}
```

Step 5 is the entire reason this milestone exists as more than "check the
serial." Steps 2–4 only prove the disk's *identity* hasn't changed
(same number, same serial, same name, same size). None of that proves the
*plan* hasn't changed — a disk can keep an identical identity while its
capacity-trust classification silently flips underneath it (a driver update,
a different USB port with a different bridge chip reporting differently,
etc.). Re-deriving the whole plan and demanding bit-for-bit equality — not
just "is it still `Planned`" — catches that class of problem with no new
Windows queries needed at all, since `plan_for_disk` only needs the
`PhysicalDisk` value itself.

### `verify_target_before_operation` — reused unchanged, plus one fix

This function already existed before M1-5 (built earlier, unused until now).
It checks, against a fresh snapshot:
1. The original disk actually had a serial (else: can't prove identity at
   all, refuse).
2. Exactly one disk still has that number in the fresh list (0 → "gone"; 2+ →
   "ambiguous").
3. The fresh disk's serial matches (mismatch → refuse; **never** search for
   the serial elsewhere to "recover" — a renumbered disk must never be
   silently followed).
4. Friendly name matches.
5. `size_gb` matches.
6. **`size_bytes` matches** — added during M1-5 phase 1. `size_gb` is
   rounded to 2 decimals; two genuinely different exact byte counts could
   round to the same displayed value and slip past check 5 alone.
7. Not now a system/boot disk (redundant with `evaluate_eligibility`'s own
   check — kept anyway, deliberately, as defense-in-depth on the single most
   catastrophic possible failure).
8. Re-run `evaluate_eligibility` itself.

### `select_target_disk` — also pre-existing, now finally called

```rust
fn select_target_disk<'a>(disks, disk_number, expected_serial: Option<&str>) -> Result<&'a PhysicalDisk, String>
```
Looks a disk up **by number** in the current snapshot (0 matches → error, 2+
→ "ambiguous" error), optionally checks a serial if one was supplied, then
runs eligibility. `main()` calls this with `expected_serial: None` — the
serial check happens later, interactively, in the confirmation prompt
instead of at selection time.

### The CLI wrapper — `parse_target_disk_arg` + `main()`

```rust
fn parse_target_disk_arg(args: &[String]) -> Result<Option<u32>, String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--target-disk" {
            let value = iter.next().ok_or_else(|| "--target-disk requires a disk number".to_string())?;
            let number: u32 = value.parse().map_err(|_| format!("--target-disk value {:?} is not a valid disk number", value))?;
            return Ok(Some(number));
        }
    }
    Ok(None)
}
```
Pure, no I/O, fully unit-tested. Takes the raw arg vector (`argv[0]`
included — it never matches `"--target-disk"` so needs no special-casing).
Absent flag is `Ok(None)`, not an error — the default, zero-argument
behavior must stay exactly what it always was.

**`main()`'s full sequence, in exact order:**

1. Parse `--target-disk` **before anything else** — a typo here is a pure
   input error, unrelated to disk access, and should fail instantly
   (`exit(2)`) rather than making the operator wait through elevation and
   enumeration first.
2. Elevation check (`is_elevated()`) — refuses (`exit(1)`) if not
   Administrator, before touching any disk state at all.
3. Fetch disks/partitions/BitLocker **once**.
4. Print, **unconditionally, every single time, regardless of
   `--target-disk`**: Disk Information → BitLocker Status → Correlation →
   Eligibility → Extended Pre-Flight → Sanitization Plan. This is
   deliberate: the operator always sees full context before any prompt, and
   it means the default (no-args) behavior of the tool never changes no
   matter what gets built into the confirmation flow later.
5. If no `--target-disk` was given: `return` — done, exit 0. This is the
   entire default behavior.
6. If a disk number was given:
   - `disks_result` must be `Ok` (else `exit(2)`).
   - `select_target_disk(disks, n, None)` — not found/blocked → `exit(2)`.
   - `plan_for_disk(selected)` — must be `Planned`; `Skipped`/
     `PendingCapacityConfirmation` → print the reason, `exit(2)`,
     **without ever printing a confirmation prompt.**
   - Must have a non-blank serial, else same treatment.
   - Print the full confirmation prompt (exact text below), showing real
     identity + real plan values.
   - Read one line from stdin (`read_line`) — any error here (e.g. invalid
     UTF-8) is quietly left as an empty string, which then fails the serial
     match the same way a genuine wrong answer or a cancelled prompt would.
     No special-case handling needed.
   - Re-fetch disks (**fresh**, right now — not reusing the snapshot from
     step 3).
   - Call `confirm_and_bind`. `Ok` → print the success message, `exit(0)`
     implicitly. `Err(reason)` → print `"Confirmation failed: {reason}"`,
     `exit(2)`.

**Exit codes:** `1` = not elevated. `2` = every single refusal in the
`--target-disk` flow (bad argument, disk not found/blocked, not planned, no
serial, fresh-fetch failure, confirmation mismatch) — one code for all of
them, deliberately, rather than inventing a taxonomy nothing in this project
currently needs.

### The exact confirmation prompt text

```
=== Destructive Operation Confirmation ===

You have selected:
  Disk number:   1
  Friendly name: USB2.0 CARD-READER
  Serial number: 8120120400400000
  Reported size: 2045.49 GB (2196328163574 bytes exact, per Get-Disk)
  Planned action: overwrite the ENTIRE disk with a fixed byte pattern
                  (0x00), in 1048576-byte chunks

This operation is DESTRUCTIVE and IRREVERSIBLE. All data on this disk
will be overwritten and will not be recoverable by this tool, or any
other software, once the operation completes.

This confirmation records operator intent only. It does not prove no
other process holds this disk open, and it does not certify a NIST
SP 800-88 sanitization category -- that determination belongs to a
later, unimplemented step.

To proceed, type this disk's exact serial number and press Enter.
Anything else -- including a blank line, or Ctrl+C -- cancels. Nothing
has been written to any disk yet.

>
```
Two deliberate honesty statements are baked into the wording itself: it does
**not** claim to prove no other process has the disk open (nothing in this
codebase can prove that), and it does **not** claim a specific NIST SP
800-88 category (Clear vs. Purge is undecided — M1-9/M1-10/M1-11, not
built).

Success message:
```
Confirmed and bound: disk 1 (serial 8120120400400000), 2196328163574 bytes, pattern 0x00.
No sanitization executor exists in this build -- nothing further will happen.
```
This is printed from `bound.disk` / `bound.plan` — the values that came back
out of `confirm_and_bind` after re-verification — not the pre-confirmation
locals, so the message always reflects what was actually, freshly checked.

### Why single-attempt, no retry

If the typed serial is wrong, the whole run ends (`exit(2)`); there's no
loop that says "try again." This is a deliberate simplicity trade-off: a
legitimate typo costs a full restart (re-enumeration and all), but the
alternative (a retry loop, a retry counter, a "give up after N tries" rule)
is more state and more code for a benefit that doesn't outweigh it yet.

---

## 8. `raw_write` — the write loop that isn't connected to anything

```rust
#![allow(dead_code)]  // whole module

pub struct WriteProgress { pub bytes_written: u64, pub total_bytes: u64 }

pub enum WriteOutcome {
    Completed { bytes_written: u64 },
    Cancelled { bytes_written: u64 },
    Failed { bytes_written: u64, source: std::io::Error },
}

pub fn overwrite<W: Write>(
    sink: &mut W, total_bytes: u64, pattern: u8, chunk_size: usize,
    cancel: &dyn Fn() -> bool, progress: &mut dyn FnMut(WriteProgress),
) -> WriteOutcome
```

The module doc comment states the boundary in capital letters:

> SAFETY BOUNDARY: nothing in this module can touch a physical device. It is
> generic over `std::io::Write` and never opens a file, a handle, or a
> device path — the caller supplies the sink.

Mechanically: writes `pattern` byte-filled chunks of `chunk_size` bytes into
`sink` until `total_bytes` is reached.
- **Cancellation** is only checked between whole chunks, never mid-chunk —
  so a `Cancelled` outcome always lands on a clean, reportable byte boundary.
- **Short writes are absorbed**, not treated as failures: `Write::write()` is
  allowed by its contract to accept fewer bytes than offered in one call, and
  an inner loop keeps calling it until the whole chunk is actually written.
- **`ErrorKind::Interrupted`** (a signal interrupted the syscall) is silently
  retried, matching the Rust standard library's own convention — it isn't a
  real failure.
- **Every outcome variant carries `bytes_written`.** Even a `Failed` run
  reports exactly how far it got — described in the module doc as
  deliberately not using `write_all()`, because `write_all` collapses
  partial progress into a bare error and loses the one fact ("how much did
  we actually overwrite before this broke") that matters most for an
  auditable sanitization tool.

**Why it's generic over `Write` instead of opening a real disk itself:**
because the code to open `\\.\PhysicalDriveN` as a raw device handle simply
doesn't exist anywhere in this codebase yet. This loop is the write
*mechanism*; the write *path* (open a handle → confirm it → call this loop
on it) is a whole separate, unbuilt piece of work.

---

## 9. Full `main()` walkthrough, in execution order

```
1.  parse_target_disk_arg(argv)                      -- exit 2 on bad value
2.  is_elevated()                                      -- exit 1 if not admin
3.  get_physical_disks() / get_partitions() / get_bitlocker_volumes()  (once)
4.  print "=== Disk Information ==="                   (per disk: identity + size + bus/media/removable)
5.  print "=== BitLocker Status ==="                   (per volume)
6.  print "=== Disk / Partition / BitLocker Correlation ===" (per disk, per partition, matched to its BitLocker entry)
7.  print "=== Disk Eligibility ==="                   (per disk: ELIGIBLE or BLOCKED: system/boot disk)
8.  print "=== Extended Pre-Flight (read-only) ==="    (per disk: all 7 checks + combined Result)
9.  print "=== Sanitization Plan (dry-run -- nothing executed) ===" (per disk: PLANNED / SKIPPED / PENDING)
10. if no --target-disk: STOP (exit 0)
11. print "=== Destructive Operation Confirmation ==="
12. select_target_disk -> plan_for_disk -> serial-presence check       (all exit 2 on failure, before any prompt)
13. print the confirmation prompt with real values
14. read one line from stdin
15. get_physical_disks() again (fresh)
16. confirm_and_bind(...)  -> Ok: print success, exit 0
                            -> Err: print failure, exit 2
```

Sections 4–9 run **unconditionally**, every single time, whether or not
`--target-disk` was given — the operator (or a script capturing this
output) always sees the complete picture, and adding the confirmation flow
never changed what the plain, no-argument invocation prints.

---

## 10. Testing — philosophy and coverage

**Rule followed throughout:** any function with real decision logic gets
fixture-based unit tests with zero real I/O. Any function that's *purely* an
I/O edge (talks to PowerShell, reads stdin, checks `std::env`) gets **no**
automated test — it's verified manually against real hardware instead. This
line is drawn consistently everywhere:

| Untested (I/O edge) | Tested (pure logic) |
|---|---|
| `execute_powershell`, `is_elevated`, `get_physical_disks`, `get_partitions`, `get_bitlocker_volumes`, `get_pagefiles`, `get_hibernation`, `get_crash_dump`, `get_shadow_copies`, `get_executable_path` | `decode_powershell_stdout`, `parse_elevation_output`, `evaluate_eligibility`, `evaluate_bitlocker_protection`, `evaluate_media_detection`, all 5 `evaluate_*` pre-flight checks, `resolve_path_to_disks`, `classify_paths`, `select_target_disk`, `verify_target_before_operation`, `plan_for_disk`, `confirm_and_bind`, `parse_target_disk_arg` |
| `main()`'s stdin/prompt block | (everything it calls, individually) |

**126 tests total, all passing** — 115 in `main.rs`, 11 in `raw_write.rs`.
Rough breakdown:

| Area | Count |
|---|---|
| `verify_target_before_operation` | 11 |
| Path resolution (`resolve_path_to_disks`) | 10 |
| `confirm_and_bind` (M1-5) | 10 |
| `select_target_disk` | 8 |
| Hibernation checks | 6 |
| Crash Dump checks | 6 |
| `plan_for_disk` (M1-4) | 5 |
| Elevation-output parsing | 5 |
| `parse_target_disk_arg` (M1-5) | 4 |
| Media Detection | 4 |
| Shadow Copy / Pagefile checks | 3 each |
| BitLocker Protection scenarios | ~9 |
| `raw_write::overwrite` | 11 |

Test fixtures live in one place (`make_disk`, `make_disk_with_serial`,
`make_disk_full`, `make_target_disk`, `make_partition`,
`make_letterless_partition`, `make_volume`) so every test builds its inputs
the same consistent way.

The single most important individual test in the whole suite,
`confirm_and_bind_rejects_when_bus_type_reclassified`, exists specifically
to prove the thing Layer 4 was built to prove: it constructs a disk whose
*identity* (number/serial/name/size) is completely unchanged between
confirmation and re-verification, but whose `bus_type` moved into an
untrusted category — and confirms `confirm_and_bind` still refuses, even
though `verify_target_before_operation` alone would have said "identity
matches, proceed."

---

## 11. Session history — every real bug and design correction, in order

This is the part that answers "why does it work like *this*, specifically."

### A.1 — Real-hardware verification (USB card reader)

First real-hardware run surfaced a genuine anomaly: `Get-Disk` reported the
USB card reader's capacity as **~2,045 GB**; the physical card is **32 GB**
— roughly 64× inflated. Investigated directly (raw
`Get-Disk | Select Number,FriendlyName,Size`, no code involved) and
confirmed the bogus number comes straight from `Get-Disk`/the USB bridge
chip's firmware itself — not a bug in this program's math. Known failure
mode of cheap SD-to-USB bridge chips. This fact becomes load-bearing later
(M1-4's capacity-trust gate exists specifically because of this disk).

### M1-3 — Media/capability detection, and a real crash found and fixed

Added `bus_type`/`media_type`/`is_removable` to `PhysicalDisk` and a `Media
Detection` pre-flight check. First real-hardware run **crashed immediately**:
`invalid type: null, expected a boolean`. Root cause: `is_removable` was
typed as plain `bool`, but `Get-Disk` returned `null` for it on this
hardware (unlike `IsBoot`/`IsSystem` from the same cmdlet, which never do).
Fixed to `Option<bool>`; a regression test was added that deserializes a
literal JSON fragment with `"IsRemovable": null` to lock the fix in
permanently.

### M1-4 — Dry-run planner, and a design flaw the user caught

First version: `plan_for_disk` gated `Planned` on `evaluate_media_detection`
— both `bus_type` *and* `media_type` had to be "recognized." This would have
printed `PLANNED: overwrite 2,196,328,163,574 bytes` for the USB card reader
from A.1 — a confident-looking destructive plan built on a number already
proven wrong. **The user caught this before it shipped**, specifically
questioning whether a `Size` literal in a test even matched its own `SizeGB`
value, which led to re-examining the whole capacity-trust design. The fix:
gate on **bus type** (a fixed allowlist of buses known to report capacity
reliably), not on whether `MediaType` happened to be populated —
`MediaType` was *also* blank on this machine's own internal, perfectly
trustworthy NVMe SSD, so the original design would have wrongly distrusted
good hardware too. The `DiskPlan` variant was renamed
`PendingMediaConfirmation` → `PendingCapacityConfirmation` to match, and it
was changed to carry **no byte count at all** (not even a distrusted one) —
per explicit user instruction: *"Do not carry raw/untrusted capacity into a
pending destructive plan state."*

### The architecture review — "are we over-engineering this?"

The user asked for a brutally critical review of the entire safety
architecture, specifically worried that every missing/unresolvable Windows
fact was being turned into `UNKNOWN` without real safety justification.
Findings, both acted on immediately:

1. **BitLocker protection status was hard-blocking `Eligibility`.** A
   physical overwrite destroys ciphertext exactly as well as plaintext, so
   encryption status was never actually a wrong-disk/system-destruction
   risk — it's method-selection input for a future crypto-erase feature
   (M1-10), wearing a safety-gate costume. It was also responsible for the
   majority of `Eligibility`'s `Unknown`-producing code paths. **Fix:**
   moved to `evaluate_bitlocker_protection`, a `PreflightFinding` — same
   exact logic, now informational only.
2. **`plan_for_disk` (as built in M1-4) was already the wrong-signal
   problem described above**, independently re-confirmed by this review.

### M1-5 — Built in two explicitly separated, reviewed phases

**Phase 1** (pure logic only, no I/O, no wiring): `BoundOperation` +
`confirm_and_bind`, plus the `size_bytes` precision fix to
`verify_target_before_operation` (it only checked `size_gb` — rounded —
before this). 10 new tests. `confirm_and_bind` had zero callers at the end
of this phase, deliberately, so the safety-critical logic could be reviewed
in isolation before touching `main()`'s control flow at all.

**Phase 2** (the CLI/stdin wrapper): `parse_target_disk_arg` + the
`main()` confirmation block, wiring everything above into the first CLI
argument this binary has ever had. User then verified all four real-hardware
refusal paths directly (`--target-disk 0` → blocked as boot disk;
`--target-disk 1` → refused as capacity-untrusted; missing/non-numeric
argument values → usage errors) — none reached the confirmation prompt,
confirming the gates fire in the right order before any prompt is ever
shown.

---

## 12. What is NOT built

- Any code path from anything to an actual disk write. `raw_write::overwrite`
  has zero callers anywhere.
- Opening a real device handle (`\\.\PhysicalDriveN`) — doesn't exist.
- M1-6 (disk offline/online transition).
- M1-7 (first real destructive code — HDD sanitization).
- M1-8 (verification/read-back after a write).
- M1-9 (SSD/flash Clear), M1-10 (crypto-erase via BitLocker key deletion),
  M1-11 (NVMe Purge via FFI).
- M1-12 (interruption/power-loss recovery).
- Module 2 (file/folder secure erase) and Module 3 (file carving/recovery) —
  entirely unstarted.
- Reporting/audit schema, hash-chained tamper-evident log, UI dashboard
  (Part D of PLAN.md) — entirely unstarted.
- Any retry logic on a wrong confirmation, any CLI flag besides
  `--target-disk`, any help text.

---

## 13. Honest design critique

**What's solid:** every layer answers exactly one question and refuses to
guess when it can't. The confirmation gate re-derives its own conclusions
from scratch immediately before accepting them, rather than trusting a
decision made even a few seconds earlier. Nothing can write to a disk today,
even by accident — there is no wire between "confirmed" and "execute."
126 tests, all pure/fixture-based, cover essentially every branch that isn't
literally an I/O syscall.

**What's a known, accepted limitation, not an oversight:**
- Typing a serial number proves the operator *read a screen correctly*, not
  that they physically identified the right drive bay or USB port — no
  software-only confirmation can close that gap.
- Single-attempt confirmation means a typo costs a full restart.
- Hibernation/Crash Dump checks are near-fully redundant with the
  boot-disk block in most real-world configurations — kept as low-cost
  defense-in-depth for the rare configs where they aren't (e.g.
  `DedicatedDumpFile` pointed at a different volume).
- `MediaType`/`IsRemovable` are simply unreliable on real hardware tested
  during this project — confirmed independently of this program's own code
  — which is exactly why the capacity-trust gate does not depend on them.

**The one thing worth restating plainly:** everything described in this
document is a very thoroughly checked *front door*. The room behind it —
the part that actually erases a disk — has not been built yet.
