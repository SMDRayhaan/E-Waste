# Integrated Secure Data Erasure & Advanced File Recovery Tool — Master Plan

**Problem Statement:** 26149 — *Design and Development of an Integrated Secure
Data Erasure and Advanced File Recovery Tool for Digital Forensics and Data
Sanitization*
**Organization:** National Technical Research Organisation (NTRO)
**Category:** Software · **Theme:** Blockchain & Cybersecurity
**Stack:** Rust, edition 2024, MSRV 1.85 (toolchain in use: 1.98.0). Single
binary today; workspace-ready.
**Dependencies:** `serde`, `serde_json` (Module 1 only, so far)
**No deadline.** Build correctly, in dependency order, not urgency order.

---

## Scope note: this replaces the PS 25070 framing

Earlier work was planned against PS 25070 (IT-asset recycling / "CryptoErase").
The actual assignment is PS 26149 — a larger, dual-purpose forensic platform.
Nothing built is wasted: the existing crate becomes **Module 1**.

| | Old framing (PS 25070) | Actual (PS 26149) |
|---|---|---|
| Buyer | ITAD firms, recyclers, campus IT | Law enforcement, forensic investigators, cybersecurity units, government |
| Narrative | "prove a device was safely disposed of" | "one platform that both destroys data provably **and** recovers data others tried to destroy" |

Those two capabilities are opposites and must both be credible at once. That
tension is managed deliberately — see Module 3.

---

## Three required modules

1. **Secure Drive Eraser** — sanitize HDDs, SSDs, USB drives, memory cards,
   external storage. Verification, audit logging, tamper-resistant reporting,
   compliance with sanitization standards.
2. **Secure File & Folder Eraser** — selective secure deletion of individual
   files/folders, metadata + residual trace removal, batch operations,
   verification, multi-filesystem support.
3. **Advanced File Carving & Recovery** — recover deleted files from formatted,
   damaged or corrupted media. Signature-, structure- and intelligent carving;
   recovery without filesystem metadata; fragmented reconstruction; automatic
   classification; confidence scoring; forensic reporting.

Plus, spanning all three: unified reporting & audit management, a UI dashboard,
and the documentation deliverables named in Part D.

---

# PART A — MODULE 1: SECURE DRIVE ERASER

## A.0 Verified status

Every line below was checked against the code, not carried over from the
previous plan. Claims that did not survive that check are listed in A.0.1.

**Built and tested:**

- Rust scaffold, single binary, `.gitignore`, **103 tests**; `cargo fmt --check`
  / `build` / `test` / `clippy --all-targets -- -D warnings` enforced on every
  change
- PowerShell/CIM execution layer. The stderr guard is load-bearing: CIM cmdlets
  exit 0 while writing the real error to stderr and printing an empty `[]` to
  stdout, so stdout alone cannot distinguish "failed" from "nothing found"
- PowerShell child forced to UTF-8; all stdout decoded strictly (a non-UTF-8
  byte is an error, never a U+FFFD-mangled path)
- Physical disk inventory (`Get-Disk`): number, friendly name, serial, health,
  operational status, IsBoot, IsSystem, size
- Partition inventory (`Get-Partition`): disk number, drive letter, type,
  access paths
- BitLocker inventory (`Get-BitLockerVolume`): mount point, volume status,
  protection status, encryption percentage, volume type, capacity
- Disk ↔ partition ↔ BitLocker correlation, keyed on access paths rather than
  drive letters (a drive letter cannot resolve a VSS VolumeName or a letterless
  volume)
- Administrator/elevation gate — fails closed, no auto-relaunch
- Three-state eligibility engine: `Eligible` / `Blocked` / `Unknown`, with
  `Blocked` > `Unknown` > `Safe` precedence and no path from an unanswerable
  check to `Safe`
- System/boot disk detection — isolated, tested, highest-consequence check
- Extended pre-flight, 5 independent checks: pagefile, hibernation, crash dump,
  VSS shadow copies, self-location
- Security-audit fixes: normalized BitLocker mount-point join (case- and
  separator-insensitive, non-alphabetic drive letters rejected, a join miss
  returns `Unknown`); letterless-partition classification (System/Reserved/
  Recovery skipped, any other letterless partition is `Unknown`); BitLocker
  enumeration failure checked before the partition loop so it cannot be skipped
- Chunked raw overwrite loop (`src/raw_write.rs`): chunking, short-write
  absorption, `Interrupted` retry, `WriteZero` detection, failure-offset
  tracking, progress reporting, cooperative cancellation at chunk boundaries
- Lint hardening: `unsafe_code = "forbid"`, MSRV pinned, `Cargo.lock` committed,
  crate detached into its own workspace root

**Built and tested, but not reachable from any runtime path** (`#[allow(dead_code)]`,
exercised only by tests until the milestone that consumes them):

- `select_target_disk` — target selection with serial confirmation; rejects
  ambiguous disk numbering
- `verify_target_before_operation` — pre-operation re-verification across two
  inventory snapshots; serial is mandatory, refuses a renumbered disk, never
  follows a disk by serial to "recover" from a topology change
- `raw_write::overwrite` — deliberately unwired until M1-5 exists

### A.0.1 Claims corrected during the status audit

- **Bus type is not collected.** The previous plan listed it under disk
  inventory. `Get-Disk` is queried for eight properties and `BusType` is not one
  of them; no media-type, removable, USB, NVMe or SSD detection exists anywhere
  in the crate. All of it is M1-3 work, unstarted.
- **The raw writer did not exist** when previously listed as "designed and
  unit-tested". It does now, but it is the write *loop*, not a write *path*: it
  is generic over `std::io::Write`, opens nothing, and has no caller.
- **"Interruption handling" means cooperative cancellation only.** The writer
  polls a cancel callback at chunk boundaries. It does not survive power loss —
  that requires on-disk state and is M1-12, not done.

## A.1 Removable media — the gap the real spec surfaces

PS 26149 explicitly requires USB drives, memory cards and external storage. The
existing code was written against internal fixed disks and **has never been run
against removable media.** `Get-Disk` should enumerate them, but this is
unverified.

Do this before anything else in Module 1: confirm inventory, eligibility and
pre-flight all behave against a real USB drive and an SD card via reader.
Removable media has distinct failure modes worth testing specifically —
hot-unplug mid-operation, drive-letter reassignment on reconnect, and whether
Windows reports bus type correctly for USB-attached drives.

## A.2 Remaining milestones

- **M1-3** Media/capability detection (HDD/SSD/NVMe/removable, bus type) wired
  into the policy engine — includes adding `BusType`/`MediaType` to the
  `Get-Disk` query
- **M1-4** Planner / dry-run — prints the plan, executes nothing
- **M1-5** Destructive confirmation — explicit serial re-entry, Clear vs. Purge
  acknowledgment shown to the operator. **Gates every write path.**
- **M1-6** Disk offline/online transition, reversible
- **M1-7** HDD sanitization — **first destructive code.** Dedicated test
  hardware only, including at least one USB drive and one memory card
- **M1-8** Verification + reporting — bytes written, failure offset, read-back
  sampling; distinct `EXECUTION_SUCCESS` vs `VERIFICATION_SUCCESS`
- **M1-9** SSD/flash Clear (addressable sectors only, explicitly scoped)
- **M1-10** Crypto-erase via BitLocker key destruction
- **M1-11** NVMe device-level Purge (FFI) — one of the points where
  `unsafe_code = "forbid"` must be consciously relaxed, not deleted
- **M1-12** Interruption / power-loss recovery — never assumes started =
  completed

---

# PART B — MODULE 2: SECURE FILE & FOLDER ERASER

## B.0 Honest scope statement — write this before the code

Wiping a whole disk and securely erasing one file are not the same problem at
different scale. On SSDs, wear-levelling and TRIM mean the OS does not control
where a file's data physically lives; overwriting its logical blocks does not
guarantee the old NAND pages are gone if the controller already remapped them.
On journaling filesystems, copies of content or metadata can persist in the
journal or in filesystem-level shadow structures after the original location is
overwritten.

State this plainly in the documentation, the way Module 1 distinguishes Clear
from Purge:

> File-level secure erasure overwrites the file's allocated logical blocks and
> removes directory/metadata references. On flash media, remnant data may
> persist in controller-managed areas outside OS control. For guaranteed
> sanitization of previously-stored sensitive files on flash media, use
> whole-device crypto-erase or Purge (Module 1) instead.

## B.1 Milestones

- **M2-1** File/folder targeting — path resolution, symlink/junction handling
  (never silently follow a link outside the intended target), batch selection
- **M2-2** Metadata + residual trace inventory — file content, directory entry,
  MFT/inode metadata, journal entries, thumbnail caches, recently-used lists,
  NTFS alternate data streams
- **M2-3** Secure overwrite of file content — reuse `raw_write::overwrite`,
  do not rebuild it
- **M2-4** Metadata scrubbing — directory entry removal, MFT record handling,
  journal cleanup
- **M2-5** Batch operations — per-item success/failure tracking, not one
  aggregate result for a whole batch
- **M2-6** Verification — and documentation of what it can and cannot prove,
  given B.0
- **M2-7** Multi-filesystem support — NTFS first, then FAT32/exFAT for the
  removable media Module 1 also has to handle
- **M2-8** Audit reporting, file-level, sharing the Part D schema

---

# PART C — MODULE 3: ADVANCED FILE CARVING & RECOVERY

## C.0 Size this as its own project

Comparable in scope to PhotoRec, Scalpel or Sleuth Kit. It uses different
techniques from Modules 1 and 2 entirely: reading raw bytes off a device instead
of going through a filesystem API, pattern-matching signatures, and
reconstructing structure without metadata.

**The tension to manage deliberately:** Modules 1 and 2 exist to make data
permanently unrecoverable; Module 3 exists to recover data. If Module 3 could
recover a properly crypto-erased drive, that destroys Module 1's credibility.
Conversely, Module 3 must be honest about what it cannot recover — successfully
Purged or crypto-erased media should report as unrecoverable, explicitly, not
fail silently or claim false success.

## C.1 Techniques required

- **Signature-based carving** — scan raw bytes for known headers/footers and
  extract the range between them. Needs no filesystem metadata. Implement first.
- **Structure-based carving** — use a format's internal structure to determine
  true boundaries and validate extracted data. More accurate, more per-format
  work.
- **Intelligent / fragmented carving** — reconstruct files stored
  non-contiguously. Hardest; needs heuristics for which fragments belong
  together and in what order.

## C.2 Milestones

- **M3-1** Raw device/image reading — read-only, from a device or forensic
  image. **No write path exists in this module at all**; keep that boundary hard
  and visible in the code structure
- **M3-2** Signature-based carver — small initial type set (JPEG, PNG, PDF),
  header/footer matching, extraction to a designated output location
- **M3-3** Automatic classification — validate structure, don't blindly trust a
  signature match
- **M3-4** Confidence scoring — a stated confidence per recovered file (clean
  header+footer with valid internal structure = high; header only, truncated =
  low). A forensic integrity requirement, not a nice-to-have
- **M3-5** Structure-based carving for the initial type set
- **M3-6** Fragmented reconstruction — last, once contiguous carving is solid
- **M3-7** Forensic reporting — what was scanned, what was found, confidence
  scores, timestamps, examiner identity; chain-of-custody appropriate
- **M3-8** Expand file-type coverage based on what is realistically demonstrable

Module 3 starts once Module 1 is stable — its raw device reading benefits from
the disk-identification and safety groundwork Module 1 already has. Do not
rebuild disk enumeration.

---

# PART D — CROSS-CUTTING: REPORTING, AUDIT, BLOCKCHAIN THEME

## D.1 Unified audit/reporting

One evidence format across all three modules. A drive-erase certificate, a
file-erase certificate and a recovery report share a common schema core —
operation type, timestamps, operator identity, device/file identity, method,
result, verification status — with module-specific extensions. Signed JSON is
the authoritative record; PDF is presentation. An independent verifier binary
validates all three report types.

**Design this schema before Modules 2 and 3 each invent their own format.**
Retrofitting a shared schema onto three divergent ones is more work than
designing it once.

## D.2 Blockchain-shaped tamper-evidence (theme-aligned)

- **Hash-chained audit log**, minimum viable: each certificate includes the hash
  of the previous entry, forming an append-only chain. Tampering with any past
  entry breaks every hash after it, detectably. This satisfies the theme's
  substance — Merkle/hash-chaining doing real work — without a distributed
  ledger or consensus.
- **Stretch:** publish the chain head somewhere externally checkable, so
  tampering cannot be hidden by controlling the local log alone.
- Keep the wording honest: a local hash chain is not "we built a blockchain".
  Same discipline as "tamper-evident, not tamper-proof".

## D.3 UI dashboard

An explicit deliverable, not optional. One dashboard across all three modules'
operations, statuses and audit trail. CLI-first internally; GUI once the
underlying modules are stable. Build the engine before the interface.

## D.4 Documentation deliverables

Named in the problem statement itself — track as real milestones, not
week-before polish:

- Validation and testing documentation
- User manuals
- Technical documentation
- Performance evaluation reports

---

# IMMEDIATE NEXT STEPS

1. **Verify Module 1 against removable media** (A.1) — the one concrete gap the
   real spec exposes in already-built code
2. **M1-3 media/capability detection** — add `BusType`/`MediaType` to the
   `Get-Disk` query and wire it into the policy engine. This is genuinely
   unstarted, contrary to the previous plan's status list
3. **M1-4 → M1-5** — dry-run planner, then the destructive confirmation gate.
   Nothing may reach a write path before M1-5 exists
4. **Design the Part D.1 certificate schema** before Module 2 begins
5. **Module 3 after Module 1 is stable**

One milestone, verified, before the next.
