# E-Waste: Team Presentation Guide
## PS 26149 — Integrated Secure Data Erasure and Advanced File Recovery Tool

---

## The One-Line Pitch

**"One platform that both destroys data provably and recovers data others tried to destroy."**

Built for the National Technical Research Organisation (NTRO) — law enforcement, forensic investigators, cybersecurity units, and government — to become the authoritative tool for forensic-grade data sanitization and advanced recovery on seized/suspect media.

---

## The Problem: PS 26149

### Why This Matters
Modern digital forensics needs two contradictory capabilities at once:
1. **Proof of destruction** — when sanitizing a device for disposal/compliance, evidence that data is irreversibly gone
2. **Evidence recovery** — the ability to recover data someone else tried to destroy, for investigation

These are opposites. If a recovery tool could recover data the erasure tool claimed to destroy, the sanitizer loses all credibility. If the recovery tool claims success but silently can't recover what's there, it becomes worthless for forensics.

### Who This Is For
Not consumers. Not IT asset recyclers. **Law enforcement and cybersecurity units**: they need both capabilities on the same platform, and they need both to be *credible* — which means scientifically rigorous, auditable, and honest about limitations.

### A Brief History: Why PS 26149, Not PS 25070?
This project was originally scoped around PS 25070 ("IT-asset recycling / CryptoErase") for ITAD firms and campus IT — a simpler narrative: "prove safe disposal." That work became Module 1. But the actual user need is broader and higher-stakes, so the scope reframed to **PS 26149**, with a law-enforcement and forensics focus instead. Nothing built was lost — the crate remains a single, unified platform addressing both narratives now.

---

## The Vision: What This Will Be

The final deliverable is **one integrated platform with three required modules**, plus cross-cutting reporting and audit infrastructure.

### Module 1: Secure Drive Eraser
**Target**: HDDs, SSDs, USB drives, memory cards, external storage — anything with addressable sectors or device-level controls.

**Capabilities**:
- **Clear** (NIST SP 800-88): logical/addressable-sector overwrite — suitable for SSDs where the full device isn't accessible
- **Purge** (NIST SP 800-88): device-level sanitization (NVMe Secure Erase, BitLocker key destruction, firmware-level erasure) — the gold standard for physical/crypto erasure
- **Verification**: byte-written reporting, failure-offset capture, read-back sampling to confirm data is gone
- **Audit logging**: tamper-evident record of what was wiped, how, and whether it verified
- **Safety gates**: automated system/boot-disk detection, extended pre-flight checks (pagefile, hibernation, shadow copies, exe location), dry-run planning, operator confirmation via serial-number typing

**Current status**: The safety inspector and planning pipeline are built and tested. The actual overwrite executor and verification logic are the next phase.

### Module 2: Secure File & Folder Eraser
**Target**: selective secure deletion of individual files, folders, and their metadata/residual traces across filesystems.

**Capabilities**:
- File/folder targeting with symlink safety
- Metadata scrubbing: MFT entries, journal records, Windows alternate data streams, thumbnail caches
- Multi-filesystem support: NTFS first, then FAT32/exFAT for removable media
- Batch operations and per-item verification
- **Honest limitation**: flash-memory controller-managed areas outside OS control may retain data. For guaranteed flash sanitization, use Module 1's whole-device Purge instead.

**Current status**: Unstarted. Sequenced after Module 1 is stable.

### Module 3: Advanced File Carving & Recovery
**Target**: recover deleted files from formatted, damaged, or corrupted media — **read-only, no write capability**.

**Capabilities**:
- **Signature-based carving**: find files by magic bytes (JPEG/PNG/PDF/etc.) without filesystem metadata
- **Structure-based carving**: validate internal file structure to reduce false positives
- **Intelligent carving**: reconstruct fragmented files across non-contiguous sectors
- **Automatic classification**: distinguish valid files from partial/truncated matches
- **Confidence scoring**: high = complete header+footer+valid structure; low = header-only or truncated
- **Forensic reporting**: chain-of-custody appropriate output, identical schema as Modules 1 & 2

**Scope comparison**: comparable in ambition to PhotoRec, Scalpel, or Sleuth Kit. Uses entirely different techniques from Modules 1 & 2 — reading raw bytes off a device, pattern matching, reconstructing without filesystem APIs.

**Design principle**: **No write path exists in this module at all.** Recovery must never modify source media.

**Current status**: Unstarted. Deliberately deferred until Module 1 is stable, since its raw device-reading will benefit from the disk identification and safety groundwork Module 1 has already built.

### Cross-Cutting: Reporting, Audit & Dashboard (Part D)

#### Unified Audit Schema
One shared evidence record across all three modules:
- Operation type (wipe/file erase/recovery)
- Timestamps and operator identity
- Device/file identity and method used
- Result (success/failure) and verification status
- Module-specific extensions (e.g., bytes verified for Module 1, fragmentation info for Module 3)

#### Tamper-Evident Audit Log (The "Blockchain" Element)
A **hash-chained audit log**, not a real blockchain:
- Each certificate includes the hash of the previous entry, forming an append-only chain
- Tampering with any past entry breaks every hash after it — immediately detectable
- **Explicitly NOT a blockchain**: no distributed ledger, no consensus, no cryptocurrency. It satisfies the "Blockchain & Cybersecurity" theme by doing real cryptographic work (Merkle/hash-chaining), not by overclaiming.
- **Tamper-evident, not tamper-proof**: detects tampering after the fact; cannot prevent it.
- Stretch goal: publish the chain head externally so local tampering can't be hidden entirely.

#### UI Dashboard
A unified interface across all three modules showing:
- Current/historical operation status
- Audit trail
- Verification results

**Sequencing**: CLI-first internally; GUI built once the underlying modules are stable.

#### Documentation Deliverables
Explicitly required by the problem statement:
- Validation and testing documentation
- User manuals
- Technical documentation
- Performance evaluation reports

---

## The Tech Stack and Why

### Language: Rust (Edition 2024, MSRV 1.85)
**Why?** This tool will run with Administrator privileges and perform irreversible disk operations. Memory safety (no buffer overflows, use-after-free, etc.) is non-negotiable. Rust enforces this at compile time.

**Safety discipline**: `unsafe_code = "forbid"` lint — stronger than `deny`, prevents even local `#[allow]` exceptions. Three future milestones are *named in advance* as the points where this will be deliberately, visibly relaxed to `deny` (M1-7: raw disk I/O, M1-11: NVMe FFI, Module 3: raw device reading). When that time comes, the team will see the exception explicitly, not wonder where it snuck in.

### Current Architecture: PowerShell Orchestration
Today, all system data (disk/partition/BitLocker inventory, pagefile/hibernation/crash-dump config) comes from shelling out to `powershell.exe` and parsing JSON:
- `Get-Disk`, `Get-Partition`, `Get-BitLockerVolume` — structured, reliable, Windows-native
- WMI queries for pagefile, shadow copies, registry reads for hibernation/crash-dump
- Zero direct Windows API bindings yet, zero `unsafe` code

**Why this works**: Pragmatic, reduces unsafe-code surface, lets us verify the safety/eligibility logic thoroughly before adding low-level I/O complexity.

**Migration path**: As Module 1's overwrite executor is wired and tested, it will gradually adopt direct Windows APIs (windows-rs crate) for performance and to remove the subprocess overhead. This is deliberate, sequenced, not a rush.

### Dependencies: Minimal
- **serde** (with derive feature): deserialize PowerShell JSON output
- **serde_json**: parse structured data

That's it for Module 1. Module 2 & 3 may add filesystem parsing libraries later; no decision yet.

### NIST SP 800-88 Terminology
The project uses official NIST sanitization categories:
- **Clear**: logical block overwrite, suitable for SSDs where firmware controls allocation
- **Purge**: device-level erasure (stronger), suitable for HDD and NVMe via firmware commands or crypto-erase

Both are supported; the tool will let operators choose based on their security requirements and media type.

### Why Hash-Chaining Instead of a Real Blockchain?
A real blockchain (distributed ledger, consensus, mining) is overkill and introduces complexity that adds zero value for a local audit log. Hash-chaining gives you:
- **Same integrity property**: tampering is detectable
- **Same transparency property**: the chain is human-readable JSON
- **Simpler**: no network, no consensus mechanism, runs offline
- **Honest**: doesn't overclaim to be a blockchain

This is the project's engineering philosophy: solve the actual problem, not the buzzword problem.

---

## Where We Are Today

**Status**: A tested, hardened, read-only Windows disk-safety inspector with a fully designed (but unwired) destructive-operation pipeline.

### What's Built and Working
- **Elevation gate**: fails closed, no auto-relaunch; won't proceed without Administrator
- **Disk inventory**: PowerShell-based enumeration of physical disks, partitions, BitLocker status
- **Two-layer safety model**:
  - Layer 1 (Eligibility): system/boot disk detection — the single highest-consequence check
  - Layer 2 (Pre-flight): seven read-only checks (pagefile, hibernation, crash dump, shadow copies, exe location, media detection, BitLocker protection)
- **Dry-run planning**: shows what would be wiped without touching anything
- **Destructive confirmation gate**: operator must type back the disk's exact serial number; plan is re-derived from scratch and compared bit-for-bit
- **Generic chunked-overwrite loop** (src/raw_write.rs): built, tested, zero callers (deliberately unwired) — handles short writes, interruption, failure-offset reporting
- **Test coverage**: 126 unit tests, all passing; verified against real NVMe, USB, and SD hardware
- **Security hardening**: fail-open bugs found by a dedicated rust-review audit (BitLocker string matching, UTF-8 decoding) were caught and fixed before any write path existed
- **Zero unsafe code**: `unsafe_code = "forbid"` genuinely enforced

### What's Next (Not Yet Built)
- The actual disk-write path: connecting the confirmation gate to the overwrite executor
- SSD/NVMe-specific methods: Clear (M1-9) and Purge via firmware commands (M1-10) and BitLocker key destruction (M1-10)
- NVMe FFI for device-level commands (M1-11) — this is where `unsafe_code` will be consciously relaxed
- Verification and reporting (M1-8): bytes written, failure offset, read-back sampling
- Power-loss recovery (M1-12): on-disk state persistence — today we have cooperative cancellation only
- Module 2 (file-level erasure): unstarted
- Module 3 (file carving & recovery): unstarted
- Cross-cutting reporting/audit/dashboard (Part D): unstarted

### The Working Discipline
Quoted directly from the project's own PLAN.md: **"One milestone, verified, before the next."**

No deadline pressure. Build correctly, in dependency order, not urgency order.

---

## Likely Expert Q&A

### "Isn't this just calling PowerShell? Why not native Win32 APIs?"

**Answer**: Yes, today it does. That's a deliberate, pragmatic choice:
- **Immediate advantage**: PowerShell/WMI is Windows-native, structured, and battle-tested. We get reliable disk/BitLocker inventory without writing C FFI code.
- **Reduces unsafe-code surface**: the safety/eligibility logic is all safe Rust, thoroughly tested.
- **Clear migration path**: once Module 1's overwrite executor is built and verified, direct Windows APIs (windows-rs) will gradually replace PowerShell for performance and to eliminate subprocess overhead.
- **Already zero unsafe code**: when we do migrate, that constraint stays enforced.

### "How do you guarantee data is unrecoverable?"

**Answer**: NIST Clear vs. Purge distinction:
- **Clear**: logical block overwrite — suitable for SSDs where controller allocation tables exist. We overwrite every addressable sector. Remnant data in controller-managed areas is acknowledged but out of scope (user can choose Purge instead).
- **Purge**: device-level erasure — NVMe Secure Erase, BitLocker key destruction, HDD firmware wipe. Physical/cryptographic, not just logical.
- **Verification**: we report two distinct outcomes — `EXECUTION_SUCCESS` (bytes written) and `VERIFICATION_SUCCESS` (read-back sampling confirms zero), so operators know exactly what they got.
- **Honest limitations**: we document what each method does and doesn't cover. No false claims.

### "Isn't a hash chain not a real blockchain?"

**Answer**: Correct, it's deliberately not. Here's why:
- **The actual problem**: we need a tamper-evident audit log. A real blockchain (distributed ledger, consensus) solves problems we don't have.
- **Hash-chaining does the work**: each entry includes the hash of the previous one. Tampering with any past entry breaks every hash after it — immediately detectable.
- **Why this is better engineering**: simpler, offline, no network, human-readable JSON, same integrity property, no overclaiming.
- **Honest wording**: it's "tamper-evident, not tamper-proof" — detects tampering after the fact, doesn't prevent it. The project is explicit about this, not trying to hide the limitation.

### "How do you stop the eraser and recovery tools from contradicting each other?"

**Answer**: By design, not accident:
- **Module 3 has no write path at all** — by architecture, recovery can never modify source media.
- **Coordinated credibility**: if Module 1 certifies data is Purged, Module 3 must report that data as unrecoverable — explicitly, not silently fail or claim false success.
- **The tension is managed deliberately**: PLAN.md explicitly names this as a design principle to maintain. Module 3 documentation will state: "successfully Purged or crypto-erased media should report as unrecoverable, explicitly, not fail silently or claim false success."

### "What happens if power is lost mid-wipe?"

**Answer**: Today, no recovery. Power loss means the operation is interrupted:
- **Current capability**: cooperative, in-process cancellation only. We can stop at a chunk boundary and report exactly how many bytes were written.
- **Not a gap, a deferred feature**: power-loss recovery (on-disk state checkpointing) is a named, sequenced milestone (M1-12), not silently ignored.
- **Deliberate trade-off**: simpler initial implementation, complex state recovery added after Module 1's core methods are stable.

### "How do you know you're not wiping the wrong disk?"

**Answer**: Four-layer safety model, no single point of failure:

| Layer | Mechanism |
|-------|-----------|
| **Eligibility** | Automatic system/boot disk detection — fails closed if detection fails |
| **Pre-flight** | Seven independent read-only checks (pagefile, exe location, etc.) — any Unknown finding prevents planning |
| **Dry-run planning** | Operator sees the plan on screen, can review before proceeding |
| **Confirmation gate** | Operator must type back the disk's exact serial number; inventory is re-fetched and plan is re-verified bit-for-bit before anything happens |

A real bug (BitLocker/UTF-8 decoding) was found mid-audit — it's been fixed and is now a regression test.

### "What's actually tested vs just designed?"

**Answer**: Everything built is tested; everything not yet built is explicitly marked:
- **126 unit tests**, all passing — payfile detection, eligibility evaluation, pre-flight checks, dry-run planning, confirmation logic
- **Real hardware verification**: tested against actual NVMe SSDs, USB drives, SD card readers — the MediaType field behaves differently on real hardware than you might expect
- **Security audit pass**: a dedicated rust-review found real fail-open bugs (BitLocker string matching, UTF-8 decoding at five call sites); they were fixed, not defended
- **The bugs are evidence of rigor**: they were caught because we audit. Fix them and you build trust.
- **The overwrite loop**: built, tested (11 tests), zero callers (deliberately unwired). When we wire a caller, it hooks into tested, known-working code.
- **No stubs**: there are zero `TODO()`, `unimplemented!()`, or `todo!()` markers in the codebase. Things either exist and are tested, or they don't exist yet. No false sense of progress.

---

## Engineering Philosophy

**From the project's own working principle:**

> "One milestone, verified, before the next."

This isn't a deadline-driven codebase. It's built by correctness-first discipline:
- Audit before assuming the design is right
- Fix what audits find, even if it's embarrassing
- Don't build what you can't test
- Don't claim features that don't exist
- When you say "Clear," you mean logical overwrite; when you say "Purge," you mean device-level
- A hash chain isn't a blockchain — don't call it one

---

## Closing: Why This Matters

This tool will be deployed in forensic investigations and high-stakes data sanitization. Every wire burned, every drive wiped, every recovered file could be evidence. The bar for "correct" is not "it usually works" — it's "it's been tested, audited, and built by people who sleep better knowing their code can't silently fail."

That's the project. That's what we're building.

---

## For Your Presentation

- **Slide 1**: The one-liner and context (NTRO, dual-purpose platform)
- **Slide 2-4**: The three modules (vision-forward)
- **Slide 5**: Cross-cutting reporting/audit (the Blockchain element, explained honestly)
- **Slide 6**: Tech stack (Rust, safety, PowerShell-to-APIs migration path)
- **Slide 7**: Current status (a brief, confident overview of what's done)
- **Slide 8**: Q&A — use the prepared answers above
- **Closing**: "One milestone, verified, before the next"

Keep language clear, quote the strong lines ("one platform that both destroys data provably and recovers data others tried to destroy"), show the comparison tables (PS 25070 vs PS 26149, Clear vs Purge), and let the rigor speak for itself.
