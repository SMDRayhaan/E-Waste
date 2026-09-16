mod raw_write;

use serde::Deserialize;
use std::process::{Command, Output};

const POWERSHELL_PATH: &str = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

// Canonical Windows/.NET elevation test: prints "True" only when the current
// process token is actually elevated, "False" otherwise (non-elevated split
// token, or a user who is not an administrator at all).
const ELEVATION_CHECK: &str = "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";

#[derive(Debug, Deserialize)]
struct PhysicalDisk {
    #[serde(rename = "Number")]
    number: u32,
    #[serde(rename = "FriendlyName")]
    friendly_name: String,
    #[serde(rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(rename = "HealthStatus")]
    health_status: String,
    #[serde(rename = "OperationalStatus")]
    operational_status: String,
    #[serde(rename = "IsBoot")]
    is_boot: bool,
    #[serde(rename = "IsSystem")]
    is_system: bool,
    #[serde(rename = "SizeGB")]
    size_gb: f64,
    // Raw byte-exact size, distinct from the rounded-to-2-decimals size_gb
    // above. A future write path must overwrite the disk's real capacity,
    // not a value reconstructed from a lossy display rounding.
    #[serde(rename = "Size")]
    size_bytes: u64,
    // Absent on virtual/exotic disks, so Option rather than a default that
    // would read as a real, recognized value.
    #[serde(rename = "BusType")]
    bus_type: Option<String>,
    #[serde(rename = "MediaType")]
    media_type: Option<String>,
    // Also null on at least one real disk observed in testing, despite
    // IsBoot/IsSystem (booleans from the same cmdlet) never being null.
    #[serde(rename = "IsRemovable")]
    is_removable: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Partition {
    #[serde(rename = "DiskNumber")]
    disk_number: u32,
    #[serde(rename = "DriveLetter")]
    drive_letter: Option<char>,
    #[serde(rename = "Type")]
    partition_type: String,
    // Every mount point Windows knows for this partition: the drive-letter root
    // ("C:\\"), the volume GUID root ("\\\\?\\Volume{...}\\") and any folder mount
    // points. This is what correlates an arbitrary path back to a physical disk --
    // a drive letter alone cannot resolve a VSS VolumeName or a letterless volume.
    #[serde(rename = "AccessPaths")]
    access_paths: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct BitLockerVolume {
    #[serde(rename = "MountPoint")]
    mount_point: String,
    #[serde(rename = "VolumeStatus")]
    volume_status: Option<String>,
    #[serde(rename = "ProtectionStatus")]
    protection_status: String,
    #[serde(rename = "EncryptionPercentage")]
    encryption_percentage: Option<u32>,
    #[serde(rename = "VolumeType")]
    volume_type: String,
    #[serde(rename = "CapacityGB")]
    capacity_gb: f64,
}

fn is_system_disk(disk: &PhysicalDisk) -> bool {
    disk.is_boot || disk.is_system
}

// Get-Partition reports the EFI System Partition, the Microsoft Reserved
// partition and the WinRE recovery partition with these Type values. All three
// are legitimately letterless and hold no user data, so a disk that carries only
// these can still be Eligible. Any other letterless partition is treated as a
// data volume whose protection state must be proven, not assumed.
fn is_bare_system_partition(partition_type: &str) -> bool {
    let t = partition_type.trim();
    t.eq_ignore_ascii_case("System")
        || t.eq_ignore_ascii_case("Reserved")
        || t.eq_ignore_ascii_case("Recovery")
}

// No Unknown variant: with BitLocker's Unknown-producing checks moved out
// (see evaluate_bitlocker_protection), the boot/system-disk flag is the only
// remaining input, and it's always answerable -- there is no longer a case
// where eligibility itself cannot be determined.
enum Eligibility {
    Eligible,
    Blocked(String),
}

// BitLocker protection status used to be checked here and could Block/Unknown
// this result. It no longer does: a physical overwrite destroys ciphertext
// exactly as well as plaintext, so encryption status is not a wrong-disk or
// system-destruction risk. It's now method-selection input (crypto-erase vs.
// physical Purge) reported independently by evaluate_bitlocker_protection(),
// which cannot veto eligibility. See PLAN.md's architecture-cleanup note.
fn evaluate_eligibility(disk: &PhysicalDisk) -> Eligibility {
    if is_system_disk(disk) {
        return Eligibility::Blocked("system/boot disk".to_string());
    }

    Eligibility::Eligible
}

// M1-6: gating for the reversible offline/online transition. Deliberately
// routed through evaluate_eligibility (boot/system-disk check) rather than
// plan_for_disk's capacity-trust gate -- taking a disk offline writes no
// data, so it is orthogonal to whether its reported capacity is trusted.
//
// No pre-check here for removable media: bus_type/is_removable are not a
// reliable way to predict Windows' own "Removable media cannot be set to
// offline" restriction (is_removable is already known to be blank on real
// hardware here, see PhysicalDisk::is_removable), so this defers to
// Set-Disk's own authoritative rejection instead of guessing from an
// unreliable signal.
enum TransitionEligibility {
    Eligible,
    Blocked(String),
}

fn evaluate_transition_eligibility(
    disk: &PhysicalDisk,
    target_offline: bool,
) -> TransitionEligibility {
    if let Eligibility::Blocked(reason) = evaluate_eligibility(disk) {
        return TransitionEligibility::Blocked(reason);
    }

    let currently_offline = disk.operational_status.eq_ignore_ascii_case("Offline");
    if target_offline == currently_offline {
        let state = if currently_offline {
            "offline"
        } else {
            "online"
        };
        return TransitionEligibility::Blocked(format!("disk is already {state}"));
    }

    TransitionEligibility::Eligible
}

// The read-only selection primitive for M1-5's target-selection step,
// called from main() with expected_serial: None -- interactive serial
// confirmation happens afterward, in confirm_and_bind, not at selection.
fn select_target_disk<'a>(
    disks: &'a [PhysicalDisk],
    disk_number: u32,
    expected_serial: Option<&str>,
) -> Result<&'a PhysicalDisk, String> {
    let matches: Vec<&PhysicalDisk> = disks.iter().filter(|d| d.number == disk_number).collect();

    let disk = match matches.len() {
        0 => return Err(format!("no disk found with number {}", disk_number)),
        1 => matches[0],
        _ => {
            return Err(format!(
                "inventory is ambiguous: multiple disks found with number {}",
                disk_number
            ));
        }
    };

    if let Some(expected) = expected_serial {
        match disk.serial_number.as_deref() {
            Some(actual) if actual == expected => {}
            Some(_) => {
                return Err(format!(
                    "serial number mismatch for disk {}: does not match expected confirmation",
                    disk_number
                ));
            }
            None => {
                return Err(format!(
                    "serial number confirmation requested for disk {} but no serial number is available",
                    disk_number
                ));
            }
        }
    }

    match evaluate_eligibility(disk) {
        Eligibility::Eligible => Ok(disk),
        Eligibility::Blocked(reason) => Err(format!("disk {} is blocked: {}", disk_number, reason)),
    }
}

// Final check to run against freshly fetched inventory immediately before any
// future destructive operation. Unlike select_target_disk(), which works within a
// single snapshot where the disk number is a sufficient key, this spans two
// snapshots — so the serial is mandatory here: a different physical disk can
// occupy the same number after a topology change. For that same reason it never
// searches by serial to "follow" a renumbered disk; auto-recovering from a
// changed topology right before a destructive operation must fail closed.
// Called from confirm_and_bind, immediately before it re-derives the plan.
fn verify_target_before_operation<'a>(
    original: &PhysicalDisk,
    fresh_disks: &'a [PhysicalDisk],
) -> Result<&'a PhysicalDisk, String> {
    let expected_serial = match original.serial_number.as_deref() {
        Some(serial) if !serial.trim().is_empty() => serial,
        _ => {
            return Err(format!(
                "disk {} has no usable serial number: identity cannot be proven across snapshots",
                original.number
            ));
        }
    };

    let matches: Vec<&PhysicalDisk> = fresh_disks
        .iter()
        .filter(|d| d.number == original.number)
        .collect();

    let fresh = match matches.len() {
        0 => {
            return Err(format!(
                "disk {} is no longer present in the current inventory",
                original.number
            ));
        }
        1 => matches[0],
        _ => {
            return Err(format!(
                "inventory is ambiguous: multiple disks found with number {}",
                original.number
            ));
        }
    };

    match fresh.serial_number.as_deref() {
        Some(actual) if actual == expected_serial => {}
        Some(_) => {
            return Err(format!(
                "disk {} serial number no longer matches the selected target",
                original.number
            ));
        }
        None => {
            return Err(format!(
                "disk {} no longer reports a serial number: identity cannot be confirmed",
                original.number
            ));
        }
    }

    if fresh.friendly_name != original.friendly_name {
        return Err(format!(
            "disk {} friendly name no longer matches the selected target",
            original.number
        ));
    }

    if fresh.size_gb != original.size_gb {
        return Err(format!(
            "disk {} size no longer matches the selected target",
            original.number
        ));
    }

    // size_gb is rounded to 2 decimals for display; two genuinely different
    // raw capacities can round to the same displayed value. size_bytes is
    // exact and must match too, or a capacity change could slip through.
    if fresh.size_bytes != original.size_bytes {
        return Err(format!(
            "disk {} exact size no longer matches the selected target",
            original.number
        ));
    }

    // Redundant with evaluate_eligibility()'s first check, kept deliberately as
    // defence in depth on the most catastrophic failure case.
    if is_system_disk(fresh) {
        return Err(format!(
            "disk {} is now a system/boot disk",
            original.number
        ));
    }

    match evaluate_eligibility(fresh) {
        Eligibility::Eligible => Ok(fresh),
        Eligibility::Blocked(reason) => Err(format!(
            "disk {} is blocked in the current inventory: {}",
            original.number, reason
        )),
    }
}

// --- M1-4: sanitization planner / dry-run ------------------------------------
//
// States what a sanitize operation would do to a disk, without doing it. Pure
// and read-only: reuses evaluate_eligibility() as the sole gate rather than
// re-deriving it, and never touches raw_write. Method selection (Clear vs.
// Purge, per-media-type handling) is not decided here -- that is M1-5/M1-9/
// M1-11; the two constants below are a deliberately generic placeholder so a
// plan has something concrete to state before that policy exists.
const PLANNED_PATTERN: u8 = 0x00;
const PLANNED_CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

// Bus types whose reported capacity is trusted for planning purposes:
// internal, directly-attached buses where Windows' own value reliably
// reflects true device LBA count. Anything else -- including USB/SD/MMC
// bridge chips, or no bus type reported at all -- fails closed. Confirmed
// necessary on real hardware (A.1): a USB-SD bridge reported ~2045GB for a
// physically 32GB card. This is deliberately keyed on bus type, not media
// type: MediaType can be blank on a perfectly trustworthy internal disk too
// (observed on this machine's own NVMe SSD), so gating on MediaType alone
// would incorrectly withhold a plan for hardware with no capacity problem.
const CAPACITY_TRUSTED_BUS_TYPES: &[&str] = &[
    "SATA",
    "NVMe",
    "SAS",
    "ATA",
    "SCSI",
    "Fibre Channel",
    "RAID",
    "iSCSI",
];

fn is_capacity_trusted_bus(bus_type: Option<&str>) -> bool {
    matches!(
        bus_type,
        Some(b) if CAPACITY_TRUSTED_BUS_TYPES
            .iter()
            .any(|known| b.eq_ignore_ascii_case(known))
    )
}

#[derive(Debug, Clone, PartialEq)]
enum DiskPlan {
    Planned {
        total_bytes: u64,
        pattern: u8,
        chunk_size: usize,
    },
    Skipped(String),
    // No byte count here, deliberately: a disk lands in this state precisely
    // because its reported capacity is not trusted, so the size we'd
    // otherwise report cannot be attached to anything plan-shaped. If it's
    // worth showing at all, main() prints it separately as a labeled
    // inventory fact, sourced from PhysicalDisk directly.
    PendingCapacityConfirmation(String),
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

    DiskPlan::Planned {
        total_bytes: disk.size_bytes,
        pattern: PLANNED_PATTERN,
        chunk_size: PLANNED_CHUNK_SIZE,
    }
}

// --- M1-5: destructive-operation confirmation gate ---------------------------
//
// The last check to run before a future executor (M1-6/M1-7, not built yet)
// would ever be allowed to call raw_write::overwrite. Pure and read-only, like
// everything else in this file up to here -- confirm_and_bind() decides
// whether an operation may be bound, it never performs one. The only thing
// downstream of this milestone that doesn't exist yet is the executor itself.

// The result of a successful confirmation: an identity-verified disk paired
// with the exact plan the operator was shown. Nothing else in this module
// constructs one, and it is never re-derived after this point -- a future
// executor must receive exactly this, not re-fetch or re-plan on its own.
struct BoundOperation<'a> {
    disk: &'a PhysicalDisk,
    plan: DiskPlan,
}

// Every check here fails closed and refuses rather than guesses. Order
// matters only for cost: cheap checks (confirmed_plan shape, serial match)
// run before the more expensive fresh-inventory-dependent ones. Called from
// main()'s confirmation block after the operator's typed line is read.
fn confirm_and_bind<'a>(
    selected: &PhysicalDisk,
    confirmed_plan: &DiskPlan,
    entered_serial: &str,
    fresh_disks: &'a [PhysicalDisk],
) -> Result<BoundOperation<'a>, String> {
    // Defence in depth: this function must not trust that its caller only
    // ever reaches it with a Planned confirmed_plan.
    if !matches!(confirmed_plan, DiskPlan::Planned { .. }) {
        return Err("cannot confirm an operation that was not Planned".to_string());
    }

    let expected_serial = match selected.serial_number.as_deref() {
        Some(serial) if !serial.trim().is_empty() => serial,
        _ => {
            return Err(format!(
                "disk {} has no usable serial number: cannot be confirmed",
                selected.number
            ));
        }
    };

    // Exact, case-sensitive match: the operator is asked to type back exactly
    // what was shown on screen. A blank or whitespace-only line -- including
    // a cancelled prompt -- can never coincidentally equal a real serial.
    if entered_serial.trim() != expected_serial {
        return Err("confirmation did not match the disk's serial number".to_string());
    }

    let fresh = verify_target_before_operation(selected, fresh_disks)?;

    // The actual gap this milestone closes: identity matching alone (above)
    // does not guarantee the plan is unchanged -- a disk can keep the same
    // number, serial, name and size while its bus-type capacity-trust
    // classification changes. Re-deriving and requiring exact structural
    // equality (not just "still Planned") catches that. plan_for_disk needs
    // only the disk itself, not partitions or BitLocker state.
    let fresh_plan = plan_for_disk(fresh);
    if fresh_plan != *confirmed_plan {
        return Err(
            "the plan for this disk has changed since confirmation -- aborting; re-run to reconfirm"
                .to_string(),
        );
    }

    Ok(BoundOperation {
        disk: fresh,
        plan: fresh_plan,
    })
}

// --- M-2: extended pre-flight ------------------------------------------------
//
// A second, independent read-only layer on top of M-1's static eligibility gate.
// M-1 answers "could this disk be a target at all?" (boot/system flags,
// BitLocker); M-2 answers "is Windows using this disk right now?". Nothing here
// writes, and nothing here is wired to a destructive operation — it only produces
// evidence.

// The variant order IS the combination rule: a report's status is the maximum of
// its findings, so Blocked dominates Unknown and Unknown dominates Safe. A check
// that cannot be answered can never be promoted to Safe by other checks passing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PreflightStatus {
    Safe,
    Unknown,
    Blocked,
}

impl PreflightStatus {
    fn label(self) -> &'static str {
        match self {
            PreflightStatus::Safe => "SAFE",
            PreflightStatus::Unknown => "UNKNOWN",
            PreflightStatus::Blocked => "BLOCKED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreflightCheck {
    Pagefile,
    Hibernation,
    CrashDump,
    ShadowCopy,
    ExecutableLocation,
    MediaDetection,
    BitLockerProtection,
}

impl PreflightCheck {
    fn label(self) -> &'static str {
        match self {
            PreflightCheck::Pagefile => "Pagefile",
            PreflightCheck::Hibernation => "Hibernation",
            PreflightCheck::CrashDump => "Crash Dump",
            PreflightCheck::ShadowCopy => "Shadow Copies",
            PreflightCheck::ExecutableLocation => "Executable Location",
            PreflightCheck::MediaDetection => "Media Detection",
            PreflightCheck::BitLockerProtection => "BitLocker Protection",
        }
    }
}

#[derive(Debug)]
struct PreflightFinding {
    check: PreflightCheck,
    status: PreflightStatus,
    detail: String,
}

#[derive(Debug)]
struct PreflightReport {
    findings: Vec<PreflightFinding>,
}

impl PreflightReport {
    fn status(&self) -> PreflightStatus {
        // A report with no findings is not evidence of safety, so an empty report
        // falls to Unknown rather than the Safe that max() would otherwise imply.
        self.findings
            .iter()
            .map(|f| f.status)
            .max()
            .unwrap_or(PreflightStatus::Unknown)
    }
}

// The Option fields below keep "Windows reported this value" distinguishable from
// "the value was absent or unreadable". The second case must surface as Unknown;
// it must never fall back to a default that reads as Safe.
#[derive(Debug, Deserialize)]
struct PageFile {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Source")]
    source: String,
}

#[derive(Debug, Deserialize)]
struct Hibernation {
    #[serde(rename = "HibernateEnabled")]
    enabled: Option<u32>,
    #[serde(rename = "SystemDrive")]
    system_drive: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CrashDump {
    #[serde(rename = "CrashDumpEnabled")]
    enabled: Option<u32>,
    #[serde(rename = "DumpFile")]
    dump_file: Option<String>,
    #[serde(rename = "MinidumpDir")]
    minidump_dir: Option<String>,
    // Set, this overrides DumpFile and can put the kernel dump on an entirely
    // different volume, so it has to be correlated too. Usually absent.
    #[serde(rename = "DedicatedDumpFile")]
    dedicated_dump_file: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShadowCopy {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "VolumeName")]
    volume_name: String,
}

// One Result per check, deliberately not one combined query: a single failing
// provider must degrade exactly one check to Unknown rather than collapsing all
// five into a single uninformative failure.
struct SystemUsage {
    pagefiles: Result<Vec<PageFile>, Box<dyn std::error::Error>>,
    hibernation: Result<Hibernation, Box<dyn std::error::Error>>,
    crash_dump: Result<CrashDump, Box<dyn std::error::Error>>,
    shadow_copies: Result<Vec<ShadowCopy>, Box<dyn std::error::Error>>,
    exe_path: Result<String, Box<dyn std::error::Error>>,
}

// Lowercase, forward slashes folded to backslashes, exactly one trailing
// backslash, so that "C:", "c:\", "C:/" and a volume GUID root all compare
// predictably.
fn normalize_path(path: &str) -> String {
    let lowered = path.trim().to_lowercase().replace('/', "\\");
    format!("{}\\", lowered.trim_end_matches('\\'))
}

// Resolves a filesystem path to the physical disk(s) hosting it, via the longest
// matching AccessPath. Longest wins so a volume mounted at C:\mnt\data claims the
// paths beneath it instead of the C:\ root volume; matching on a drive letter alone
// would attribute those to the wrong physical disk.
//
// Every disk tied at that longest match is returned, not just the first one: a
// single volume can live on several physical disks (a dynamic mirrored or striped
// volume puts the same access path on a partition of each), and every one of them
// genuinely holds the data. Naming only one would let the others report as unused.
//
// An empty result means no partition claims the path. Callers must treat that as
// unknown, never as "not on the target disk".
//
// Known limitation: for a Storage Spaces volume, Get-Partition reports the virtual
// disk's number, so the physical member disks are not correlated here at all.
fn resolve_path_to_disks(path: &str, partitions: &[Partition]) -> Vec<u32> {
    let needle = normalize_path(path);
    let mut best_len = 0;
    let mut disks: Vec<u32> = Vec::new();

    for partition in partitions {
        let Some(access_paths) = &partition.access_paths else {
            continue;
        };

        for access_path in access_paths {
            let root = normalize_path(access_path);

            // An empty access path normalizes to a bare separator, which would
            // otherwise match every path on the system.
            if root.len() <= 1 || !needle.starts_with(&root) {
                continue;
            }

            if root.len() > best_len {
                best_len = root.len();
                disks.clear();
            }

            if root.len() == best_len && !disks.contains(&partition.disk_number) {
                disks.push(partition.disk_number);
            }
        }
    }

    disks
}

// The shared shape of the path-based checks: any path on the target disk blocks;
// any path that resolves to no disk at all is Unknown; only a set that fully
// resolves and lands entirely off the target is Safe.
fn classify_paths(
    check: PreflightCheck,
    disk_number: u32,
    partitions: &[Partition],
    paths: &[(String, String)],
    safe_detail: &str,
) -> PreflightFinding {
    let mut on_target: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();

    for (description, path) in paths {
        let hosts = resolve_path_to_disks(path, partitions);

        if hosts.is_empty() {
            unresolved.push(format!("{} {}", description, path));
        } else if hosts.contains(&disk_number) {
            // Blocks whenever the target is one of the hosts, so a volume spread
            // across several disks blocks every disk it occupies.
            on_target.push(format!("{} {}", description, path));
        }
    }

    if !on_target.is_empty() {
        return PreflightFinding {
            check,
            status: PreflightStatus::Blocked,
            detail: format!("on disk {}: {}", disk_number, on_target.join("; ")),
        };
    }

    if !unresolved.is_empty() {
        return PreflightFinding {
            check,
            status: PreflightStatus::Unknown,
            detail: format!(
                "could not be resolved to a physical disk: {}",
                unresolved.join("; ")
            ),
        };
    }

    PreflightFinding {
        check,
        status: PreflightStatus::Safe,
        detail: safe_detail.to_string(),
    }
}

fn unknown_finding(check: PreflightCheck, detail: String) -> PreflightFinding {
    PreflightFinding {
        check,
        status: PreflightStatus::Unknown,
        detail,
    }
}

fn safe_finding(check: PreflightCheck, detail: &str) -> PreflightFinding {
    PreflightFinding {
        check,
        status: PreflightStatus::Safe,
        detail: detail.to_string(),
    }
}

fn blocked_finding(check: PreflightCheck, detail: String) -> PreflightFinding {
    PreflightFinding {
        check,
        status: PreflightStatus::Blocked,
        detail,
    }
}

fn evaluate_pagefile(
    disk_number: u32,
    partitions: &[Partition],
    usage: &SystemUsage,
) -> PreflightFinding {
    let pagefiles = match &usage.pagefiles {
        Ok(pagefiles) => pagefiles,
        Err(e) => {
            return unknown_finding(
                PreflightCheck::Pagefile,
                format!("pagefile information unavailable: {}", e),
            );
        }
    };

    if pagefiles.is_empty() {
        return safe_finding(
            PreflightCheck::Pagefile,
            "no pagefile is in use or configured on this system",
        );
    }

    let paths: Vec<(String, String)> = pagefiles
        .iter()
        .map(|p| (format!("{} pagefile", p.source), p.name.clone()))
        .collect();

    classify_paths(
        PreflightCheck::Pagefile,
        disk_number,
        partitions,
        &paths,
        "no pagefile resolves to this disk",
    )
}

fn evaluate_hibernation(
    disk_number: u32,
    partitions: &[Partition],
    usage: &SystemUsage,
) -> PreflightFinding {
    let hibernation = match &usage.hibernation {
        Ok(hibernation) => hibernation,
        Err(e) => {
            return unknown_finding(
                PreflightCheck::Hibernation,
                format!("hibernation state unavailable: {}", e),
            );
        }
    };

    // HibernateEnabled is the DWORD powercfg writes: 0 off, non-zero on. Absent
    // means unreadable, not off — inferring the answer from the presence of
    // hiberfil.sys would be a heuristic, so it stays Unknown.
    let Some(enabled) = hibernation.enabled else {
        return unknown_finding(
            PreflightCheck::Hibernation,
            "HibernateEnabled is absent or unreadable".to_string(),
        );
    };

    if enabled == 0 {
        return safe_finding(
            PreflightCheck::Hibernation,
            "hibernation is disabled (HibernateEnabled = 0)",
        );
    }

    // hiberfil.sys lives on the system volume, so hibernation only concerns the
    // target disk when that volume belongs to it.
    let Some(system_drive) = hibernation.system_drive.as_deref() else {
        return unknown_finding(
            PreflightCheck::Hibernation,
            "hibernation is enabled but the system drive could not be determined".to_string(),
        );
    };

    classify_paths(
        PreflightCheck::Hibernation,
        disk_number,
        partitions,
        &[(
            "hibernation system volume (hiberfil.sys)".to_string(),
            system_drive.to_string(),
        )],
        "hibernation is enabled, but the system volume is not on this disk",
    )
}

fn evaluate_crash_dump(
    disk_number: u32,
    partitions: &[Partition],
    usage: &SystemUsage,
) -> PreflightFinding {
    let crash_dump = match &usage.crash_dump {
        Ok(crash_dump) => crash_dump,
        Err(e) => {
            return unknown_finding(
                PreflightCheck::CrashDump,
                format!("crash dump configuration unavailable: {}", e),
            );
        }
    };

    let Some(enabled) = crash_dump.enabled else {
        return unknown_finding(
            PreflightCheck::CrashDump,
            "CrashDumpEnabled is absent or unreadable".to_string(),
        );
    };

    if enabled == 0 {
        return safe_finding(
            PreflightCheck::CrashDump,
            "crash dumps are disabled (CrashDumpEnabled = 0)",
        );
    }

    let mut paths: Vec<(String, String)> = Vec::new();
    if let Some(dump_file) = &crash_dump.dump_file {
        paths.push(("dump file".to_string(), dump_file.clone()));
    }
    if let Some(minidump_dir) = &crash_dump.minidump_dir {
        paths.push(("minidump directory".to_string(), minidump_dir.clone()));
    }
    if let Some(dedicated) = &crash_dump.dedicated_dump_file {
        paths.push(("dedicated dump file".to_string(), dedicated.clone()));
    }

    if paths.is_empty() {
        return unknown_finding(
            PreflightCheck::CrashDump,
            format!(
                "crash dumps are enabled (CrashDumpEnabled = {}) but no dump path is configured",
                enabled
            ),
        );
    }

    classify_paths(
        PreflightCheck::CrashDump,
        disk_number,
        partitions,
        &paths,
        "no configured crash dump path resolves to this disk",
    )
}

fn evaluate_shadow_copies(
    disk_number: u32,
    partitions: &[Partition],
    usage: &SystemUsage,
) -> PreflightFinding {
    let shadow_copies = match &usage.shadow_copies {
        Ok(shadow_copies) => shadow_copies,
        Err(e) => {
            return unknown_finding(
                PreflightCheck::ShadowCopy,
                format!("shadow copy enumeration unavailable: {}", e),
            );
        }
    };

    if shadow_copies.is_empty() {
        return safe_finding(
            PreflightCheck::ShadowCopy,
            "no shadow copies exist on this system",
        );
    }

    let paths: Vec<(String, String)> = shadow_copies
        .iter()
        .map(|s| (format!("shadow copy {} on", s.id), s.volume_name.clone()))
        .collect();

    classify_paths(
        PreflightCheck::ShadowCopy,
        disk_number,
        partitions,
        &paths,
        "no shadow copy resolves to this disk",
    )
}

fn evaluate_executable_location(
    disk_number: u32,
    partitions: &[Partition],
    usage: &SystemUsage,
) -> PreflightFinding {
    let exe_path = match &usage.exe_path {
        Ok(exe_path) => exe_path,
        Err(e) => {
            return unknown_finding(
                PreflightCheck::ExecutableLocation,
                format!("E-Waste executable location unavailable: {}", e),
            );
        }
    };

    classify_paths(
        PreflightCheck::ExecutableLocation,
        disk_number,
        partitions,
        &[("E-Waste executable".to_string(), exe_path.clone())],
        "E-Waste is not running from this disk",
    )
}

// Architecture-cleanup: this used to be evaluate_eligibility()'s partition
// loop and could Block/Unknown the whole disk. It's now purely informational
// -- reported alongside Media Detection, not one of evaluate_preflight's fixed
// checks because it reads BitLockerVolume/Partition data main() already has,
// not SystemUsage. Same checks, same messages, same order as before; only the
// authority to veto a plan is gone. Cannot be called before the disk's own
// partitions have been filtered by the caller, exactly like the eligibility
// version was.
fn evaluate_bitlocker_protection(
    disk: &PhysicalDisk,
    disk_partitions: &[&Partition],
    bitlocker: &Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>>,
) -> PreflightFinding {
    // Checked before the loop, not inside it: a failed Get-BitLockerVolume query
    // is relevant to every disk, so it must not be skipped just because this disk
    // has no lettered partition to trip the check.
    let volumes = match bitlocker {
        Ok(volumes) => volumes,
        Err(e) => {
            return unknown_finding(
                PreflightCheck::BitLockerProtection,
                format!("BitLocker information unavailable: {}", e),
            );
        }
    };

    for partition in disk_partitions {
        let Some(letter) = partition.drive_letter else {
            // Letterless. EFI/MSR/Recovery partitions are legitimately letterless
            // and carry no user data — skip them. Anything else letterless is a
            // data volume we cannot key to a BitLocker entry (correlation is by
            // drive letter only), so its protection state is unknown, not "safe".
            if !is_bare_system_partition(&partition.partition_type) {
                return unknown_finding(
                    PreflightCheck::BitLockerProtection,
                    format!(
                        "disk {} has a letterless {} partition whose BitLocker state cannot be determined",
                        disk.number, partition.partition_type
                    ),
                );
            }
            continue;
        };

        // A drive letter that is not A-Z cannot name a real volume. Get-Partition
        // types DriveLetter as System.Char, so a partition with no letter
        // serializes as "\u0000" and deserializes to Some('\0') rather than None,
        // slipping past the guard above. Fail closed rather than build a key that
        // matches nothing.
        if !letter.is_ascii_alphabetic() {
            return unknown_finding(
                PreflightCheck::BitLockerProtection,
                format!(
                    "partition on disk {} reports an unusable drive letter {:?}",
                    disk.number, letter
                ),
            );
        }

        // Match case-insensitively and tolerate a trailing separator: Get-Partition
        // and Get-BitLockerVolume do not agree on the case or exact shape of a
        // mount point ("c:" vs "C:", "C:" vs "C:\\"). An exact == here turns a
        // BitLocker-protected volume into a silent Safe when the strings differ.
        let mount_point = format!("{}:", letter);
        let Some(volume) = volumes.iter().find(|v| {
            v.mount_point
                .trim_end_matches('\\')
                .eq_ignore_ascii_case(&mount_point)
        }) else {
            // Get-BitLockerVolume lists every fixed volume, protected or not, so a
            // lettered partition with no entry at all is anomalous: report Unknown
            // instead of falling through to Safe.
            return unknown_finding(
                PreflightCheck::BitLockerProtection,
                format!(
                    "no BitLocker entry for volume {} on disk {}: protection state unknown",
                    mount_point, disk.number
                ),
            );
        };

        match volume.protection_status.as_str() {
            "On" => {
                return blocked_finding(
                    PreflightCheck::BitLockerProtection,
                    format!(
                        "volume {} is BitLocker-protected (ProtectionStatus: On)",
                        mount_point
                    ),
                );
            }
            "Off" => continue,
            other => {
                return unknown_finding(
                    PreflightCheck::BitLockerProtection,
                    format!(
                        "volume {} has unrecognized ProtectionStatus '{}'",
                        mount_point, other
                    ),
                );
            }
        }
    }

    safe_finding(
        PreflightCheck::BitLockerProtection,
        "no partition on this disk is BitLocker-protected",
    )
}

// M1-3: media/capability detection. Not one of evaluate_preflight's fixed
// checks because it reads PhysicalDisk, not SystemUsage -- callers append its
// finding to a PreflightReport themselves. Fails closed: BusType/MediaType
// absent, or Windows' own "Unspecified"/"Unknown" sentinels, means we do not
// actually know what kind of media this is, and later method-selection logic
// (SSD vs. HDD vs. NVMe handling) must not be allowed to assume otherwise.
fn is_recognized_media_value(value: Option<&str>) -> bool {
    matches!(value, Some(v) if !v.is_empty() && v != "Unspecified" && v != "Unknown")
}

fn evaluate_media_detection(disk: &PhysicalDisk) -> PreflightFinding {
    let bus_type = disk.bus_type.as_deref();
    let media_type = disk.media_type.as_deref();

    if is_recognized_media_value(bus_type) && is_recognized_media_value(media_type) {
        let removable = disk
            .is_removable
            .map(|b| b.to_string())
            .unwrap_or_else(|| "Unavailable".to_string());
        return safe_finding(
            PreflightCheck::MediaDetection,
            &format!(
                "bus type {} / media type {} / removable: {}",
                bus_type.unwrap(),
                media_type.unwrap(),
                removable
            ),
        );
    }

    unknown_finding(
        PreflightCheck::MediaDetection,
        format!(
            "bus type {} / media type {} not fully recognized",
            bus_type.unwrap_or("(absent)"),
            media_type.unwrap_or("(absent)")
        ),
    )
}

// Pure: no Windows I/O, so the whole safety decision is unit-testable. Emits
// exactly one finding per check, in a fixed order, so the combined result is
// deterministic and no check can be silently omitted from the report.
fn evaluate_preflight(
    disk_number: u32,
    partitions: &[Partition],
    usage: &SystemUsage,
) -> PreflightReport {
    PreflightReport {
        findings: vec![
            evaluate_pagefile(disk_number, partitions, usage),
            evaluate_hibernation(disk_number, partitions, usage),
            evaluate_crash_dump(disk_number, partitions, usage),
            evaluate_shadow_copies(disk_number, partitions, usage),
            evaluate_executable_location(disk_number, partitions, usage),
        ],
    }
}

fn execute_powershell(command: &str) -> Result<Output, Box<dyn std::error::Error>> {
    // powershell.exe emits the console's OEM/ANSI code page by default, so a
    // non-ASCII byte in any queried path would reach us as raw non-UTF-8. Force
    // UTF-8 on the child so decode_powershell_stdout() can be strict.
    let command = format!(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; \
$OutputEncoding=[Text.Encoding]::UTF8; {command}"
    );
    Command::new(POWERSHELL_PATH)
        .args(["-NoProfile", "-Command", &command])
        .output()
        .map_err(|e| e.into())
}

// Strict UTF-8 decode of a PowerShell stdout capture. Unlike from_utf8_lossy, a
// non-UTF-8 sequence becomes an error (-> Unknown downstream) instead of a
// U+FFFD-mangled path that resolve_path_to_disks would silently attribute to the
// wrong physical disk.
fn decode_powershell_stdout(bytes: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s.trim().to_string()),
        Err(_) => Err("PowerShell produced output that was not valid UTF-8".into()),
    }
}

// Only "True"/"False" are accepted; anything else (empty output, a PowerShell
// warning printed to stdout, unexpected text) is an error so the caller fails
// closed rather than guessing about elevation.
fn parse_elevation_output(stdout: &str) -> Result<bool, String> {
    match stdout.trim() {
        "True" => Ok(true),
        "False" => Ok(false),
        other => Err(format!(
            "unexpected output from privilege check: {:?}",
            other
        )),
    }
}

fn is_elevated() -> Result<bool, Box<dyn std::error::Error>> {
    let output = execute_powershell(ELEVATION_CHECK)?;

    let stdout = decode_powershell_stdout(&output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    // Mirrors the getters: PowerShell can exit 0 while reporting the real
    // failure on stderr.
    if !stderr.is_empty() {
        return Err(format!("PowerShell error: {}", stderr).into());
    }

    parse_elevation_output(&stdout).map_err(|e| e.into())
}

fn get_physical_disks() -> Result<Vec<PhysicalDisk>, Box<dyn std::error::Error>> {
    let output = execute_powershell(
        "$disks = @(Get-Disk | Select-Object Number,FriendlyName,SerialNumber,HealthStatus,\
OperationalStatus,IsBoot,IsSystem,@{N='SizeGB';E={[math]::Round($_.Size / 1GB, 2)}},Size,\
@{N='BusType';E={$_.BusType.ToString()}},@{N='MediaType';E={$_.MediaType.ToString()}},\
IsRemovable); \
ConvertTo-Json -InputObject $disks",
    )?;

    let stdout = decode_powershell_stdout(&output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    // Mirrors get_bitlocker_volumes(): a CIM-backed cmdlet can exit 0 while still
    // failing internally, leaving the real error on stderr instead of the exit code.
    if !stderr.is_empty() {
        return Err(format!("PowerShell error: {}", stderr).into());
    }

    if stdout.is_empty() {
        return Ok(Vec::new());
    }

    let disks: Vec<PhysicalDisk> = serde_json::from_str(&stdout)?;
    Ok(disks)
}

// M1-6: reversible offline/online transition. Same error-handling shape as
// every other PowerShell caller here (non-empty stderr is a failure even on
// exit 0) -- but note the error text itself is load-bearing for removable
// media: Set-Disk rejects -IsOffline $true on a removable disk with "Not
// Supported / Removable media cannot be set to offline", and that message is
// passed through verbatim rather than being caught or reworded, since it's
// the OS's own authoritative answer (see evaluate_transition_eligibility).
fn set_disk_offline(disk_number: u32) -> Result<(), String> {
    let output = execute_powershell(&format!("Set-Disk -Number {disk_number} -IsOffline $true"))
        .map_err(|e| e.to_string())?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return Err(format!("PowerShell error: {stderr}"));
    }
    Ok(())
}

fn set_disk_online(disk_number: u32) -> Result<(), String> {
    let output = execute_powershell(&format!("Set-Disk -Number {disk_number} -IsOffline $false"))
        .map_err(|e| e.to_string())?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return Err(format!("PowerShell error: {stderr}"));
    }
    Ok(())
}

fn get_partitions() -> Result<Vec<Partition>, Box<dyn std::error::Error>> {
    let output = execute_powershell(
        "$partitions = @(Get-Partition | \
Select-Object DiskNumber,DriveLetter,Type,AccessPaths); \
ConvertTo-Json -InputObject $partitions",
    )?;

    let stdout = decode_powershell_stdout(&output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    // Mirrors get_physical_disks()/get_bitlocker_volumes(): defend against a
    // CIM-backed cmdlet exiting 0 while still failing internally.
    if !stderr.is_empty() {
        return Err(format!("PowerShell error: {}", stderr).into());
    }

    if stdout.is_empty() {
        return Ok(Vec::new());
    }

    let partitions: Vec<Partition> = serde_json::from_str(&stdout)?;
    Ok(partitions)
}

fn get_bitlocker_volumes() -> Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> {
    let output = execute_powershell(
        "$volumes = @(Get-BitLockerVolume | Select-Object MountPoint,\
@{N='VolumeStatus';E={$_.VolumeStatus.ToString()}},\
@{N='ProtectionStatus';E={$_.ProtectionStatus.ToString()}},\
EncryptionPercentage,\
@{N='VolumeType';E={$_.VolumeType.ToString()}},\
CapacityGB); \
ConvertTo-Json -InputObject $volumes",
    )?;

    let stdout = decode_powershell_stdout(&output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    // Get-BitLockerVolume can exit 0 while still failing internally (e.g. access
    // denied), leaving the real error on stderr instead of the exit code.
    if !stderr.is_empty() {
        return Err(format!("PowerShell error: {}", stderr).into());
    }

    if stdout.is_empty() {
        return Ok(Vec::new());
    }

    let volumes: Vec<BitLockerVolume> = serde_json::from_str(&stdout)?;
    Ok(volumes)
}

// Runs a read-only PowerShell query and returns its trimmed stdout.
//
// The stderr guard is load-bearing, not defensive noise: a failing CIM provider
// exits 0, writes the real error to stderr, and still prints an empty JSON array
// to stdout. Verified on this machine — Win32_ShadowCopy failing with
// WBEM_E_PROVIDER_LOAD_FAILURE emits exactly the same "[]" as a system with no
// shadow copies. stdout alone cannot tell "failed" from "nothing found", so a
// non-empty stderr is the only thing standing between a failed query and a
// silent, falsely reassuring "nothing detected".
//
// ponytail: the three M-1 getters still inline this same guard. Folding them in
// is a behaviour-preserving cleanup, deliberately deferred so M-2 leaves M-1
// byte-for-byte unchanged.
fn powershell_json(command: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = execute_powershell(command)?;

    let stdout = decode_powershell_stdout(&output.stdout)?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !stderr.is_empty() {
        return Err(format!("PowerShell error: {}", stderr).into());
    }

    Ok(stdout)
}

// Two sources, because they answer different questions: Win32_PageFileUsage is
// what is paging right now, Win32_PageFileSetting is what is configured. With an
// automatically managed pagefile the Setting class reports nothing, so neither
// class alone is sufficient. A configured-but-not-yet-active pagefile on the
// target disk is still a reason to refuse.
fn get_pagefiles() -> Result<Vec<PageFile>, Box<dyn std::error::Error>> {
    let stdout = powershell_json(
        "$rows = @(); \
$rows += @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop | \
ForEach-Object { [pscustomobject]@{Name=$_.Name; Source='in-use'} }); \
$rows += @(Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction Stop | \
ForEach-Object { [pscustomobject]@{Name=$_.Name; Source='configured'} }); \
ConvertTo-Json -InputObject @($rows)",
    )?;

    // A successful query never lands here: ConvertTo-Json emits "[]" for an empty
    // result set, so empty output means the query failed without writing to stderr.
    // Reporting that as an empty list would turn a failure into "no pagefile found".
    if stdout.is_empty() {
        return Err("pagefile query returned no output".into());
    }

    let pagefiles: Vec<PageFile> = serde_json::from_str(&stdout)?;
    Ok(pagefiles)
}

// HibernateEnabled is the value powercfg /hibernate writes. SystemDrive comes
// along in the same query because hiberfil.sys always lives on the system volume,
// and that volume is what has to be correlated back to a physical disk.
fn get_hibernation() -> Result<Hibernation, Box<dyn std::error::Error>> {
    let stdout = powershell_json(
        "$power = Get-ItemProperty -Path \
'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power' -ErrorAction Stop; \
ConvertTo-Json -InputObject ([pscustomobject]@{\
HibernateEnabled=$power.HibernateEnabled; SystemDrive=$env:SystemDrive})",
    )?;

    if stdout.is_empty() {
        return Err("hibernation query returned no output".into());
    }

    let hibernation: Hibernation = serde_json::from_str(&stdout)?;
    Ok(hibernation)
}

fn get_crash_dump() -> Result<CrashDump, Box<dyn std::error::Error>> {
    let stdout = powershell_json(
        "$crash = Get-ItemProperty -Path \
'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl' -ErrorAction Stop; \
ConvertTo-Json -InputObject ([pscustomobject]@{\
CrashDumpEnabled=$crash.CrashDumpEnabled; DumpFile=$crash.DumpFile; \
MinidumpDir=$crash.MinidumpDir; DedicatedDumpFile=$crash.DedicatedDumpFile})",
    )?;

    if stdout.is_empty() {
        return Err("crash dump query returned no output".into());
    }

    let crash_dump: CrashDump = serde_json::from_str(&stdout)?;
    Ok(crash_dump)
}

// Enumerates existing shadow copies. VolumeName is a volume GUID root, which is
// why AccessPaths rather than drive letters is the correlation key: a shadow copy
// on a letterless volume is still a shadow copy.
//
// Read-only: this never deletes, resizes or reverts a shadow copy.
fn get_shadow_copies() -> Result<Vec<ShadowCopy>, Box<dyn std::error::Error>> {
    let stdout = powershell_json(
        "$shadows = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop | \
Select-Object ID,VolumeName); ConvertTo-Json -InputObject $shadows",
    )?;

    // As in get_pagefiles(): empty output cannot come from a successful query, so it
    // must not be reported as "no shadow copies exist".
    if stdout.is_empty() {
        return Err("shadow copy query returned no output".into());
    }

    let shadow_copies: Vec<ShadowCopy> = serde_json::from_str(&stdout)?;
    Ok(shadow_copies)
}

// A Windows path is UTF-16 and may hold sequences with no UTF-8 form (unpaired
// surrogates). to_string_lossy would replace them with U+FFFD, and the mangled
// string still prefix-matches a shorter access path -- so classify_paths would
// name the wrong disk and the true host disk would read Safe. Fail closed on a
// lossy conversion instead: an unrepresentable path becomes Unknown.
fn exe_path_to_string(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "executable path is not valid UTF-8".into())
}

// A UNC path (\\server\share\...) or a verbatim path (\\?\C:\...) matches no
// AccessPath and so reports Unknown rather than Safe. That errs in the conservative
// direction, which is the correct way to be wrong here.
fn get_executable_path() -> Result<String, Box<dyn std::error::Error>> {
    exe_path_to_string(&std::env::current_exe()?)
}

// Collected once per run and shared across every disk: these are system-wide
// facts, and re-querying per disk would let the answers drift mid-report.
fn collect_system_usage() -> SystemUsage {
    SystemUsage {
        pagefiles: get_pagefiles(),
        hibernation: get_hibernation(),
        crash_dump: get_crash_dump(),
        shadow_copies: get_shadow_copies(),
        exe_path: get_executable_path(),
    }
}

// Pure: takes the raw arg vector (argv[0] included -- it never matches the
// flag, so no special-casing is needed) so it's testable without touching
// std::env. Absent flag is not an error: the default, argument-free
// behavior (report everything, target nothing) must remain unchanged.
fn parse_disk_number_arg(args: &[String], flag: &str) -> Result<Option<u32>, String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            let value = iter
                .next()
                .ok_or_else(|| format!("{flag} requires a disk number"))?;
            let number: u32 = value
                .parse()
                .map_err(|_| format!("{flag} value {:?} is not a valid disk number", value))?;
            return Ok(Some(number));
        }
    }
    Ok(None)
}

fn parse_target_disk_arg(args: &[String]) -> Result<Option<u32>, String> {
    parse_disk_number_arg(args, "--target-disk")
}

fn parse_offline_disk_arg(args: &[String]) -> Result<Option<u32>, String> {
    parse_disk_number_arg(args, "--offline-disk")
}

fn parse_online_disk_arg(args: &[String]) -> Result<Option<u32>, String> {
    parse_disk_number_arg(args, "--online-disk")
}

fn require_disk_inventory(
    disks_result: &Result<Vec<PhysicalDisk>, Box<dyn std::error::Error>>,
    disk_number: u32,
) -> &[PhysicalDisk] {
    match disks_result {
        Ok(disks) => disks,
        Err(e) => {
            eprintln!(
                "Cannot target disk {}: disk information unavailable: {}",
                disk_number, e
            );
            std::process::exit(2);
        }
    }
}

fn read_stdin_line() -> String {
    print!("> ");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    let mut entered = String::new();
    // A read error (e.g. invalid UTF-8) can never match a real confirmation
    // value, so it is left as an empty line and handled by the same path as
    // a wrong or cancelled entry -- no special-casing needed.
    let _ = std::io::stdin().read_line(&mut entered);
    entered
}

// M1-6: shared flow for --offline-disk/--online-disk. Confirmation is a
// plain "YES" rather than M1-5's serial-retype flow -- this writes no data
// and is reversible (modulo the still-open drive-letter-restoration
// question noted in PLAN.md), so it doesn't warrant that much friction.
fn run_disk_transition(disk_number: u32, target_offline: bool, disks: &[PhysicalDisk]) {
    let verb = if target_offline { "offline" } else { "online" };
    println!(
        "=== Disk {} Transition ===",
        if target_offline { "Offline" } else { "Online" }
    );

    let selected = match select_target_disk(disks, disk_number, None) {
        Ok(selected) => selected,
        Err(e) => {
            eprintln!("Cannot target disk {}: {}", disk_number, e);
            std::process::exit(2);
        }
    };

    if let TransitionEligibility::Blocked(reason) =
        evaluate_transition_eligibility(selected, target_offline)
    {
        eprintln!("Cannot transition disk {}: {}", disk_number, reason);
        std::process::exit(2);
    }

    println!();
    println!("You have selected:");
    println!("  Disk number:      {}", selected.number);
    println!("  Friendly name:    {}", selected.friendly_name);
    println!("  Current state:    {}", selected.operational_status);
    println!("  Requested action: take this disk {}", verb);
    println!();
    println!("This is a reversible state change -- no data is written by this");
    println!("operation. Windows may reject it for reasons unrelated to this tool");
    println!("(for example, removable media cannot be taken offline).");
    println!();
    println!("Type YES and press Enter to proceed. Anything else cancels.");
    println!();

    let entered = read_stdin_line();
    if entered.trim() != "YES" {
        eprintln!("Confirmation failed: input did not match \"YES\".");
        eprintln!("No data has been modified. Re-run the tool to try again.");
        std::process::exit(2);
    }

    let result = if target_offline {
        set_disk_offline(disk_number)
    } else {
        set_disk_online(disk_number)
    };
    if let Err(e) = result {
        eprintln!("Transition failed: {}", e);
        eprintln!("No further action was taken.");
        std::process::exit(2);
    }

    println!();
    println!("Transition command completed. Re-checking inventory...");
    match get_physical_disks() {
        Ok(fresh_disks) => match fresh_disks.iter().find(|d| d.number == disk_number) {
            Some(fresh) => {
                println!("  Disk number:   {}", fresh.number);
                println!("  Friendly name: {}", fresh.friendly_name);
                println!(
                    "  Serial number: {}",
                    fresh.serial_number.as_deref().unwrap_or("(none)")
                );
                println!("  Operational:   {}", fresh.operational_status);
            }
            None => {
                println!(
                    "  Disk {} no longer appears in inventory after the transition.",
                    disk_number
                );
            }
        },
        Err(e) => {
            eprintln!(
                "Transition command completed, but re-inventory failed: {}",
                e
            );
        }
    }
}

fn main() {
    // Parsed before elevation/enumeration: a malformed disk-number value is a
    // pure input error, unrelated to disk access, and should fail fast.
    let args: Vec<String> = std::env::args().collect();
    let target_disk = match parse_target_disk_arg(&args) {
        Ok(target_disk) => target_disk,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(2);
        }
    };
    let offline_disk = match parse_offline_disk_arg(&args) {
        Ok(offline_disk) => offline_disk,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(2);
        }
    };
    let online_disk = match parse_online_disk_arg(&args) {
        Ok(online_disk) => online_disk,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(2);
        }
    };
    if [
        target_disk.is_some(),
        offline_disk.is_some(),
        online_disk.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count()
        > 1
    {
        eprintln!("Only one of --target-disk, --offline-disk, --online-disk may be given.");
        std::process::exit(2);
    }

    // Administrator privileges are a prerequisite: the disk and BitLocker
    // inventory below needs an elevated token, and later milestones will perform
    // operations that must never run unprivileged. Refuse before touching any
    // disk state. No automatic UAC relaunch yet — detect and stop.
    match is_elevated() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("E-Waste must be run as Administrator.");
            eprintln!();
            eprintln!(
                "It needs elevated privileges to inspect physical disks and BitLocker state."
            );
            eprintln!(
                "Close this window, right-click your terminal (PowerShell or Windows Terminal),"
            );
            eprintln!("choose \"Run as administrator\", then run E-Waste again.");
            eprintln!();
            eprintln!("No disks have been inspected or changed.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "E-Waste could not determine whether it is running with administrator privileges: {}",
                e
            );
            eprintln!("Refusing to continue. No disks have been inspected or changed.");
            std::process::exit(1);
        }
    }

    let disks_result = get_physical_disks();
    let partitions_result = get_partitions();
    let bitlocker_result = get_bitlocker_volumes();

    println!("=== Disk Information ===");
    match &disks_result {
        Ok(disks) if disks.is_empty() => {
            println!("No physical disks found.");
        }
        Ok(disks) => {
            for disk in disks {
                let serial = disk.serial_number.as_deref().unwrap_or("Unavailable");

                println!("Disk {}", disk.number);
                println!("  Name: {}", disk.friendly_name);
                println!("  Serial: {}", serial);
                println!("  Health: {}", disk.health_status);
                println!("  Operational: {}", disk.operational_status);
                println!(
                    "  System Disk: {}",
                    if is_system_disk(disk) { "YES" } else { "NO" }
                );
                println!("  Size: {:.2} GB", disk.size_gb);
                println!(
                    "  Bus Type: {}",
                    disk.bus_type.as_deref().unwrap_or("Unavailable")
                );
                println!(
                    "  Media Type: {}",
                    disk.media_type.as_deref().unwrap_or("Unavailable")
                );
                println!(
                    "  Removable: {}",
                    disk.is_removable
                        .map(|b| b.to_string())
                        .unwrap_or_else(|| "Unavailable".to_string())
                );
            }
        }
        Err(e) => {
            eprintln!("Error getting disk information: {}", e);
        }
    }

    println!("=== BitLocker Status ===");
    match &bitlocker_result {
        Ok(volumes) if volumes.is_empty() => {
            println!("No BitLocker-capable volumes found.");
        }
        Ok(volumes) => {
            for volume in volumes {
                let status = volume
                    .volume_status
                    .as_deref()
                    .unwrap_or("Unavailable (volume locked)");
                let encryption = match volume.encryption_percentage {
                    Some(percent) => format!("{}%", percent),
                    None => "Unavailable (volume locked)".to_string(),
                };

                println!("Volume {}", volume.mount_point);
                println!("  Type: {}", volume.volume_type);
                println!("  Status: {}", status);
                println!("  Protection: {}", volume.protection_status);
                println!("  Encryption: {}", encryption);
                println!("  Capacity: {:.2} GB", volume.capacity_gb);
            }
        }
        Err(e) => {
            eprintln!("Error getting BitLocker status: {}", e);
        }
    }

    println!("=== Disk / Partition / BitLocker Correlation ===");
    match (&disks_result, &partitions_result) {
        (Ok(disks), Ok(partitions)) => {
            if disks.is_empty() {
                println!("No physical disks found.");
            }

            for disk in disks {
                println!("Disk {}", disk.number);

                let disk_partitions: Vec<&Partition> = partitions
                    .iter()
                    .filter(|p| p.disk_number == disk.number)
                    .collect();

                if disk_partitions.is_empty() {
                    println!("  No partitions found.");
                    continue;
                }

                for partition in disk_partitions {
                    let Some(letter) = partition.drive_letter else {
                        println!(
                            "  Partition: (no drive letter, type: {})",
                            partition.partition_type
                        );
                        continue;
                    };

                    let mount_point = format!("{}:", letter);
                    println!("  Partition: {}", mount_point);

                    match &bitlocker_result {
                        Ok(volumes) => {
                            match volumes.iter().find(|v| v.mount_point == mount_point) {
                                Some(v) => {
                                    let status = v
                                        .volume_status
                                        .as_deref()
                                        .unwrap_or("Unavailable (volume locked)");
                                    let encryption = match v.encryption_percentage {
                                        Some(percent) => format!("{}%", percent),
                                        None => "Unavailable (volume locked)".to_string(),
                                    };
                                    println!(
                                        "    BitLocker: {} / {} / {} / {}",
                                        mount_point, status, v.protection_status, encryption
                                    );
                                }
                                None => println!("    BitLocker: no matching volume found"),
                            }
                        }
                        Err(_) => {
                            println!("    BitLocker: unavailable (see BitLocker Status above)")
                        }
                    }
                }
            }
        }
        (Err(e), _) => eprintln!("Error getting disk information: {}", e),
        (_, Err(e)) => eprintln!("Error getting partition information: {}", e),
    }

    // M1-1: only the boot/system-disk check now -- BitLocker protection moved
    // to the Extended Pre-Flight section below (see evaluate_bitlocker_protection),
    // since it's method-selection evidence, not a wrong-disk/system-destruction
    // risk a physical overwrite needs to guard against.
    println!("=== Disk Eligibility ===");
    match &disks_result {
        Ok(disks) if disks.is_empty() => {
            println!("No physical disks found.");
        }
        Ok(disks) => {
            for disk in disks {
                print!("Disk {}: ", disk.number);
                match evaluate_eligibility(disk) {
                    Eligibility::Eligible => println!("ELIGIBLE"),
                    Eligibility::Blocked(reason) => println!("BLOCKED: {}", reason),
                }
            }
        }
        Err(e) => eprintln!("Error getting disk information: {}", e),
    }

    // M-2: read-only usage detection. Reports only -- no disk, volume, service,
    // BitLocker or hibernation state is touched, and nothing here gates a
    // destructive operation, because there is not one yet.
    println!("=== Extended Pre-Flight (read-only) ===");
    match (&disks_result, &partitions_result) {
        (Ok(disks), Ok(partitions)) => {
            if disks.is_empty() {
                println!("No physical disks found.");
            }

            // Collected once: these are system-wide facts, and re-querying per
            // disk would let the answers drift mid-report.
            let usage = collect_system_usage();

            for disk in disks {
                println!("Disk {}", disk.number);

                let disk_partitions: Vec<&Partition> = partitions
                    .iter()
                    .filter(|p| p.disk_number == disk.number)
                    .collect();

                let mut report = evaluate_preflight(disk.number, partitions, &usage);
                report.findings.push(evaluate_media_detection(disk));
                report.findings.push(evaluate_bitlocker_protection(
                    disk,
                    &disk_partitions,
                    &bitlocker_result,
                ));
                for finding in &report.findings {
                    println!(
                        "  {:<21}{:<9}{}",
                        format!("{}:", finding.check.label()),
                        finding.status.label(),
                        finding.detail
                    );
                }
                println!("  Result: {}", report.status().label());
            }
        }
        (Ok(disks), Err(e)) => {
            for disk in disks {
                println!(
                    "Disk {}: UNKNOWN: partition information is unavailable, so no path can \
be correlated to a physical disk: {}",
                    disk.number, e
                );
            }
        }
        (Err(e), _) => eprintln!("Error getting disk information: {}", e),
    }

    // M1-4: states what a sanitize operation would do -- nothing here writes,
    // and nothing here is wired to raw_write. Method selection (Clear vs.
    // Purge) is not decided here; see PLANNED_PATTERN/PLANNED_CHUNK_SIZE.
    println!("=== Sanitization Plan (dry-run -- nothing executed) ===");
    match &disks_result {
        Ok(disks) if disks.is_empty() => {
            println!("No physical disks found.");
        }
        Ok(disks) => {
            for disk in disks {
                print!("Disk {}: ", disk.number);
                match plan_for_disk(disk) {
                    DiskPlan::Planned {
                        total_bytes,
                        pattern,
                        chunk_size,
                    } => println!(
                        "PLANNED  overwrite {} bytes, pattern {:#04x}, chunk size {} bytes",
                        total_bytes, pattern, chunk_size
                    ),
                    DiskPlan::Skipped(reason) => println!("SKIPPED  {}", reason),
                    DiskPlan::PendingCapacityConfirmation(reason) => {
                        println!(
                            "PENDING  capacity not trusted: {} -- not planned until resolved",
                            reason
                        );
                        println!(
                            "  (inventory only, capacity trust unresolved: Get-Disk reports {} bytes exact)",
                            disk.size_bytes
                        );
                    }
                }
            }
        }
        Err(e) => eprintln!("Error getting disk information: {}", e),
    }

    // M1-5: the confirmation gate. Opt-in only -- everything above runs
    // unconditionally regardless of --target-disk, so the operator always
    // sees full context before any prompt, and the argument-free default
    // behavior above is unchanged. Refuses before ever printing a prompt if
    // the disk isn't Planned or has no serial; nothing here calls
    // raw_write::overwrite -- confirm_and_bind only decides whether an
    // operation may be bound.
    if let Some(disk_number) = offline_disk {
        let disks = require_disk_inventory(&disks_result, disk_number);
        run_disk_transition(disk_number, true, disks);
        return;
    }

    if let Some(disk_number) = online_disk {
        let disks = require_disk_inventory(&disks_result, disk_number);
        run_disk_transition(disk_number, false, disks);
        return;
    }

    let Some(disk_number) = target_disk else {
        return;
    };

    println!("=== Destructive Operation Confirmation ===");

    let disks = require_disk_inventory(&disks_result, disk_number);

    let selected = match select_target_disk(disks, disk_number, None) {
        Ok(selected) => selected,
        Err(e) => {
            eprintln!("Cannot target disk {}: {}", disk_number, e);
            std::process::exit(2);
        }
    };

    let confirmed_plan = plan_for_disk(selected);
    let (pattern, chunk_size) = match &confirmed_plan {
        DiskPlan::Planned {
            pattern,
            chunk_size,
            ..
        } => (*pattern, *chunk_size),
        DiskPlan::Skipped(reason) => {
            eprintln!("Cannot target disk {}: {}", disk_number, reason);
            std::process::exit(2);
        }
        DiskPlan::PendingCapacityConfirmation(reason) => {
            eprintln!(
                "Cannot target disk {}: capacity not trusted: {}",
                disk_number, reason
            );
            std::process::exit(2);
        }
    };

    let Some(serial) = selected
        .serial_number
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    else {
        eprintln!(
            "Disk {} has no usable serial number and cannot be confirmed.",
            disk_number
        );
        std::process::exit(2);
    };

    println!();
    println!("You have selected:");
    println!("  Disk number:   {}", selected.number);
    println!("  Friendly name: {}", selected.friendly_name);
    println!("  Serial number: {}", serial);
    println!(
        "  Reported size: {:.2} GB ({} bytes exact, per Get-Disk)",
        selected.size_gb, selected.size_bytes
    );
    println!("  Planned action: overwrite the ENTIRE disk with a fixed byte pattern");
    println!(
        "                  ({:#04x}), in {}-byte chunks",
        pattern, chunk_size
    );
    println!();
    println!("This operation is DESTRUCTIVE and IRREVERSIBLE. All data on this disk");
    println!("will be overwritten and will not be recoverable by this tool, or any");
    println!("other software, once the operation completes.");
    println!();
    println!("This confirmation records operator intent only. It does not prove no");
    println!("other process holds this disk open, and it does not certify a NIST");
    println!("SP 800-88 sanitization category -- that determination belongs to a");
    println!("later, unimplemented step.");
    println!();
    println!("To proceed, type this disk's exact serial number and press Enter.");
    println!("Anything else -- including a blank line, or Ctrl+C -- cancels. Nothing");
    println!("has been written to any disk yet.");
    println!();
    let entered = read_stdin_line();

    let fresh_disks = match get_physical_disks() {
        Ok(fresh_disks) => fresh_disks,
        Err(e) => {
            eprintln!(
                "Could not re-verify target: fresh inventory unavailable: {}",
                e
            );
            std::process::exit(2);
        }
    };

    match confirm_and_bind(selected, &confirmed_plan, &entered, &fresh_disks) {
        Ok(bound) => {
            // confirm_and_bind guarantees bound.plan is Planned -- it refuses
            // to construct a BoundOperation otherwise.
            let DiskPlan::Planned {
                total_bytes,
                pattern,
                ..
            } = bound.plan
            else {
                unreachable!("confirm_and_bind only binds a Planned plan");
            };
            println!(
                "Confirmed and bound: disk {} (serial {}), {} bytes, pattern {:#04x}.",
                bound.disk.number,
                bound.disk.serial_number.as_deref().unwrap_or(""),
                total_bytes,
                pattern
            );
            println!(
                "No sanitization executor exists in this build -- nothing further will happen."
            );
        }
        Err(reason) => {
            eprintln!("Confirmation failed: {}", reason);
            eprintln!("No data has been modified. Re-run the tool to try again.");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_disk(is_boot: bool, is_system: bool) -> PhysicalDisk {
        PhysicalDisk {
            number: 0,
            friendly_name: "Test Disk".to_string(),
            serial_number: None,
            health_status: "Healthy".to_string(),
            operational_status: "Online".to_string(),
            is_boot,
            is_system,
            size_gb: 100.0,
            size_bytes: 100 * 1024 * 1024 * 1024,
            bus_type: Some("SATA".to_string()),
            media_type: Some("HDD".to_string()),
            is_removable: Some(false),
        }
    }

    fn make_disk_with_serial(is_boot: bool, is_system: bool, serial: Option<&str>) -> PhysicalDisk {
        PhysicalDisk {
            number: 0,
            friendly_name: "Test Disk".to_string(),
            serial_number: serial.map(|s| s.to_string()),
            health_status: "Healthy".to_string(),
            operational_status: "Online".to_string(),
            is_boot,
            is_system,
            size_gb: 100.0,
            size_bytes: 100 * 1024 * 1024 * 1024,
            bus_type: Some("SATA".to_string()),
            media_type: Some("HDD".to_string()),
            is_removable: Some(false),
        }
    }

    fn make_disk_full(
        number: u32,
        serial: Option<&str>,
        friendly_name: &str,
        size_gb: f64,
        health_status: &str,
        is_boot: bool,
        is_system: bool,
    ) -> PhysicalDisk {
        PhysicalDisk {
            number,
            friendly_name: friendly_name.to_string(),
            serial_number: serial.map(|s| s.to_string()),
            health_status: health_status.to_string(),
            operational_status: "Online".to_string(),
            is_boot,
            is_system,
            size_gb,
            size_bytes: (size_gb * 1024.0 * 1024.0 * 1024.0) as u64,
            bus_type: Some("SATA".to_string()),
            media_type: Some("HDD".to_string()),
            is_removable: Some(false),
        }
    }

    // Canonical selected target the verification tests start from.
    fn make_target_disk() -> PhysicalDisk {
        make_disk_full(
            0,
            Some("ABC123"),
            "Test Disk",
            100.0,
            "Healthy",
            false,
            false,
        )
    }

    #[test]
    fn evaluate_transition_eligibility_blocks_system_disk() {
        let disk = make_disk(true, false);
        assert!(matches!(
            evaluate_transition_eligibility(&disk, true),
            TransitionEligibility::Blocked(_)
        ));
        assert!(matches!(
            evaluate_transition_eligibility(&disk, false),
            TransitionEligibility::Blocked(_)
        ));
    }

    #[test]
    fn evaluate_transition_eligibility_blocks_when_already_offline() {
        let mut disk = make_disk(false, false);
        disk.operational_status = "Offline".to_string();
        assert!(matches!(
            evaluate_transition_eligibility(&disk, true),
            TransitionEligibility::Blocked(_)
        ));
    }

    #[test]
    fn evaluate_transition_eligibility_blocks_when_already_online() {
        let disk = make_disk(false, false); // operational_status: "Online"
        assert!(matches!(
            evaluate_transition_eligibility(&disk, false),
            TransitionEligibility::Blocked(_)
        ));
    }

    #[test]
    fn evaluate_transition_eligibility_allows_valid_transition() {
        let mut offline_disk = make_disk(false, false);
        offline_disk.operational_status = "Offline".to_string();
        assert!(matches!(
            evaluate_transition_eligibility(&offline_disk, false),
            TransitionEligibility::Eligible
        ));

        let online_disk = make_disk(false, false); // operational_status: "Online"
        assert!(matches!(
            evaluate_transition_eligibility(&online_disk, true),
            TransitionEligibility::Eligible
        ));
    }

    fn make_partition(drive_letter: Option<char>) -> Partition {
        Partition {
            disk_number: 0,
            drive_letter,
            partition_type: "Basic".to_string(),
            access_paths: drive_letter.map(|l| vec![format!("{}:\\", l)]),
        }
    }

    fn make_letterless_partition(partition_type: &str) -> Partition {
        Partition {
            disk_number: 0,
            drive_letter: None,
            partition_type: partition_type.to_string(),
            access_paths: None,
        }
    }

    fn make_volume(mount_point: &str, protection_status: &str) -> BitLockerVolume {
        BitLockerVolume {
            mount_point: mount_point.to_string(),
            volume_status: Some("FullyEncrypted".to_string()),
            protection_status: protection_status.to_string(),
            encryption_percentage: Some(100),
            volume_type: "Data".to_string(),
            capacity_gb: 100.0,
        }
    }

    #[test]
    fn elevation_output_true_is_elevated() {
        assert_eq!(parse_elevation_output("True\r\n"), Ok(true));
    }

    #[test]
    fn elevation_output_false_is_not_elevated() {
        assert_eq!(parse_elevation_output("False\n"), Ok(false));
    }

    #[test]
    fn elevation_output_tolerates_surrounding_whitespace() {
        assert_eq!(parse_elevation_output("  True  "), Ok(true));
    }

    #[test]
    fn elevation_output_empty_is_error() {
        assert!(parse_elevation_output("").is_err());
    }

    #[test]
    fn elevation_output_unexpected_text_is_error() {
        assert!(parse_elevation_output("Access is denied.").is_err());
    }

    #[test]
    fn system_disk_is_blocked() {
        let disk = make_disk(true, false);

        let result = evaluate_eligibility(&disk);

        assert!(matches!(result, Eligibility::Blocked(_)));
    }

    #[test]
    fn system_disk_via_is_system_flag_alone_is_blocked() {
        let disk = make_disk(false, true);

        let result = evaluate_eligibility(&disk);

        assert!(matches!(result, Eligibility::Blocked(_)));
    }

    // The tests below exercised evaluate_eligibility()'s BitLocker handling
    // before the architecture cleanup that moved it to
    // evaluate_bitlocker_protection() -- same checks, same messages, same
    // order, now informational (PreflightFinding) rather than able to veto
    // Eligibility.

    #[test]
    fn active_bitlocker_protection_is_blocked() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let volume = make_volume("C:", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Blocked);
    }

    #[test]
    fn missing_bitlocker_data_is_unknown() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> =
            Err("simulated failure".into());

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Unknown);
    }

    #[test]
    fn unrecognized_protection_status_is_unknown() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let volume = make_volume("C:", "Unknown");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Unknown);
    }

    #[test]
    fn non_system_disk_with_protection_off_is_eligible() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        assert!(matches!(evaluate_eligibility(&disk), Eligibility::Eligible));
        assert_eq!(
            evaluate_bitlocker_protection(&disk, &partitions, &bitlocker).status,
            PreflightStatus::Safe
        );
    }

    #[test]
    fn one_protected_volume_among_multiple_partitions_is_blocked() {
        let disk = make_disk(false, false);
        let partition_c = make_partition(Some('C'));
        let partition_d = make_partition(Some('D'));
        let partitions = vec![&partition_c, &partition_d];
        let volume_c = make_volume("C:", "Off");
        let volume_d = make_volume("D:", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> =
            Ok(vec![volume_c, volume_d]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Blocked);
    }

    #[test]
    fn lettered_partition_with_no_bitlocker_entry_is_unknown() {
        // Get-BitLockerVolume lists every fixed volume, so a lettered partition
        // with no entry at all is anomalous: fail closed, do not fall through to
        // Safe.
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Unknown);
    }

    #[test]
    fn lowercase_drive_letter_still_matches_protected_volume() {
        // Get-Partition may emit "c" while Get-BitLockerVolume reports "C:". An
        // exact == would miss and silently mark the encrypted disk Safe.
        let disk = make_disk(false, false);
        let partition = make_partition(Some('c'));
        let partitions = vec![&partition];
        let volume = make_volume("C:", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Blocked);
    }

    #[test]
    fn trailing_separator_mount_point_still_matches_protected_volume() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let volume = make_volume("C:\\", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Blocked);
    }

    #[test]
    fn nul_drive_letter_is_unknown() {
        // A partition with no assigned letter serializes from System.Char as
        // "\u0000" and deserializes to Some('\0'), passing the Option guard.
        let disk = make_disk(false, false);
        let partition = make_partition(Some('\0'));
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Unknown);
    }

    #[test]
    fn letterless_efi_msr_recovery_partitions_do_not_force_unknown() {
        // EFI System, MSR (Reserved) and WinRE (Recovery) partitions are
        // legitimately letterless and hold no user data.
        let disk = make_disk(false, false);
        let system = make_letterless_partition("System");
        let reserved = make_letterless_partition("Reserved");
        let recovery = make_letterless_partition("Recovery");
        let partitions = vec![&system, &reserved, &recovery];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Safe);
    }

    #[test]
    fn letterless_data_volume_is_unknown() {
        // A "Basic" partition with no drive letter is a data volume we cannot
        // correlate to a BitLocker entry: its protection state is unknown.
        let disk = make_disk(false, false);
        let partition = make_partition(None);
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Unknown);
    }

    #[test]
    fn letterless_data_volume_among_system_partitions_is_unknown() {
        let disk = make_disk(false, false);
        let system = make_letterless_partition("System");
        let data = make_partition(None);
        let partitions = vec![&system, &data];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Unknown);
    }

    #[test]
    fn unrecognized_letterless_partition_type_is_unknown() {
        // Anything not System/Reserved/Recovery is treated as a data volume.
        let disk = make_disk(false, false);
        let partition = make_letterless_partition("");
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Unknown);
    }

    #[test]
    fn lettered_volume_still_evaluated_past_a_letterless_system_partition() {
        // The letterless-partition skip must not short-circuit evaluation of the
        // real lettered volumes that follow it.
        let disk = make_disk(false, false);
        let system = make_letterless_partition("System");
        let data = make_partition(Some('D'));
        let partitions = vec![&system, &data];
        let volume = make_volume("D:", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Blocked);
    }

    #[test]
    fn bitlocker_failure_with_no_lettered_partitions_is_unknown() {
        // A failed Get-BitLockerVolume query must not be skipped just because the
        // disk has no lettered partition to reach the check.
        let disk = make_disk(false, false);
        let partition = make_letterless_partition("System");
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> =
            Err("simulated failure".into());

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Unknown);
    }

    #[test]
    fn bitlocker_failure_with_empty_partition_list_is_unknown() {
        let disk = make_disk(false, false);
        let partitions: Vec<&Partition> = vec![];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> =
            Err("simulated failure".into());

        let result = evaluate_bitlocker_protection(&disk, &partitions, &bitlocker);

        assert_eq!(result.status, PreflightStatus::Unknown);
    }

    #[test]
    fn select_nonexistent_disk_returns_err() {
        let disks = vec![make_disk(false, false)];

        let result = select_target_disk(&disks, 99, None);

        assert!(result.is_err());
    }

    #[test]
    fn select_system_disk_returns_err() {
        let disks = vec![make_disk(true, false)];

        let result = select_target_disk(&disks, 0, None);

        assert!(result.is_err());
    }

    #[test]
    fn select_disk_with_active_bitlocker_returns_ok() {
        // Architecture cleanup: BitLocker protection no longer gates
        // selection -- a physical overwrite destroys ciphertext exactly as
        // well as plaintext, so it's method-selection evidence (reported via
        // evaluate_bitlocker_protection), not a wrong-disk/system-destruction
        // risk select_target_disk needs to guard against.
        let disks = vec![make_disk(false, false)];

        let result = select_target_disk(&disks, 0, None);

        assert!(result.is_ok());
    }

    #[test]
    fn select_eligible_disk_without_serial_returns_ok() {
        let disks = vec![make_disk(false, false)];

        let result = select_target_disk(&disks, 0, None);

        assert!(result.is_ok());
    }

    #[test]
    fn select_eligible_disk_with_correct_serial_returns_ok() {
        let disks = vec![make_disk_with_serial(false, false, Some("ABC123"))];

        let result = select_target_disk(&disks, 0, Some("ABC123"));

        assert!(result.is_ok());
    }

    #[test]
    fn select_eligible_disk_with_incorrect_serial_returns_err() {
        let disks = vec![make_disk_with_serial(false, false, Some("ABC123"))];

        let result = select_target_disk(&disks, 0, Some("WRONG"));

        assert!(result.is_err());
    }

    #[test]
    fn select_disk_requiring_serial_but_unavailable_returns_err() {
        let disks = vec![make_disk_with_serial(false, false, None)];

        let result = select_target_disk(&disks, 0, Some("ABC123"));

        assert!(result.is_err());
    }

    #[test]
    fn select_disk_with_duplicate_numbers_returns_err() {
        let disks = vec![make_disk(false, false), make_disk(false, false)];

        let result = select_target_disk(&disks, 0, None);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_original_without_serial() {
        let original = make_disk_full(0, None, "Test Disk", 100.0, "Healthy", false, false);
        let fresh_disks = vec![make_target_disk()];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_original_with_empty_serial() {
        let original = make_disk_full(0, Some("   "), "Test Disk", 100.0, "Healthy", false, false);
        let fresh_disks = vec![make_disk_full(
            0,
            Some("   "),
            "Test Disk",
            100.0,
            "Healthy",
            false,
            false,
        )];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_when_disk_is_gone() {
        let original = make_target_disk();
        let fresh_disks: Vec<PhysicalDisk> = vec![];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_duplicate_disk_numbers() {
        let original = make_target_disk();
        let fresh_disks = vec![make_target_disk(), make_target_disk()];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_when_serial_differs() {
        let original = make_target_disk();
        let fresh_disks = vec![make_disk_full(
            0,
            Some("DIFFERENT"),
            "Test Disk",
            100.0,
            "Healthy",
            false,
            false,
        )];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_when_fresh_serial_is_missing() {
        let original = make_target_disk();
        let fresh_disks = vec![make_disk_full(
            0,
            None,
            "Test Disk",
            100.0,
            "Healthy",
            false,
            false,
        )];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_when_friendly_name_differs() {
        let original = make_target_disk();
        let fresh_disks = vec![make_disk_full(
            0,
            Some("ABC123"),
            "Different Disk",
            100.0,
            "Healthy",
            false,
            false,
        )];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_when_size_differs() {
        let original = make_target_disk();
        let fresh_disks = vec![make_disk_full(
            0,
            Some("ABC123"),
            "Test Disk",
            250.0,
            "Healthy",
            false,
            false,
        )];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_when_disk_is_now_system_disk() {
        let original = make_target_disk();
        let fresh_disks = vec![make_disk_full(
            0,
            Some("ABC123"),
            "Test Disk",
            100.0,
            "Healthy",
            true,
            false,
        )];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn verify_accepts_when_volume_is_now_protected() {
        // Architecture cleanup: BitLocker protection no longer gates
        // verification either -- see select_disk_with_active_bitlocker_returns_ok.
        let original = make_target_disk();
        let fresh_disks = vec![make_target_disk()];

        let result = verify_target_before_operation(&original, &fresh_disks);

        assert!(result.is_ok());
    }

    #[test]
    fn verify_accepts_matching_disk_and_returns_fresh_inventory_entry() {
        // health_status is not an identity field, so it may differ between
        // snapshots — used here to prove the returned reference is the fresh one.
        let original = make_target_disk();
        let fresh_disks = vec![make_disk_full(
            0,
            Some("ABC123"),
            "Test Disk",
            100.0,
            "Warning",
            false,
            false,
        )];

        let result = verify_target_before_operation(&original, &fresh_disks);

        let verified = result.expect("matching disk should verify");
        assert_eq!(verified.health_status, "Warning");
        assert!(std::ptr::eq(verified, &fresh_disks[0]));
    }

    // --- M1-5: destructive-operation confirmation gate ----------------------

    #[test]
    fn confirm_and_bind_succeeds_when_everything_matches() {
        let selected = make_target_disk();
        let confirmed_plan = plan_for_disk(&selected);
        let fresh_disks = vec![make_target_disk()];

        let result = confirm_and_bind(&selected, &confirmed_plan, "ABC123", &fresh_disks);

        let bound = result.expect("matching confirmation should bind");
        assert_eq!(bound.plan, confirmed_plan);
    }

    #[test]
    fn confirm_and_bind_rejects_wrong_serial() {
        let selected = make_target_disk();
        let confirmed_plan = plan_for_disk(&selected);
        let fresh_disks = vec![make_target_disk()];

        let result = confirm_and_bind(&selected, &confirmed_plan, "WRONG", &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn confirm_and_bind_rejects_empty_confirmation() {
        // Also covers an operator cancelling the prompt: a blank line can
        // never coincidentally equal a real serial.
        let selected = make_target_disk();
        let confirmed_plan = plan_for_disk(&selected);
        let fresh_disks = vec![make_target_disk()];

        let result = confirm_and_bind(&selected, &confirmed_plan, "   ", &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn confirm_and_bind_rejects_a_disk_with_no_serial() {
        let selected = make_disk(false, false);
        let confirmed_plan = plan_for_disk(&selected);
        let fresh_disks = vec![make_disk(false, false)];

        let result = confirm_and_bind(&selected, &confirmed_plan, "anything", &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn confirm_and_bind_rejects_when_disk_is_gone() {
        let selected = make_target_disk();
        let confirmed_plan = plan_for_disk(&selected);
        let fresh_disks: Vec<PhysicalDisk> = vec![];

        let result = confirm_and_bind(&selected, &confirmed_plan, "ABC123", &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn confirm_and_bind_rejects_when_disk_is_now_system_disk() {
        let selected = make_target_disk();
        let confirmed_plan = plan_for_disk(&selected);
        let fresh_disks = vec![make_disk_full(
            0,
            Some("ABC123"),
            "Test Disk",
            100.0,
            "Healthy",
            true,
            false,
        )];

        let result = confirm_and_bind(&selected, &confirmed_plan, "ABC123", &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn confirm_and_bind_rejects_duplicate_disk_numbers_in_fresh_inventory() {
        let selected = make_target_disk();
        let confirmed_plan = plan_for_disk(&selected);
        let fresh_disks = vec![make_target_disk(), make_target_disk()];

        let result = confirm_and_bind(&selected, &confirmed_plan, "ABC123", &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn confirm_and_bind_rejects_when_bus_type_reclassified() {
        // The scenario this milestone exists to close: identity fields
        // (number, serial, name, size) are all unchanged, so
        // verify_target_before_operation alone would accept this. Only the
        // plan-equality re-check catches the capacity-trust reclassification.
        let selected = make_target_disk();
        let confirmed_plan = plan_for_disk(&selected);
        assert!(matches!(confirmed_plan, DiskPlan::Planned { .. }));

        let mut fresh = make_target_disk();
        fresh.bus_type = Some("USB".to_string());
        let fresh_disks = vec![fresh];

        let result = confirm_and_bind(&selected, &confirmed_plan, "ABC123", &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn confirm_and_bind_rejects_when_size_bytes_differs_but_size_gb_does_not() {
        // Proves the verify_target_before_operation precision fix is wired
        // in: size_gb is rounded to 2 decimals and can't distinguish this.
        let selected = make_target_disk();
        let confirmed_plan = plan_for_disk(&selected);

        let mut fresh = make_target_disk();
        fresh.size_bytes += 1;
        let fresh_disks = vec![fresh];

        let result = confirm_and_bind(&selected, &confirmed_plan, "ABC123", &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn confirm_and_bind_requires_a_planned_confirmed_plan() {
        let selected = make_target_disk();
        let not_planned = DiskPlan::Skipped("test".to_string());
        let fresh_disks = vec![make_target_disk()];

        let result = confirm_and_bind(&selected, &not_planned, "ABC123", &fresh_disks);

        assert!(result.is_err());
    }

    #[test]
    fn parse_target_disk_arg_returns_none_when_absent() {
        let args = vec!["E-Waste.exe".to_string()];

        assert_eq!(parse_target_disk_arg(&args), Ok(None));
    }

    #[test]
    fn parse_target_disk_arg_parses_a_valid_number() {
        let args = vec![
            "E-Waste.exe".to_string(),
            "--target-disk".to_string(),
            "1".to_string(),
        ];

        assert_eq!(parse_target_disk_arg(&args), Ok(Some(1)));
    }

    #[test]
    fn parse_target_disk_arg_errors_when_value_is_missing() {
        let args = vec!["E-Waste.exe".to_string(), "--target-disk".to_string()];

        assert!(parse_target_disk_arg(&args).is_err());
    }

    #[test]
    fn parse_target_disk_arg_errors_when_value_is_not_a_number() {
        let args = vec![
            "E-Waste.exe".to_string(),
            "--target-disk".to_string(),
            "abc".to_string(),
        ];

        assert!(parse_target_disk_arg(&args).is_err());
    }

    // --- M-2: extended pre-flight -------------------------------------------

    // Two-disk fixture. Disk 0 holds C:, disk 1 is the target under test and holds
    // E:. Both carry a volume GUID access path, as real partitions do.
    const TARGET: u32 = 1;
    const OTHER_GUID: &str = "\\\\?\\Volume{aaaaaaaa-0000-0000-0000-000000000000}\\";
    const TARGET_GUID: &str = "\\\\?\\Volume{bbbbbbbb-0000-0000-0000-000000000000}\\";

    fn make_partition_on(disk_number: u32, access_paths: &[&str]) -> Partition {
        Partition {
            disk_number,
            drive_letter: None,
            partition_type: "Basic".to_string(),
            access_paths: Some(access_paths.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn preflight_partitions() -> Vec<Partition> {
        vec![
            make_partition_on(0, &["C:\\", OTHER_GUID]),
            make_partition_on(TARGET, &["E:\\", TARGET_GUID]),
        ]
    }

    // Deliberately not an empty system: every check has real data, all of it on
    // disk 0. A fixture of empty vectors would pass the "safe" test without
    // proving the checks discriminate between disks at all.
    fn safe_usage() -> SystemUsage {
        SystemUsage {
            pagefiles: Ok(vec![PageFile {
                name: "C:\\pagefile.sys".to_string(),
                source: "in-use".to_string(),
            }]),
            hibernation: Ok(Hibernation {
                enabled: Some(0),
                system_drive: Some("C:".to_string()),
            }),
            crash_dump: Ok(CrashDump {
                enabled: Some(3),
                dump_file: Some("C:\\WINDOWS\\MEMORY.DMP".to_string()),
                minidump_dir: Some("C:\\WINDOWS\\Minidump".to_string()),
                dedicated_dump_file: None,
            }),
            shadow_copies: Ok(vec![ShadowCopy {
                id: "{11111111-0000-0000-0000-000000000000}".to_string(),
                volume_name: OTHER_GUID.to_string(),
            }]),
            exe_path: Ok("C:\\tools\\e-waste.exe".to_string()),
        }
    }

    fn finding_for(report: &PreflightReport, check: PreflightCheck) -> &PreflightFinding {
        report
            .findings
            .iter()
            .find(|f| f.check == check)
            .expect("every check must produce exactly one finding")
    }

    fn status_of(usage: &SystemUsage, check: PreflightCheck) -> PreflightStatus {
        let partitions = preflight_partitions();
        let report = evaluate_preflight(TARGET, &partitions, usage);
        finding_for(&report, check).status
    }

    #[test]
    fn preflight_with_no_usage_on_target_is_safe() {
        let partitions = preflight_partitions();
        let report = evaluate_preflight(TARGET, &partitions, &safe_usage());

        assert_eq!(report.status(), PreflightStatus::Safe);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.status == PreflightStatus::Safe),
            "expected every finding to be safe, got {:?}",
            report.findings
        );
    }

    #[test]
    fn every_check_produces_exactly_one_finding_in_fixed_order() {
        let partitions = preflight_partitions();
        let report = evaluate_preflight(TARGET, &partitions, &safe_usage());

        let checks: Vec<PreflightCheck> = report.findings.iter().map(|f| f.check).collect();
        assert_eq!(
            checks,
            vec![
                PreflightCheck::Pagefile,
                PreflightCheck::Hibernation,
                PreflightCheck::CrashDump,
                PreflightCheck::ShadowCopy,
                PreflightCheck::ExecutableLocation,
            ]
        );
    }

    #[test]
    fn pagefile_on_target_is_blocked() {
        let mut usage = safe_usage();
        usage.pagefiles = Ok(vec![PageFile {
            name: "E:\\pagefile.sys".to_string(),
            source: "in-use".to_string(),
        }]);

        assert_eq!(
            status_of(&usage, PreflightCheck::Pagefile),
            PreflightStatus::Blocked
        );
    }

    #[test]
    fn configured_but_inactive_pagefile_on_target_is_blocked() {
        let mut usage = safe_usage();
        usage.pagefiles = Ok(vec![PageFile {
            name: "E:\\pagefile.sys".to_string(),
            source: "configured".to_string(),
        }]);

        assert_eq!(
            status_of(&usage, PreflightCheck::Pagefile),
            PreflightStatus::Blocked
        );
    }

    #[test]
    fn pagefile_on_another_disk_is_safe() {
        assert_eq!(
            status_of(&safe_usage(), PreflightCheck::Pagefile),
            PreflightStatus::Safe
        );
    }

    #[test]
    fn pagefile_query_failure_is_unknown() {
        let mut usage = safe_usage();
        usage.pagefiles = Err("simulated failure".into());

        assert_eq!(
            status_of(&usage, PreflightCheck::Pagefile),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn hibernation_enabled_with_system_volume_on_target_is_blocked() {
        let mut usage = safe_usage();
        usage.hibernation = Ok(Hibernation {
            enabled: Some(1),
            system_drive: Some("E:".to_string()),
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::Hibernation),
            PreflightStatus::Blocked
        );
    }

    #[test]
    fn hibernation_enabled_with_system_volume_elsewhere_is_safe() {
        let mut usage = safe_usage();
        usage.hibernation = Ok(Hibernation {
            enabled: Some(1),
            system_drive: Some("C:".to_string()),
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::Hibernation),
            PreflightStatus::Safe
        );
    }

    #[test]
    fn hibernation_disabled_is_safe() {
        assert_eq!(
            status_of(&safe_usage(), PreflightCheck::Hibernation),
            PreflightStatus::Safe
        );
    }

    #[test]
    fn hibernation_registry_value_absent_is_unknown() {
        let mut usage = safe_usage();
        usage.hibernation = Ok(Hibernation {
            enabled: None,
            system_drive: Some("C:".to_string()),
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::Hibernation),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn hibernation_enabled_without_system_drive_is_unknown() {
        let mut usage = safe_usage();
        usage.hibernation = Ok(Hibernation {
            enabled: Some(1),
            system_drive: None,
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::Hibernation),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn hibernation_query_failure_is_unknown() {
        let mut usage = safe_usage();
        usage.hibernation = Err("simulated failure".into());

        assert_eq!(
            status_of(&usage, PreflightCheck::Hibernation),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn crash_dump_on_target_is_blocked() {
        let mut usage = safe_usage();
        usage.crash_dump = Ok(CrashDump {
            enabled: Some(3),
            dump_file: Some("E:\\dumps\\MEMORY.DMP".to_string()),
            minidump_dir: None,
            dedicated_dump_file: None,
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::CrashDump),
            PreflightStatus::Blocked
        );
    }

    #[test]
    fn crash_dump_minidump_directory_on_target_is_blocked() {
        let mut usage = safe_usage();
        usage.crash_dump = Ok(CrashDump {
            enabled: Some(3),
            dump_file: Some("C:\\WINDOWS\\MEMORY.DMP".to_string()),
            minidump_dir: Some("E:\\Minidump".to_string()),
            dedicated_dump_file: None,
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::CrashDump),
            PreflightStatus::Blocked
        );
    }

    #[test]
    fn crash_dump_disabled_is_safe() {
        let mut usage = safe_usage();
        usage.crash_dump = Ok(CrashDump {
            enabled: Some(0),
            dump_file: Some("E:\\dumps\\MEMORY.DMP".to_string()),
            minidump_dir: Some("E:\\Minidump".to_string()),
            dedicated_dump_file: None,
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::CrashDump),
            PreflightStatus::Safe
        );
    }

    #[test]
    fn crash_dump_enabled_without_any_path_is_unknown() {
        let mut usage = safe_usage();
        usage.crash_dump = Ok(CrashDump {
            enabled: Some(3),
            dump_file: None,
            minidump_dir: None,
            dedicated_dump_file: None,
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::CrashDump),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn crash_dump_registry_value_absent_is_unknown() {
        let mut usage = safe_usage();
        usage.crash_dump = Ok(CrashDump {
            enabled: None,
            dump_file: Some("C:\\WINDOWS\\MEMORY.DMP".to_string()),
            minidump_dir: None,
            dedicated_dump_file: None,
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::CrashDump),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn crash_dump_query_failure_is_unknown() {
        let mut usage = safe_usage();
        usage.crash_dump = Err("simulated failure".into());

        assert_eq!(
            status_of(&usage, PreflightCheck::CrashDump),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn shadow_copy_on_target_is_blocked() {
        let mut usage = safe_usage();
        usage.shadow_copies = Ok(vec![ShadowCopy {
            id: "{22222222-0000-0000-0000-000000000000}".to_string(),
            volume_name: TARGET_GUID.to_string(),
        }]);

        assert_eq!(
            status_of(&usage, PreflightCheck::ShadowCopy),
            PreflightStatus::Blocked
        );
    }

    #[test]
    fn shadow_copy_on_another_disk_is_safe() {
        assert_eq!(
            status_of(&safe_usage(), PreflightCheck::ShadowCopy),
            PreflightStatus::Safe
        );
    }

    #[test]
    fn no_shadow_copies_is_safe() {
        let mut usage = safe_usage();
        usage.shadow_copies = Ok(vec![]);

        assert_eq!(
            status_of(&usage, PreflightCheck::ShadowCopy),
            PreflightStatus::Safe
        );
    }

    // The case that actually happens on a machine with the VSS service stopped:
    // the query fails while still printing an empty array. It must not read as
    // "no shadow copies".
    #[test]
    fn shadow_copy_query_failure_is_unknown_not_safe() {
        let mut usage = safe_usage();
        usage.shadow_copies = Err("simulated provider load failure".into());

        assert_eq!(
            status_of(&usage, PreflightCheck::ShadowCopy),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn executable_on_target_is_blocked() {
        let mut usage = safe_usage();
        usage.exe_path = Ok("E:\\tools\\e-waste.exe".to_string());

        assert_eq!(
            status_of(&usage, PreflightCheck::ExecutableLocation),
            PreflightStatus::Blocked
        );
    }

    #[test]
    fn executable_on_another_disk_is_safe() {
        assert_eq!(
            status_of(&safe_usage(), PreflightCheck::ExecutableLocation),
            PreflightStatus::Safe
        );
    }

    #[test]
    fn executable_path_unavailable_is_unknown() {
        let mut usage = safe_usage();
        usage.exe_path = Err("simulated failure".into());

        assert_eq!(
            status_of(&usage, PreflightCheck::ExecutableLocation),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn path_on_an_unknown_volume_is_unknown_not_safe() {
        let mut usage = safe_usage();
        usage.pagefiles = Ok(vec![PageFile {
            name: "Z:\\pagefile.sys".to_string(),
            source: "in-use".to_string(),
        }]);

        assert_eq!(
            status_of(&usage, PreflightCheck::Pagefile),
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn a_single_unknown_keeps_the_whole_report_off_safe() {
        let mut usage = safe_usage();
        usage.shadow_copies = Err("simulated failure".into());

        let partitions = preflight_partitions();
        let report = evaluate_preflight(TARGET, &partitions, &usage);

        assert_eq!(report.status(), PreflightStatus::Unknown);
    }

    #[test]
    fn blocked_dominates_unknown_and_safe() {
        let mut usage = safe_usage();
        usage.shadow_copies = Err("simulated failure".into());
        usage.exe_path = Ok("E:\\tools\\e-waste.exe".to_string());

        let partitions = preflight_partitions();
        let report = evaluate_preflight(TARGET, &partitions, &usage);

        assert_eq!(report.status(), PreflightStatus::Blocked);
        assert_eq!(
            finding_for(&report, PreflightCheck::ShadowCopy).status,
            PreflightStatus::Unknown
        );
        assert_eq!(
            finding_for(&report, PreflightCheck::ExecutableLocation).status,
            PreflightStatus::Blocked
        );
    }

    #[test]
    fn multiple_findings_combine_deterministically() {
        // Every check fails in a different way at once.
        let usage = SystemUsage {
            pagefiles: Ok(vec![PageFile {
                name: "E:\\pagefile.sys".to_string(),
                source: "in-use".to_string(),
            }]),
            hibernation: Ok(Hibernation {
                enabled: Some(1),
                system_drive: Some("E:".to_string()),
            }),
            crash_dump: Ok(CrashDump {
                enabled: Some(3),
                dump_file: Some("E:\\MEMORY.DMP".to_string()),
                minidump_dir: None,
                dedicated_dump_file: None,
            }),
            shadow_copies: Err("simulated failure".into()),
            exe_path: Ok("E:\\tools\\e-waste.exe".to_string()),
        };

        let partitions = preflight_partitions();
        let first = evaluate_preflight(TARGET, &partitions, &usage);
        let second = evaluate_preflight(TARGET, &partitions, &usage);

        assert_eq!(first.status(), PreflightStatus::Blocked);

        let summarize =
            |report: &PreflightReport| -> Vec<(PreflightCheck, PreflightStatus, String)> {
                report
                    .findings
                    .iter()
                    .map(|f| (f.check, f.status, f.detail.clone()))
                    .collect()
            };
        assert_eq!(summarize(&first), summarize(&second));

        assert_eq!(
            first
                .findings
                .iter()
                .filter(|f| f.status == PreflightStatus::Blocked)
                .count(),
            4
        );
        assert_eq!(
            finding_for(&first, PreflightCheck::ShadowCopy).status,
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn status_ordering_is_safe_then_unknown_then_blocked() {
        assert!(PreflightStatus::Safe < PreflightStatus::Unknown);
        assert!(PreflightStatus::Unknown < PreflightStatus::Blocked);
    }

    #[test]
    fn empty_report_is_unknown_not_safe() {
        let report = PreflightReport {
            findings: Vec::new(),
        };

        assert_eq!(report.status(), PreflightStatus::Unknown);
    }

    #[test]
    fn physical_disk_deserializes_when_is_removable_is_null() {
        // Real-world Get-Disk output on this machine: IsRemovable came back
        // null for at least one disk, despite IsBoot/IsSystem never doing so.
        let json = r#"{
            "Number": 1,
            "FriendlyName": "USB2.0 CARD-READER",
            "SerialNumber": "8120120400400000",
            "HealthStatus": "Healthy",
            "OperationalStatus": "Online",
            "IsBoot": false,
            "IsSystem": false,
            "SizeGB": 2045.49,
            "Size": 2196328163574,
            "BusType": "USB",
            "MediaType": "Unspecified",
            "IsRemovable": null
        }"#;

        let disk: PhysicalDisk = serde_json::from_str(json).unwrap();

        assert_eq!(disk.is_removable, None);
    }

    #[test]
    fn media_detection_safe_when_bus_and_media_type_recognized() {
        let mut disk = make_disk(false, false);
        disk.bus_type = Some("USB".to_string());
        disk.media_type = Some("SSD".to_string());
        disk.is_removable = Some(true);

        let finding = evaluate_media_detection(&disk);

        assert_eq!(finding.status, PreflightStatus::Safe);
    }

    #[test]
    fn media_detection_unknown_when_bus_type_absent() {
        let mut disk = make_disk(false, false);
        disk.bus_type = None;

        assert_eq!(
            evaluate_media_detection(&disk).status,
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn media_detection_unknown_when_media_type_is_windows_sentinel() {
        let mut disk = make_disk(false, false);
        disk.media_type = Some("Unspecified".to_string());

        assert_eq!(
            evaluate_media_detection(&disk).status,
            PreflightStatus::Unknown
        );
    }

    #[test]
    fn media_detection_participates_in_report_status_combination() {
        let mut disk = make_disk(false, false);
        disk.bus_type = None;

        // Every other check is Safe; only media detection is Unknown, so the
        // combined report must still surface Unknown rather than the Safe
        // that max() would give if this finding were dropped.
        let mut report = evaluate_preflight(TARGET, &preflight_partitions(), &safe_usage());
        report.findings.push(evaluate_media_detection(&disk));

        assert_eq!(report.status(), PreflightStatus::Unknown);
    }

    #[test]
    fn physical_disk_deserializes_raw_size_into_size_bytes() {
        let json = r#"{
            "Number": 0,
            "FriendlyName": "Test Disk",
            "SerialNumber": null,
            "HealthStatus": "Healthy",
            "OperationalStatus": "Online",
            "IsBoot": false,
            "IsSystem": false,
            "SizeGB": 0.5,
            "Size": 536870912,
            "BusType": "SATA",
            "MediaType": "SSD",
            "IsRemovable": false
        }"#;

        let disk: PhysicalDisk = serde_json::from_str(json).unwrap();

        assert_eq!(disk.size_bytes, 536_870_912);
    }

    #[test]
    fn plan_for_disk_is_planned_for_an_eligible_disk() {
        let disk = make_disk(false, false);

        let plan = plan_for_disk(&disk);

        assert_eq!(
            plan,
            DiskPlan::Planned {
                total_bytes: disk.size_bytes,
                pattern: PLANNED_PATTERN,
                chunk_size: PLANNED_CHUNK_SIZE,
            }
        );
    }

    #[test]
    fn plan_for_disk_skips_a_blocked_system_disk() {
        let disk = make_disk(true, false);

        assert!(matches!(plan_for_disk(&disk), DiskPlan::Skipped(_)));
    }

    #[test]
    fn plan_for_disk_is_pending_for_a_capacity_untrusted_bus_type() {
        // Eligible (not system/boot), but the bus type is not on the
        // capacity-trusted list -- confirmed necessary on real hardware
        // (A.1): a USB-SD bridge reported ~2045GB for a physically 32GB
        // card. Must not be silently promoted to a trusted, byte-count
        // -bearing Planned.
        let mut disk = make_disk(false, false);
        disk.bus_type = Some("USB".to_string());

        let plan = plan_for_disk(&disk);

        assert!(matches!(plan, DiskPlan::PendingCapacityConfirmation(_)));
    }

    #[test]
    fn plan_for_disk_is_pending_for_an_absent_bus_type() {
        // Fail closed: no bus type reported at all must not default to
        // trusted just because it also isn't a known-bad one.
        let mut disk = make_disk(false, false);
        disk.bus_type = None;

        let plan = plan_for_disk(&disk);

        assert!(matches!(plan, DiskPlan::PendingCapacityConfirmation(_)));
    }

    #[test]
    fn plan_for_disk_is_planned_even_when_media_type_is_unrecognized_for_a_trusted_bus() {
        // This is the case the old MediaType-based gate got wrong: a
        // perfectly trustworthy internal disk (bus type SATA/NVMe/etc.) can
        // still have a blank MediaType (observed on this machine's own NVMe
        // SSD). Capacity trust must key on bus type only, not media type.
        let mut disk = make_disk(false, false);
        disk.bus_type = Some("NVMe".to_string());
        disk.media_type = None;

        let plan = plan_for_disk(&disk);

        assert_eq!(
            plan,
            DiskPlan::Planned {
                total_bytes: disk.size_bytes,
                pattern: PLANNED_PATTERN,
                chunk_size: PLANNED_CHUNK_SIZE,
            }
        );
    }

    #[test]
    fn resolve_matches_drive_letter_root() {
        let partitions = preflight_partitions();

        assert_eq!(
            resolve_path_to_disks("E:\\pagefile.sys", &partitions),
            vec![TARGET]
        );
    }

    #[test]
    fn resolve_matches_volume_guid_root() {
        let partitions = preflight_partitions();

        assert_eq!(
            resolve_path_to_disks(TARGET_GUID, &partitions),
            vec![TARGET]
        );
    }

    #[test]
    fn resolve_is_case_and_separator_insensitive() {
        let partitions = preflight_partitions();

        assert_eq!(
            resolve_path_to_disks("e:/WINDOWS/MEMORY.DMP", &partitions),
            vec![TARGET]
        );
    }

    #[test]
    fn resolve_matches_a_bare_drive_specifier() {
        let partitions = preflight_partitions();

        assert_eq!(resolve_path_to_disks("E:", &partitions), vec![TARGET]);
    }

    // The reason AccessPaths is the correlation key rather than the drive letter:
    // a volume mounted at a folder on C: can live on a different physical disk,
    // and the longest match has to win.
    #[test]
    fn resolve_prefers_the_longest_access_path() {
        let partitions = vec![
            make_partition_on(0, &["C:\\"]),
            make_partition_on(TARGET, &["C:\\mnt\\data\\"]),
        ];

        assert_eq!(
            resolve_path_to_disks("C:\\mnt\\data\\pagefile.sys", &partitions),
            vec![TARGET]
        );
        assert_eq!(
            resolve_path_to_disks("C:\\pagefile.sys", &partitions),
            vec![0]
        );
    }

    #[test]
    fn resolve_returns_none_for_an_unclaimed_path() {
        let partitions = preflight_partitions();

        assert_eq!(
            resolve_path_to_disks("Z:\\pagefile.sys", &partitions),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn resolve_ignores_partitions_without_access_paths() {
        let partitions = vec![Partition {
            disk_number: 0,
            drive_letter: None,
            partition_type: "Reserved".to_string(),
            access_paths: None,
        }];

        assert_eq!(
            resolve_path_to_disks("C:\\pagefile.sys", &partitions),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn resolve_ignores_an_empty_access_path() {
        let partitions = vec![make_partition_on(0, &["", "   "])];

        assert_eq!(
            resolve_path_to_disks("C:\\pagefile.sys", &partitions),
            Vec::<u32>::new()
        );
    }

    #[test]
    fn resolve_does_not_match_a_sibling_directory_by_prefix() {
        let partitions = vec![
            make_partition_on(0, &["C:\\"]),
            make_partition_on(TARGET, &["C:\\mnt\\data\\"]),
        ];

        // "C:\mnt\database" starts with "C:\mnt\data" as raw text but is not
        // inside that mount point.
        assert_eq!(
            resolve_path_to_disks("C:\\mnt\\database\\pagefile.sys", &partitions),
            vec![0]
        );
    }

    // One volume living on two physical disks, as a dynamic mirrored or striped
    // volume does: the same access path appears on a partition of each disk.
    fn mirrored_partitions() -> Vec<Partition> {
        vec![
            make_partition_on(0, &["E:\\", TARGET_GUID]),
            make_partition_on(1, &["E:\\", TARGET_GUID]),
        ]
    }

    #[test]
    fn resolve_returns_every_disk_of_a_mirrored_volume() {
        assert_eq!(
            resolve_path_to_disks("E:\\pagefile.sys", &mirrored_partitions()),
            vec![0, 1]
        );
    }

    // Both disks genuinely hold the pagefile volume, so naming only the first would
    // let the second report as unused.
    #[test]
    fn mirrored_volume_blocks_every_disk_it_occupies() {
        let mut usage = safe_usage();
        usage.pagefiles = Ok(vec![PageFile {
            name: "E:\\pagefile.sys".to_string(),
            source: "in-use".to_string(),
        }]);
        let partitions = mirrored_partitions();

        for disk_number in [0, 1] {
            let report = evaluate_preflight(disk_number, &partitions, &usage);
            assert_eq!(
                finding_for(&report, PreflightCheck::Pagefile).status,
                PreflightStatus::Blocked,
                "disk {} hosts the mirrored pagefile volume and must block",
                disk_number
            );
        }
    }

    #[test]
    fn a_tie_does_not_mask_a_longer_nested_mount_point() {
        let partitions = vec![
            make_partition_on(0, &["C:\\"]),
            make_partition_on(1, &["C:\\"]),
            make_partition_on(2, &["C:\\mnt\\data\\"]),
        ];

        assert_eq!(
            resolve_path_to_disks("C:\\mnt\\data\\pagefile.sys", &partitions),
            vec![2]
        );
        assert_eq!(
            resolve_path_to_disks("C:\\pagefile.sys", &partitions),
            vec![0, 1]
        );
    }

    // DumpFile points somewhere harmless while DedicatedDumpFile, which overrides
    // it, points at the target.
    #[test]
    fn dedicated_dump_file_on_target_is_blocked() {
        let mut usage = safe_usage();
        usage.crash_dump = Ok(CrashDump {
            enabled: Some(3),
            dump_file: Some("C:\\WINDOWS\\MEMORY.DMP".to_string()),
            minidump_dir: Some("C:\\WINDOWS\\Minidump".to_string()),
            dedicated_dump_file: Some("E:\\dedicated.sys".to_string()),
        });

        assert_eq!(
            status_of(&usage, PreflightCheck::CrashDump),
            PreflightStatus::Blocked
        );
    }

    // --- decode_powershell_stdout / exe_path_to_string -----------------------

    #[test]
    fn decode_powershell_stdout_rejects_non_utf8() {
        // A U+FFFD substitution here would become a mangled path that
        // resolve_path_to_disks attributes to the wrong disk; reject instead.
        assert!(decode_powershell_stdout(b"C:\\\xff\xfe").is_err());
    }

    #[test]
    fn decode_powershell_stdout_trims_valid_output() {
        assert_eq!(
            decode_powershell_stdout(b"  []  \r\n").unwrap(),
            "[]".to_string()
        );
    }

    #[test]
    fn exe_path_to_string_accepts_utf8_path() {
        let path = std::path::Path::new("C:\\tools\\e-waste.exe");
        assert_eq!(
            exe_path_to_string(path).unwrap(),
            "C:\\tools\\e-waste.exe".to_string()
        );
    }

    #[test]
    #[cfg(windows)]
    fn exe_path_to_string_rejects_non_utf8_path() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        // 'A', an unpaired high surrogate, 'B': a valid Windows path with no
        // UTF-8 form. to_string_lossy would flatten it to "A\u{FFFD}B".
        let os = OsString::from_wide(&[0x0041, 0xD800, 0x0042]);
        let path = std::path::PathBuf::from(os);

        assert!(exe_path_to_string(&path).is_err());
    }
}
