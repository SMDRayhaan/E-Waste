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

enum Eligibility {
    Eligible,
    Blocked(String),
    Unknown(String),
}

fn evaluate_eligibility(
    disk: &PhysicalDisk,
    disk_partitions: &[&Partition],
    bitlocker: &Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>>,
) -> Eligibility {
    if is_system_disk(disk) {
        return Eligibility::Blocked("system/boot disk".to_string());
    }

    // Checked before the loop, not inside it: a failed Get-BitLockerVolume query
    // is relevant to every disk, so it must not be skipped just because this disk
    // has no lettered partition to trip the check.
    let volumes = match bitlocker {
        Ok(volumes) => volumes,
        Err(e) => {
            return Eligibility::Unknown(format!("BitLocker information unavailable: {}", e));
        }
    };

    for partition in disk_partitions {
        let Some(letter) = partition.drive_letter else {
            // Letterless. EFI/MSR/Recovery partitions are legitimately letterless
            // and carry no user data — skip them. Anything else letterless is a
            // data volume we cannot key to a BitLocker entry (correlation is by
            // drive letter only), so its protection state is unknown, not "safe".
            if !is_bare_system_partition(&partition.partition_type) {
                return Eligibility::Unknown(format!(
                    "disk {} has a letterless {} partition whose BitLocker state cannot be determined",
                    disk.number, partition.partition_type
                ));
            }
            continue;
        };

        // A drive letter that is not A-Z cannot name a real volume. Get-Partition
        // types DriveLetter as System.Char, so a partition with no letter
        // serializes as "\u0000" and deserializes to Some('\0') rather than None,
        // slipping past the guard above. Fail closed rather than build a key that
        // matches nothing.
        if !letter.is_ascii_alphabetic() {
            return Eligibility::Unknown(format!(
                "partition on disk {} reports an unusable drive letter {:?}",
                disk.number, letter
            ));
        }

        // Match case-insensitively and tolerate a trailing separator: Get-Partition
        // and Get-BitLockerVolume do not agree on the case or exact shape of a
        // mount point ("c:" vs "C:", "C:" vs "C:\\"). An exact == here turns a
        // BitLocker-protected volume into a silent Eligible when the strings differ.
        let mount_point = format!("{}:", letter);
        let Some(volume) = volumes.iter().find(|v| {
            v.mount_point
                .trim_end_matches('\\')
                .eq_ignore_ascii_case(&mount_point)
        }) else {
            // Get-BitLockerVolume lists every fixed volume, protected or not, so a
            // lettered partition with no entry at all is anomalous: report Unknown
            // instead of falling through to Eligible.
            return Eligibility::Unknown(format!(
                "no BitLocker entry for volume {} on disk {}: protection state unknown",
                mount_point, disk.number
            ));
        };

        match volume.protection_status.as_str() {
            "On" => {
                return Eligibility::Blocked(format!(
                    "volume {} is BitLocker-protected (ProtectionStatus: On)",
                    mount_point
                ));
            }
            "Off" => continue,
            other => {
                return Eligibility::Unknown(format!(
                    "volume {} has unrecognized ProtectionStatus '{}'",
                    mount_point, other
                ));
            }
        }
    }

    Eligibility::Eligible
}

// Not yet called from main(): this is the read-only selection primitive for a
// future target-selection step, exercised by the tests below until it's wired in.
#[allow(dead_code)]
fn select_target_disk<'a>(
    disks: &'a [PhysicalDisk],
    partitions: &[Partition],
    bitlocker: &Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>>,
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

    let disk_partitions: Vec<&Partition> = partitions
        .iter()
        .filter(|p| p.disk_number == disk_number)
        .collect();

    match evaluate_eligibility(disk, &disk_partitions, bitlocker) {
        Eligibility::Eligible => Ok(disk),
        Eligibility::Blocked(reason) => Err(format!("disk {} is blocked: {}", disk_number, reason)),
        Eligibility::Unknown(reason) => Err(format!(
            "disk {} eligibility is unknown: {}",
            disk_number, reason
        )),
    }
}

// Final check to run against freshly fetched inventory immediately before any
// future destructive operation. Unlike select_target_disk(), which works within a
// single snapshot where the disk number is a sufficient key, this spans two
// snapshots — so the serial is mandatory here: a different physical disk can
// occupy the same number after a topology change. For that same reason it never
// searches by serial to "follow" a renumbered disk; auto-recovering from a
// changed topology right before a destructive operation must fail closed.
#[allow(dead_code)]
fn verify_target_before_operation<'a>(
    original: &PhysicalDisk,
    fresh_disks: &'a [PhysicalDisk],
    fresh_partitions: &[Partition],
    fresh_bitlocker: &Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>>,
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

    // Redundant with evaluate_eligibility()'s first check, kept deliberately as
    // defence in depth on the most catastrophic failure case.
    if is_system_disk(fresh) {
        return Err(format!(
            "disk {} is now a system/boot disk",
            original.number
        ));
    }

    let disk_partitions: Vec<&Partition> = fresh_partitions
        .iter()
        .filter(|p| p.disk_number == fresh.number)
        .collect();

    match evaluate_eligibility(fresh, &disk_partitions, fresh_bitlocker) {
        Eligibility::Eligible => Ok(fresh),
        Eligibility::Blocked(reason) => Err(format!(
            "disk {} is blocked in the current inventory: {}",
            original.number, reason
        )),
        Eligibility::Unknown(reason) => Err(format!(
            "disk {} eligibility is unknown in the current inventory: {}",
            original.number, reason
        )),
    }
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
}

impl PreflightCheck {
    fn label(self) -> &'static str {
        match self {
            PreflightCheck::Pagefile => "Pagefile",
            PreflightCheck::Hibernation => "Hibernation",
            PreflightCheck::CrashDump => "Crash Dump",
            PreflightCheck::ShadowCopy => "Shadow Copies",
            PreflightCheck::ExecutableLocation => "Executable Location",
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
OperationalStatus,IsBoot,IsSystem,@{N='SizeGB';E={[math]::Round($_.Size / 1GB, 2)}}); \
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

fn main() {
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

    println!("=== Disk Eligibility ===");
    match (&disks_result, &partitions_result) {
        (Ok(disks), Ok(partitions)) => {
            if disks.is_empty() {
                println!("No physical disks found.");
            }

            for disk in disks {
                let disk_partitions: Vec<&Partition> = partitions
                    .iter()
                    .filter(|p| p.disk_number == disk.number)
                    .collect();

                let eligibility = evaluate_eligibility(disk, &disk_partitions, &bitlocker_result);

                print!("Disk {}: ", disk.number);
                match eligibility {
                    Eligibility::Eligible => println!("ELIGIBLE"),
                    Eligibility::Blocked(reason) => println!("BLOCKED: {}", reason),
                    Eligibility::Unknown(reason) => println!("UNKNOWN: {}", reason),
                }
            }
        }
        (Ok(disks), Err(e)) => {
            for disk in disks {
                println!(
                    "Disk {}: UNKNOWN: partition information unavailable: {}",
                    disk.number, e
                );
            }
        }
        (Err(e), _) => eprintln!("Error getting disk information: {}", e),
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

                let report = evaluate_preflight(disk.number, partitions, &usage);
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
        let partitions: Vec<&Partition> = vec![];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Blocked(_)));
    }

    #[test]
    fn active_bitlocker_protection_is_blocked() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let volume = make_volume("C:", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Blocked(_)));
    }

    #[test]
    fn missing_bitlocker_data_is_unknown() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> =
            Err("simulated failure".into());

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Unknown(_)));
    }

    #[test]
    fn unrecognized_protection_status_is_unknown() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let volume = make_volume("C:", "Unknown");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Unknown(_)));
    }

    #[test]
    fn non_system_disk_with_protection_off_is_eligible() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Eligible));
    }

    #[test]
    fn system_disk_via_is_system_flag_alone_is_blocked() {
        let disk = make_disk(false, true);
        let partitions: Vec<&Partition> = vec![];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Blocked(_)));
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

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Blocked(_)));
    }

    #[test]
    fn lettered_partition_with_no_bitlocker_entry_is_unknown() {
        // Get-BitLockerVolume lists every fixed volume, so a lettered partition
        // with no entry at all is anomalous: fail closed, do not fall through to
        // Eligible.
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Unknown(_)));
    }

    #[test]
    fn lowercase_drive_letter_still_matches_protected_volume() {
        // Get-Partition may emit "c" while Get-BitLockerVolume reports "C:". An
        // exact == would miss and silently mark the encrypted disk Eligible.
        let disk = make_disk(false, false);
        let partition = make_partition(Some('c'));
        let partitions = vec![&partition];
        let volume = make_volume("C:", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Blocked(_)));
    }

    #[test]
    fn trailing_separator_mount_point_still_matches_protected_volume() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let volume = make_volume("C:\\", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Blocked(_)));
    }

    #[test]
    fn nul_drive_letter_is_unknown() {
        // A partition with no assigned letter serializes from System.Char as
        // "\u0000" and deserializes to Some('\0'), passing the Option guard.
        let disk = make_disk(false, false);
        let partition = make_partition(Some('\0'));
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Unknown(_)));
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

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Eligible));
    }

    #[test]
    fn letterless_data_volume_is_unknown() {
        // A "Basic" partition with no drive letter is a data volume we cannot
        // correlate to a BitLocker entry: its protection state is unknown.
        let disk = make_disk(false, false);
        let partition = make_partition(None);
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Unknown(_)));
    }

    #[test]
    fn letterless_data_volume_among_system_partitions_is_unknown() {
        let disk = make_disk(false, false);
        let system = make_letterless_partition("System");
        let data = make_partition(None);
        let partitions = vec![&system, &data];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Unknown(_)));
    }

    #[test]
    fn unrecognized_letterless_partition_type_is_unknown() {
        // Anything not System/Reserved/Recovery is treated as a data volume.
        let disk = make_disk(false, false);
        let partition = make_letterless_partition("");
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Unknown(_)));
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

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Blocked(_)));
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

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Unknown(_)));
    }

    #[test]
    fn bitlocker_failure_with_empty_partition_list_is_unknown() {
        let disk = make_disk(false, false);
        let partitions: Vec<&Partition> = vec![];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> =
            Err("simulated failure".into());

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Unknown(_)));
    }

    #[test]
    fn select_nonexistent_disk_returns_err() {
        let disks = vec![make_disk(false, false)];
        let partitions: Vec<Partition> = vec![];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = select_target_disk(&disks, &partitions, &bitlocker, 99, None);

        assert!(result.is_err());
    }

    #[test]
    fn select_system_disk_returns_err() {
        let disks = vec![make_disk(true, false)];
        let partitions: Vec<Partition> = vec![];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = select_target_disk(&disks, &partitions, &bitlocker, 0, None);

        assert!(result.is_err());
    }

    #[test]
    fn select_disk_with_active_bitlocker_returns_err() {
        let disks = vec![make_disk(false, false)];
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = select_target_disk(&disks, &partitions, &bitlocker, 0, None);

        assert!(result.is_err());
    }

    #[test]
    fn select_disk_with_unavailable_bitlocker_returns_err() {
        let disks = vec![make_disk(false, false)];
        let partitions = vec![make_partition(Some('C'))];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> =
            Err("simulated failure".into());

        let result = select_target_disk(&disks, &partitions, &bitlocker, 0, None);

        assert!(result.is_err());
    }

    #[test]
    fn select_eligible_disk_without_serial_returns_ok() {
        let disks = vec![make_disk(false, false)];
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = select_target_disk(&disks, &partitions, &bitlocker, 0, None);

        assert!(result.is_ok());
    }

    #[test]
    fn select_eligible_disk_with_correct_serial_returns_ok() {
        let disks = vec![make_disk_with_serial(false, false, Some("ABC123"))];
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = select_target_disk(&disks, &partitions, &bitlocker, 0, Some("ABC123"));

        assert!(result.is_ok());
    }

    #[test]
    fn select_eligible_disk_with_incorrect_serial_returns_err() {
        let disks = vec![make_disk_with_serial(false, false, Some("ABC123"))];
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = select_target_disk(&disks, &partitions, &bitlocker, 0, Some("WRONG"));

        assert!(result.is_err());
    }

    #[test]
    fn select_disk_requiring_serial_but_unavailable_returns_err() {
        let disks = vec![make_disk_with_serial(false, false, None)];
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result = select_target_disk(&disks, &partitions, &bitlocker, 0, Some("ABC123"));

        assert!(result.is_err());
    }

    #[test]
    fn select_disk_with_duplicate_numbers_returns_err() {
        let disks = vec![make_disk(false, false), make_disk(false, false)];
        let partitions: Vec<Partition> = vec![];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = select_target_disk(&disks, &partitions, &bitlocker, 0, None);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_original_without_serial() {
        let original = make_disk_full(0, None, "Test Disk", 100.0, "Healthy", false, false);
        let fresh_disks = vec![make_target_disk()];
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

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
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_when_disk_is_gone() {
        let original = make_target_disk();
        let fresh_disks: Vec<PhysicalDisk> = vec![];
        let partitions: Vec<Partition> = vec![];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_duplicate_disk_numbers() {
        let original = make_target_disk();
        let fresh_disks = vec![make_target_disk(), make_target_disk()];
        let partitions: Vec<Partition> = vec![];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

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
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

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
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

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
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

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
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

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
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_when_volume_is_now_protected() {
        let original = make_target_disk();
        let fresh_disks = vec![make_target_disk()];
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "On");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

        assert!(result.is_err());
    }

    #[test]
    fn verify_refuses_when_bitlocker_is_unavailable() {
        let original = make_target_disk();
        let fresh_disks = vec![make_target_disk()];
        let partitions = vec![make_partition(Some('C'))];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> =
            Err("simulated failure".into());

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

        assert!(result.is_err());
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
        let partitions = vec![make_partition(Some('C'))];
        let volume = make_volume("C:", "Off");
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![volume]);

        let result =
            verify_target_before_operation(&original, &fresh_disks, &partitions, &bitlocker);

        let verified = result.expect("matching disk should verify");
        assert_eq!(verified.health_status, "Warning");
        assert!(std::ptr::eq(verified, &fresh_disks[0]));
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
