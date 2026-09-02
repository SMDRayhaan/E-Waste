use serde::Deserialize;
use std::process::{Command, Output};

const POWERSHELL_PATH: &str = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

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

    for partition in disk_partitions {
        let Some(letter) = partition.drive_letter else {
            continue;
        };

        let volumes = match bitlocker {
            Ok(volumes) => volumes,
            Err(e) => {
                return Eligibility::Unknown(format!("BitLocker information unavailable: {}", e));
            }
        };

        let mount_point = format!("{}:", letter);
        let Some(volume) = volumes.iter().find(|v| v.mount_point == mount_point) else {
            continue;
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

fn execute_powershell(command: &str) -> Result<Output, Box<dyn std::error::Error>> {
    Command::new(POWERSHELL_PATH)
        .args(["-NoProfile", "-Command", command])
        .output()
        .map_err(|e| e.into())
}

fn get_physical_disks() -> Result<Vec<PhysicalDisk>, Box<dyn std::error::Error>> {
    let output = execute_powershell(
        "$disks = @(Get-Disk | Select-Object Number,FriendlyName,SerialNumber,HealthStatus,\
OperationalStatus,IsBoot,IsSystem,@{N='SizeGB';E={[math]::Round($_.Size / 1GB, 2)}}); \
ConvertTo-Json -InputObject $disks",
    )?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
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
        "$partitions = @(Get-Partition | Select-Object DiskNumber,DriveLetter,Type); \
ConvertTo-Json -InputObject $partitions",
    )?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
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

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
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

fn main() {
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
    fn partition_with_no_matching_bitlocker_volume_does_not_block() {
        let disk = make_disk(false, false);
        let partition = make_partition(Some('C'));
        let partitions = vec![&partition];
        let bitlocker: Result<Vec<BitLockerVolume>, Box<dyn std::error::Error>> = Ok(vec![]);

        let result = evaluate_eligibility(&disk, &partitions, &bitlocker);

        assert!(matches!(result, Eligibility::Eligible));
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
}
