//! Cross-process volume lock for M1-7's raw physical-drive write.
//!
//! Verified on real hardware before this was written: neither removing a
//! drive letter (`Remove-PartitionAccessPath`) nor a short-lived
//! `FSCTL_LOCK_VOLUME` + `FSCTL_DISMOUNT_VOLUME` sequence survives past the
//! process that acquired it -- the volume was remounted within moments of
//! the locking process exiting, in both cases. A volume lock's protection
//! lasts only as long as the handle/process that holds it, so the locking
//! process must stay alive for the *entire* physical-drive write, not just
//! run once beforehand.
//!
//! This module spawns a long-lived PowerShell/.NET helper that performs the
//! actual `CreateFile`/`DeviceIoControl` calls via `Add-Type` C# P/Invoke,
//! holds the lock while Rust writes through a separate `\\.\PhysicalDriveN`
//! handle, and is released by an explicit signal (or by its stdin pipe
//! closing, if this process dies first). `unsafe_code = "forbid"` is never
//! touched: every Win32 call happens inside the helper's own .NET runtime,
//! in a different process -- this module only ever talks to it over a pipe.

use crate::POWERSHELL_PATH;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// How long to wait for the helper to report LOCKED, and separately, how
/// long to wait for it to confirm RELEASED after being signaled. Locking a
/// couple of volumes and exiting are both sub-second operations in
/// practice; ten seconds is generous headroom for a loaded machine, not a
/// tuned budget.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const RELEASE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum LockError {
    Spawn(String),
    HelperExited { stderr: String },
    HelperReportedError(String),
    Timeout,
    UnexpectedMessage(String),
    Io(String),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Spawn(e) => write!(f, "could not start volume-lock helper: {e}"),
            LockError::HelperExited { stderr } => write!(
                f,
                "volume-lock helper exited before confirming a lock{}",
                if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", stderr.trim())
                }
            ),
            LockError::HelperReportedError(msg) => write!(f, "volume-lock helper reported: {msg}"),
            LockError::Timeout => write!(f, "timed out waiting for the volume-lock helper"),
            LockError::UnexpectedMessage(line) => {
                write!(f, "volume-lock helper sent an unexpected message: {line:?}")
            }
            LockError::Io(e) => write!(f, "I/O error talking to the volume-lock helper: {e}"),
        }
    }
}

/// How cleanly the helper was released. Never conflated with the write's own
/// outcome -- a caller must combine both before deciding what to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockLifecycle {
    /// RELEASE was sent, the helper confirmed RELEASED, and it exited.
    CleanRelease,
    /// The helper was already gone before RELEASE was sent (e.g. detected
    /// dead mid-write via the liveness check) -- expected in that case, not
    /// a new failure by itself.
    HelperAlreadyGone,
    /// RELEASE was sent but the helper did not exit within the timeout; it
    /// was force-killed as a last resort.
    ReleaseTimedOut,
    /// The helper exited after RELEASE was sent, but never confirmed
    /// RELEASED first -- cleanup state is uncertain.
    ReleaseUnconfirmed,
}

pub struct LockHelper {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<std::io::Result<String>>,
}

impl LockHelper {
    /// Non-blocking liveness probe, safe to call at every chunk boundary of
    /// a write loop: `false` the instant the helper has exited or its
    /// status can no longer be determined.
    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

/// Spawns the helper and blocks (bounded by LOCK_TIMEOUT) until it confirms
/// every requested drive letter is locked and dismounted, or reports/implies
/// failure. `drive_letters` may be empty (a disk with no lettered
/// partitions) -- the helper still runs, locks nothing, and reports LOCKED
/// immediately, which keeps the caller's control flow uniform.
pub fn acquire(drive_letters: &[char]) -> Result<LockHelper, LockError> {
    let mut child = spawn(drive_letters).map_err(|e| LockError::Spawn(e.to_string()))?;

    let stdin = child.stdin.take();
    let stdout = child.stdout.take().expect("stdout was piped");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
        // Channel sender drops here when the helper's stdout closes (it
        // exited), which turns into RecvTimeoutError::Disconnected for
        // whichever recv_timeout call is waiting.
    });

    let mut helper = LockHelper {
        child,
        stdin,
        lines: rx,
    };

    // Every branch below returns -- an unexpected message is a protocol
    // violation and fails closed immediately rather than waiting for a
    // "real" one, so this is a single bounded wait, not a retry loop.
    match helper.lines.recv_timeout(LOCK_TIMEOUT) {
        Ok(Ok(line)) if line == "LOCKED" => Ok(helper),
        Ok(Ok(line)) if line.starts_with("ERROR: ") => Err(LockError::HelperReportedError(
            line["ERROR: ".len()..].to_string(),
        )),
        Ok(Ok(other)) => Err(LockError::UnexpectedMessage(other)),
        Ok(Err(e)) => Err(LockError::Io(e.to_string())),
        Err(RecvTimeoutError::Timeout) => {
            let _ = helper.child.kill();
            Err(LockError::Timeout)
        }
        Err(RecvTimeoutError::Disconnected) => {
            let stderr = drain_stderr(&mut helper.child);
            let _ = helper.child.wait();
            Err(LockError::HelperExited { stderr })
        }
    }
}

/// Signals the helper to release and waits (bounded by RELEASE_TIMEOUT) for
/// it to confirm and exit. Always safe to call, including after the helper
/// is already known to be dead -- consumes `helper` so it can never be used
/// again afterward (a released lock has nothing left to hold).
pub fn release(mut helper: LockHelper) -> LockLifecycle {
    let signal_sent = helper
        .stdin
        .as_mut()
        .map(|stdin| writeln!(stdin, "RELEASE").and_then(|_| stdin.flush()))
        .transpose()
        .is_ok();
    // Drop stdin now regardless of outcome: an already-broken pipe should
    // not be retried, and a closed stdin is also how the helper notices
    // this process going away, which is the same signal as RELEASE.
    helper.stdin = None;

    if !signal_sent {
        let exited = wait_for_exit(&mut helper.child, RELEASE_TIMEOUT);
        return if exited {
            LockLifecycle::HelperAlreadyGone
        } else {
            LockLifecycle::ReleaseTimedOut
        };
    }

    let deadline = Instant::now() + RELEASE_TIMEOUT;
    let mut saw_released = false;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match helper.lines.recv_timeout(remaining) {
            Ok(Ok(line)) if line == "RELEASED" => {
                saw_released = true;
                break;
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => break,
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    let exited = wait_for_exit(&mut helper.child, remaining);

    match (saw_released, exited) {
        (true, true) => LockLifecycle::CleanRelease,
        (_, false) => LockLifecycle::ReleaseTimedOut,
        (false, true) => LockLifecycle::ReleaseUnconfirmed,
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return false,
        }
    }
}

fn drain_stderr(child: &mut Child) -> String {
    use std::io::Read;
    let mut buf = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut buf);
    }
    buf
}

fn spawn(drive_letters: &[char]) -> std::io::Result<Child> {
    let command = build_helper_script(drive_letters);
    Command::new(POWERSHELL_PATH)
        .args(["-NoProfile", "-Command", &command])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

/// Every drive letter must already be a plain ASCII letter (sourced from
/// Get-Partition's own DriveLetter field, never free-form text), so direct
/// interpolation into the PowerShell array literal is safe -- same posture
/// already used for disk numbers elsewhere in this crate.
fn build_helper_script(drive_letters: &[char]) -> String {
    let letters_literal = drive_letters
        .iter()
        .map(|c| format!("'{c}'"))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        r#"[Console]::OutputEncoding=[Text.Encoding]::UTF8; $OutputEncoding=[Text.Encoding]::UTF8;
$ErrorActionPreference = 'Stop'
try {{
    Add-Type -Namespace EWaste -Name VolumeLock -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(
    string lpFileName, uint dwDesiredAccess, uint dwShareMode,
    IntPtr lpSecurityAttributes, uint dwCreationDisposition,
    uint dwFlagsAndAttributes, IntPtr hTemplateFile);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool DeviceIoControl(
    Microsoft.Win32.SafeHandles.SafeFileHandle hDevice, uint dwIoControlCode,
    IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize,
    out uint lpBytesReturned, IntPtr lpOverlapped);
'@

    $FSCTL_LOCK_VOLUME = [Convert]::ToUInt32("00090018", 16)
    $FSCTL_DISMOUNT_VOLUME = [Convert]::ToUInt32("00090020", 16)
    $GENERIC_READ = [Convert]::ToUInt32("80000000", 16)
    $GENERIC_WRITE = [Convert]::ToUInt32("40000000", 16)
    $FILE_SHARE_READ = [uint32]1
    $FILE_SHARE_WRITE = [uint32]2
    $OPEN_EXISTING = [uint32]3

    $letters = @({letters_literal})
    $handles = New-Object System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]

    foreach ($letter in $letters) {{
        $path = "\\.\${{letter}}:"
        $h = [EWaste.VolumeLock]::CreateFile($path, $GENERIC_READ -bor $GENERIC_WRITE, $FILE_SHARE_READ -bor $FILE_SHARE_WRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
        if ($h.IsInvalid) {{
            throw "open failed for ${{letter}}: Win32 error $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }}
        $bytesReturned = 0
        $lockOk = [EWaste.VolumeLock]::DeviceIoControl($h, $FSCTL_LOCK_VOLUME, [IntPtr]::Zero, 0, [IntPtr]::Zero, 0, [ref]$bytesReturned, [IntPtr]::Zero)
        if (-not $lockOk) {{
            $h.Dispose()
            throw "lock failed for ${{letter}}: Win32 error $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }}
        $dismountOk = [EWaste.VolumeLock]::DeviceIoControl($h, $FSCTL_DISMOUNT_VOLUME, [IntPtr]::Zero, 0, [IntPtr]::Zero, 0, [ref]$bytesReturned, [IntPtr]::Zero)
        if (-not $dismountOk) {{
            $h.Dispose()
            throw "dismount failed for ${{letter}}: Win32 error $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }}
        $handles.Add($h)
    }}

    Write-Output "LOCKED"
    [Console]::Out.Flush()

    $null = [Console]::In.ReadLine()

    foreach ($h in $handles) {{
        if ($h -and -not $h.IsClosed) {{ $h.Dispose() }}
    }}
    Write-Output "RELEASED"
    [Console]::Out.Flush()
    exit 0
}} catch {{
    Write-Output "ERROR: $($_.Exception.Message)"
    [Console]::Out.Flush()
    if ($handles) {{
        foreach ($h in $handles) {{
            if ($h -and -not $h.IsClosed) {{ $h.Dispose() }}
        }}
    }}
    exit 1
}}
"#,
        letters_literal = letters_literal
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_helper_script_embeds_each_drive_letter() {
        let script = build_helper_script(&['E', 'F']);
        assert!(script.contains("@('E','F')"));
    }

    #[test]
    fn build_helper_script_handles_no_letters() {
        let script = build_helper_script(&[]);
        assert!(script.contains("@()"));
    }

    #[test]
    fn lock_error_display_includes_stderr_when_present() {
        let e = LockError::HelperExited {
            stderr: "boom".to_string(),
        };
        assert!(format!("{e}").contains("boom"));
    }

    #[test]
    fn lock_error_display_omits_empty_stderr() {
        let e = LockError::HelperExited {
            stderr: "".to_string(),
        };
        assert!(!format!("{e}").contains(':'));
    }
}
