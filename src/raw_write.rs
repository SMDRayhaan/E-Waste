//! Chunked overwrite loop for M1-7 (HDD sanitization).
//!
//! SAFETY BOUNDARY: nothing in this module can touch a physical device. It is
//! generic over `std::io::Write` and never opens a file, a handle, or a device
//! path — the caller supplies the sink. No caller exists yet: `overwrite()` is
//! wired to nothing, and it must stay that way until M1-5's destructive
//! confirmation gate (explicit serial re-entry, Clear vs. Purge acknowledgment)
//! is built. This file is the write *loop*, not a write *path*.
//!
//! The loop is deliberately hand-rolled on `write()` rather than delegating to
//! `write_all()`. `write_all` collapses partial progress into a bare error, and
//! the byte offset a sanitization reached before failing is the single most
//! important fact to report: it is the boundary between "provably overwritten"
//! and "untouched". Losing it would make an interrupted wipe unauditable.

// Module-wide: every item here is deliberately unwired until M1-5's confirmation
// gate exists, so the outcome fields and accessor have no non-test reader yet.
// Same posture as select_target_disk / verify_target_before_operation in main.rs.
#![allow(dead_code)]

use std::io::{ErrorKind, Write};

/// Bytes completed so far against the total requested, reported at every chunk
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteProgress {
    pub bytes_written: u64,
    pub total_bytes: u64,
}

/// How an overwrite ended. Every variant carries `bytes_written`: a run that
/// stopped early is still evidence, and the caller must be able to record
/// exactly how far the overwrite got.
#[derive(Debug)]
pub enum WriteOutcome {
    Completed {
        bytes_written: u64,
    },
    Cancelled {
        bytes_written: u64,
    },
    Failed {
        bytes_written: u64,
        source: std::io::Error,
    },
}

impl WriteOutcome {
    /// The offset reached, whatever the ending. Only a `Completed` outcome
    /// means the whole requested range was covered.
    pub fn bytes_written(&self) -> u64 {
        match self {
            WriteOutcome::Completed { bytes_written }
            | WriteOutcome::Cancelled { bytes_written }
            | WriteOutcome::Failed { bytes_written, .. } => *bytes_written,
        }
    }
}

/// Write `pattern` over `total_bytes` of `sink`, in `chunk_size` chunks.
///
/// `cancel` is polled at chunk boundaries only — a chunk is never abandoned
/// half-written, so a `Cancelled` outcome always lands on a clean boundary.
/// `progress` is called after each chunk completes.
///
/// `ErrorKind::Interrupted` is retried rather than reported, matching the std
/// convention; it means the syscall was signal-interrupted, not that the write
/// failed. Any other error ends the run as `Failed`, carrying the offset.
pub fn overwrite<W: Write>(
    sink: &mut W,
    total_bytes: u64,
    pattern: u8,
    chunk_size: usize,
    cancel: &dyn Fn() -> bool,
    progress: &mut dyn FnMut(WriteProgress),
) -> WriteOutcome {
    if chunk_size == 0 {
        return WriteOutcome::Failed {
            bytes_written: 0,
            source: std::io::Error::new(ErrorKind::InvalidInput, "chunk_size must be non-zero"),
        };
    }

    let buffer = vec![pattern; chunk_size];
    let mut bytes_written: u64 = 0;

    while bytes_written < total_bytes {
        if cancel() {
            return WriteOutcome::Cancelled { bytes_written };
        }

        // Final chunk is short whenever total_bytes is not a multiple of
        // chunk_size; never write past the requested range.
        let remaining = total_bytes - bytes_written;
        let this_chunk = remaining.min(chunk_size as u64) as usize;
        let mut chunk_done = 0usize;

        // Inner loop absorbs short writes: `write()` may accept fewer bytes
        // than offered, which is not an error and must not be treated as one.
        while chunk_done < this_chunk {
            match sink.write(&buffer[chunk_done..this_chunk]) {
                Ok(0) => {
                    return WriteOutcome::Failed {
                        bytes_written: bytes_written + chunk_done as u64,
                        source: std::io::Error::new(
                            ErrorKind::WriteZero,
                            "sink accepted zero bytes; device may be full or detached",
                        ),
                    };
                }
                Ok(n) => chunk_done += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    return WriteOutcome::Failed {
                        bytes_written: bytes_written + chunk_done as u64,
                        source: e,
                    };
                }
            }
        }

        bytes_written += chunk_done as u64;
        progress(WriteProgress {
            bytes_written,
            total_bytes,
        });
    }

    WriteOutcome::Completed { bytes_written }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn never_cancel() -> impl Fn() -> bool {
        || false
    }

    fn ignore_progress() -> impl FnMut(WriteProgress) {
        |_| {}
    }

    /// Accepts at most `limit` bytes per call, so every chunk takes several
    /// `write()` calls. Models a device that reports short writes.
    struct ShortWriteSink {
        limit: usize,
        written: Vec<u8>,
    }

    impl Write for ShortWriteSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.limit);
            self.written.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Fails with `kind` once `fail_at` bytes have been accepted. When `kind`
    /// is `Interrupted` it fails only `interrupt_budget` times, then behaves
    /// normally — modelling a signal-interrupted syscall that should be retried.
    struct FaultSink {
        accepted: u64,
        fail_at: u64,
        kind: ErrorKind,
        interrupt_budget: u32,
    }

    impl Write for FaultSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.accepted >= self.fail_at {
                if self.kind == ErrorKind::Interrupted && self.interrupt_budget > 0 {
                    self.interrupt_budget -= 1;
                    return Err(std::io::Error::from(ErrorKind::Interrupted));
                }
                if self.kind != ErrorKind::Interrupted {
                    return Err(std::io::Error::from(self.kind));
                }
            }
            self.accepted += buf.len() as u64;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writes_exact_byte_count_and_pattern() {
        let mut sink: Vec<u8> = Vec::new();
        let outcome = overwrite(
            &mut sink,
            4096,
            0xAA,
            1024,
            &never_cancel(),
            &mut ignore_progress(),
        );

        assert!(matches!(
            outcome,
            WriteOutcome::Completed {
                bytes_written: 4096
            }
        ));
        assert_eq!(sink.len(), 4096);
        assert!(sink.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn final_chunk_is_a_remainder_when_total_is_not_a_multiple() {
        let mut sink: Vec<u8> = Vec::new();
        // 2500 = two 1024 chunks + a 452-byte remainder.
        let outcome = overwrite(
            &mut sink,
            2500,
            0xFF,
            1024,
            &never_cancel(),
            &mut ignore_progress(),
        );

        assert_eq!(outcome.bytes_written(), 2500);
        assert_eq!(sink.len(), 2500, "must not write past the requested range");
    }

    #[test]
    fn short_writes_are_absorbed_not_treated_as_failure() {
        let mut sink = ShortWriteSink {
            limit: 7,
            written: Vec::new(),
        };
        let outcome = overwrite(
            &mut sink,
            1000,
            0x5A,
            256,
            &never_cancel(),
            &mut ignore_progress(),
        );

        assert!(matches!(
            outcome,
            WriteOutcome::Completed {
                bytes_written: 1000
            }
        ));
        assert_eq!(sink.written.len(), 1000);
        assert!(sink.written.iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn failure_reports_the_offset_reached() {
        let mut sink = FaultSink {
            accepted: 0,
            fail_at: 512,
            kind: ErrorKind::PermissionDenied,
            interrupt_budget: 0,
        };
        let outcome = overwrite(
            &mut sink,
            4096,
            0x00,
            256,
            &never_cancel(),
            &mut ignore_progress(),
        );

        match outcome {
            WriteOutcome::Failed {
                bytes_written,
                source,
            } => {
                assert_eq!(bytes_written, 512, "failure offset must be exact");
                assert_eq!(source.kind(), ErrorKind::PermissionDenied);
            }
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn interrupted_is_retried_not_reported_as_failure() {
        let mut sink = FaultSink {
            accepted: 0,
            fail_at: 512,
            kind: ErrorKind::Interrupted,
            interrupt_budget: 3,
        };
        let outcome = overwrite(
            &mut sink,
            2048,
            0x11,
            256,
            &never_cancel(),
            &mut ignore_progress(),
        );

        assert!(
            matches!(
                outcome,
                WriteOutcome::Completed {
                    bytes_written: 2048
                }
            ),
            "a signal-interrupted syscall must be retried, not surfaced"
        );
    }

    #[test]
    fn zero_byte_sink_is_a_failure_with_the_offset() {
        struct ZeroSink;
        impl Write for ZeroSink {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Ok(0)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let outcome = overwrite(
            &mut ZeroSink,
            1024,
            0x00,
            256,
            &never_cancel(),
            &mut ignore_progress(),
        );

        match outcome {
            WriteOutcome::Failed {
                bytes_written,
                source,
            } => {
                assert_eq!(bytes_written, 0);
                assert_eq!(source.kind(), ErrorKind::WriteZero);
            }
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn cancellation_stops_on_a_chunk_boundary() {
        let mut sink: Vec<u8> = Vec::new();
        let seen = std::cell::Cell::new(0u32);
        // Runs two chunks, then cancels on the third boundary check.
        let cancel = || {
            let n = seen.get();
            seen.set(n + 1);
            n >= 2
        };

        let outcome = overwrite(&mut sink, 4096, 0x77, 256, &cancel, &mut ignore_progress());

        match outcome {
            WriteOutcome::Cancelled { bytes_written } => {
                assert_eq!(bytes_written, 512, "must stop on a clean chunk boundary");
                assert_eq!(sink.len(), 512);
            }
            other => panic!("expected Cancelled, got {:?}", other),
        }
    }

    #[test]
    fn progress_is_monotonic_and_ends_at_total() {
        let mut sink: Vec<u8> = Vec::new();
        let mut seen: Vec<u64> = Vec::new();
        let mut record = |p: WriteProgress| {
            assert_eq!(p.total_bytes, 1000);
            seen.push(p.bytes_written);
        };

        overwrite(&mut sink, 1000, 0x01, 256, &never_cancel(), &mut record);

        assert_eq!(seen, vec![256, 512, 768, 1000]);
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn zero_total_completes_without_writing() {
        let mut sink: Vec<u8> = Vec::new();
        let outcome = overwrite(
            &mut sink,
            0,
            0xAA,
            256,
            &never_cancel(),
            &mut ignore_progress(),
        );

        assert!(matches!(
            outcome,
            WriteOutcome::Completed { bytes_written: 0 }
        ));
        assert!(sink.is_empty());
    }

    #[test]
    fn zero_chunk_size_is_rejected() {
        let mut sink: Vec<u8> = Vec::new();
        let outcome = overwrite(
            &mut sink,
            1024,
            0xAA,
            0,
            &never_cancel(),
            &mut ignore_progress(),
        );

        assert!(matches!(outcome, WriteOutcome::Failed { .. }));
        assert!(sink.is_empty());
    }

    #[test]
    fn writes_through_a_real_file_sink() {
        // Exercises the loop against a real std::fs::File rather than a Vec, so
        // the chunking is proven against actual OS write semantics. A temp file,
        // never a device.
        use std::io::Read;

        let path = std::env::temp_dir().join("ewaste_raw_write_test.bin");
        {
            let mut file = std::fs::File::create(&path).expect("create temp file");
            let outcome = overwrite(
                &mut file,
                3000,
                0xC3,
                512,
                &never_cancel(),
                &mut ignore_progress(),
            );
            assert_eq!(outcome.bytes_written(), 3000);
            file.flush().expect("flush");
        }

        let mut contents = Vec::new();
        std::fs::File::open(&path)
            .expect("reopen temp file")
            .read_to_end(&mut contents)
            .expect("read back");
        let _ = std::fs::remove_file(&path);

        assert_eq!(contents.len(), 3000);
        assert!(contents.iter().all(|&b| b == 0xC3));
    }
}
