//! mpcheck - fast Defender signature locator for Linux.
//!
//! Drives the `mpscand` daemon (loadlibrary + Defender mpengine) which boots
//! the engine once and scans in-memory buffers in a few milliseconds each.
//! That makes it practical to bisect a flagged file down to the concrete bytes
//! that trip a signature, the way gocheck does on Windows.
//!
//! Usage:
//!   mpcheck scan   <file> [more files...]   # just detect + signature name
//!   mpcheck locate <file>                   # bisect to the triggering bytes
//!
//! The daemon needs to run from the loadlibrary directory (it loads
//! engine/mpengine.dll by relative path). Point mpcheck at it with --engine
//! <dir> or the MPCHECK_ENGINE env var; otherwise it looks for a `loadlibrary`
//! or `../loadlibrary` directory next to where it is run.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

/// A live connection to one booted engine.
///
/// The engine caches verdicts by content within a boot, so rescanning an
/// identical buffer returns "clean" the second time. We memoize on our side
/// and never send the same bytes twice, which also keeps the bisection fast.
struct Scanner {
    child: Child,
    scans: u64,
    engine_calls: u64,
    memo: HashMap<Vec<u8>, ScanResult>,
}

#[derive(Clone)]
struct ScanResult {
    detected: bool,
    name: String,
}

impl Scanner {
    fn start(engine_dir: &Path, verbose: bool) -> io::Result<Scanner> {
        let bin = engine_dir.join("mpscand");
        if !bin.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{} not found. Build it: make -C {} mpscand",
                    bin.display(),
                    engine_dir.display()
                ),
            ));
        }
        let mut child = Command::new(&bin)
            .current_dir(engine_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(if verbose { Stdio::inherit() } else { Stdio::null() })
            .spawn()?;

        // Wait for the readiness byte (boot can take a few seconds).
        let mut ready = [0u8; 1];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut ready)
            .map_err(|_| io::Error::other("engine failed to boot (run with --verbose)"))?;

        Ok(Scanner {
            child,
            scans: 0,
            engine_calls: 0,
            memo: HashMap::new(),
        })
    }

    fn scan(&mut self, data: &[u8]) -> ScanResult {
        self.scans += 1;
        if let Some(r) = self.memo.get(data) {
            return r.clone();
        }
        let r = self.scan_uncached(data);
        self.memo.insert(data.to_vec(), r.clone());
        r
    }

    /// Does `data` trip the specific signature `target` (not just any threat)?
    /// Truncating/altering a file can raise unrelated heuristics (e.g.
    /// TruncatedSegments on a chopped ELF); matching on the name keeps the
    /// bisection locked onto the signature we actually care about.
    fn hits(&mut self, data: &[u8], target: &str) -> bool {
        let r = self.scan(data);
        r.detected && r.name == target
    }

    fn scan_uncached(&mut self, data: &[u8]) -> ScanResult {
        self.engine_calls += 1;
        let len = u32::try_from(data.len()).expect("file too large (>4GiB)");
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin.write_all(&len.to_le_bytes()).unwrap();
        stdin.write_all(data).unwrap();
        stdin.flush().unwrap();

        let stdout = self.child.stdout.as_mut().unwrap();
        let mut hdr = [0u8; 2];
        stdout.read_exact(&mut hdr).expect("daemon died mid-scan");
        let mut name = vec![0u8; hdr[1] as usize];
        stdout.read_exact(&mut name).unwrap();
        ScanResult {
            detected: hdr[0] != 0,
            name: String::from_utf8_lossy(&name).into_owned(),
        }
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        if let Some(mut stdin) = self.child.stdin.take() {
            let _ = stdin.write_all(&0xFFFF_FFFFu32.to_le_bytes());
            let _ = stdin.flush();
        }
        let _ = self.child.wait();
    }
}

fn resolve_engine_dir(explicit: Option<String>) -> PathBuf {
    if let Some(d) = explicit {
        return PathBuf::from(d);
    }
    if let Ok(d) = std::env::var("MPCHECK_ENGINE") {
        return PathBuf::from(d);
    }
    for cand in ["loadlibrary", "../loadlibrary"] {
        let p = PathBuf::from(cand);
        if p.join("mpscand").exists() {
            return p;
        }
    }
    // Fall back to ../loadlibrary even if it isn't there yet, so the error
    // message points somewhere sensible.
    PathBuf::from("../loadlibrary")
}

fn hexdump(data: &[u8], base: usize) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let off = base + i * 16;
        let mut hex = String::new();
        let mut asc = String::new();
        for (j, &b) in chunk.iter().enumerate() {
            hex.push_str(&format!("{:02x} ", b));
            if j == 7 {
                hex.push(' ');
            }
            asc.push(if (0x20..0x7f).contains(&b) { b as char } else { '.' });
        }
        out.push_str(&format!("{off:08x}  {hex:<49} |{asc}|\n"));
    }
    out
}

/// Bisect the smallest prefix length L such that data[0..L] still trips
/// `target`. Assumes detection is monotonic in prefix length (true for
/// substring/offset signatures).
fn min_prefix(sc: &mut Scanner, data: &[u8], target: &str) -> usize {
    let (mut lo, mut hi) = (1usize, data.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        if sc.hits(&data[..mid], target) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    hi
}

/// Within data[..end], bisect the largest start S such that data[S..end] still
/// trips `target`.
fn max_start(sc: &mut Scanner, data: &[u8], end: usize, target: &str) -> usize {
    let (mut lo, mut hi) = (0usize, end.saturating_sub(1));
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if sc.hits(&data[mid..end], target) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

fn cmd_scan(engine: &Path, files: &[String], verbose: bool) -> io::Result<i32> {
    let mut sc = Scanner::start(engine, verbose)?;
    let mut any = false;
    for f in files {
        match std::fs::read(f) {
            Ok(data) => {
                let r = sc.scan(&data);
                if r.detected {
                    any = true;
                    println!("{:<8} {}  ({} bytes)", "THREAT", r.name, data.len());
                    println!("    {f}");
                } else {
                    println!("{:<8} {}  ({} bytes)", "clean", "-", data.len());
                    println!("    {f}");
                }
            }
            Err(e) => eprintln!("mpcheck: {f}: {e}"),
        }
    }
    Ok(if any { 1 } else { 0 })
}

fn cmd_locate(engine: &Path, file: &str, verbose: bool) -> io::Result<i32> {
    let data = std::fs::read(file)?;
    let n = data.len();
    println!("file   : {file}  ({n} bytes)");

    let t0 = Instant::now();
    let mut sc = Scanner::start(engine, verbose)?;

    let full = sc.scan(&data);
    if !full.detected {
        println!("result : clean - nothing to locate");
        return Ok(0);
    }
    let target = full.name.clone();
    println!("threat : {target}");

    let end = min_prefix(&mut sc, &data, &target);
    let start = max_start(&mut sc, &data, end, &target);
    let region = &data[start..end];
    let span = end - start;
    let frac = span as f64 / n as f64;

    // Cross-check: zero out the located region in the full file and confirm the
    // signature goes away. If it doesn't, more than one copy/signature matches.
    let mut neutralised = data.clone();
    for b in &mut neutralised[start..end] {
        *b = 0;
    }
    let after = sc.scan(&neutralised);
    let still_target = after.detected && after.name == target;

    println!();
    println!(
        "signature region: offset {start:#x} .. {end:#x}  ({span} bytes, {:.0}% of file)",
        frac * 100.0
    );
    if still_target {
        println!("note   : zeroing this region still trips {target} - the signature matches");
        println!("         in more than one place; this is only the first occurrence.");
    } else if after.detected {
        println!("verify : zeroing this region clears {target} (file now flags {} instead).", after.name);
    } else {
        println!("verify : zeroing this region clears the detection - confirmed trigger.");
    }

    // Heuristic/structural call-out.
    if start == 0 && end == n {
        println!(
            "class  : whole-file match. The signature needs every byte - either an\n\
             \x20        exact-match test string (like EICAR) or a structural / format\n\
             \x20        heuristic (e.g. a packer). There is no short sub-sequence to\n\
             \x20        point at; truncating from either end drops the detection."
        );
    } else if frac > 0.5 {
        println!(
            "class  : broad / structural match ({:.0}% of the file). Likely a format\n\
             \x20        or packer heuristic rather than a tight content signature.",
            frac * 100.0
        );
    } else {
        println!("class  : localized content signature.");
    }

    println!();
    let shown = region.len().min(256);
    println!("bytes at {start:#x} (showing {shown} of {span}):");
    print!("{}", hexdump(&region[..shown], start));
    if shown < span {
        println!("... ({} more bytes)", span - shown);
    }

    println!();
    println!(
        "done   : {} probes ({} engine scans) in {:.1}s",
        sc.scans,
        sc.engine_calls,
        t0.elapsed().as_secs_f64()
    );
    Ok(1)
}

fn usage() -> ! {
    eprintln!(
        "mpcheck - fast Defender signature locator\n\n\
         usage:\n  \
           mpcheck scan   <file> [files...]   detect + signature name\n  \
           mpcheck locate <file>              bisect to the triggering bytes\n\n\
         options:\n  \
           --engine <dir>   loadlibrary dir containing mpscand + engine/\n  \
           --verbose        show engine stderr\n"
    );
    std::process::exit(2);
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    let mut engine_arg = None;
    if let Some(i) = args.iter().position(|a| a == "--engine") {
        engine_arg = args.get(i + 1).cloned();
        args.drain(i..=i + 1);
    }
    let verbose = args.iter().any(|a| a == "--verbose");
    args.retain(|a| a != "--verbose");

    if args.is_empty() {
        usage();
    }
    let cmd = args.remove(0);
    let engine = resolve_engine_dir(engine_arg);

    if verbose {
        // Re-expose engine stderr by flipping the daemon's stderr to inherit.
        // Simplest: set an env the Scanner could read; kept minimal here.
        eprintln!("mpcheck: engine dir = {}", engine.display());
    }

    let r = match cmd.as_str() {
        "scan" if !args.is_empty() => cmd_scan(&engine, &args, verbose),
        "locate" if args.len() == 1 => cmd_locate(&engine, &args[0], verbose),
        _ => usage(),
    };

    match r {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("mpcheck: {e}");
            std::process::exit(2);
        }
    }
}
