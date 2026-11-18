# mpcheck

Fast Windows Defender signature locator for Linux — a gocheck-style tool that
tells you **which bytes** of a file trip a Defender signature, without Windows.

It drives Defender's real engine (`mpengine.dll`) through
[taviso/loadlibrary](https://github.com/taviso/loadlibrary). A small C daemon
(`mpscand`) boots the engine once and scans in-memory buffers in a few
milliseconds each; `mpcheck` (this Rust tool) bisects a flagged file down to the
region that triggers a given signature.

## Build

You need a [taviso/loadlibrary](https://github.com/taviso/loadlibrary) checkout
with the 32-bit toolchain set up (`gcc-multilib`, `libc6-dev-i386`) and the
engine present in `engine/` — `mpengine.dll` plus the four `*.vdm` files. Those
are Microsoft's and are **not** included here (see *Legal*). Current engines
need the fixes from loadlibrary PR
[#123](https://github.com/taviso/loadlibrary/pull/123), merged upstream.

1. Build the `mpscand` daemon inside that checkout:

   ```
   ./mpscand/build.sh /path/to/loadlibrary
   ```

2. Build mpcheck:

   ```
   cargo build --release
   ```

Point mpcheck at the loadlibrary dir with `--engine <dir>` or the
`MPCHECK_ENGINE` env var; by default it looks for `./loadlibrary` or
`../loadlibrary`.

## Use

```
mpcheck scan   <file> [files...]   # just: detected? which signature?
mpcheck locate <file>              # bisect to the triggering bytes
```

`scan` exits non-zero if any file is flagged (like clamscan/grep).

### Example: EICAR

```
$ mpcheck locate eicar.com
threat : Virus:DOS/EICAR_Test_File
signature region: offset 0x0 .. 0x44  (68 bytes, 100% of file)
verify : zeroing this region clears the detection - confirmed trigger.
class  : whole-file match. ...exact-match test string (like EICAR)...
```

### Example: a UPX-packed ELF

```
$ mpcheck locate ./client
threat : ALF:ELFUPX!rfn
signature region: offset 0x0 .. 0x34ed5  (216789 bytes, 100% of file)
class  : broad / structural match (100% of the file). Likely a format
         or packer heuristic rather than a tight content signature.
```

This is the honest answer when there is **no short signature**: the `!rfn`
suffix is an ML/heuristic name and the detection is for *being UPX-packed*, not
for any specific byte pattern. `upx -d` the file and it scans clean.

## How it works / caveats

- **Signature-name-aware bisection.** Truncating a file raises unrelated
  heuristics (e.g. `TEL:Linux/TruncatedSegments` on a chopped ELF). mpcheck
  bisects on the *specific* signature from the full-file scan, not "any
  detection", so it stays locked on the real target.
- **The engine caches verdicts per boot** (an identical buffer scans "clean" the
  second time). mpcheck memoizes and never sends the same bytes twice.
- **Offline only.** This is local signature/heuristic matching — no cloud,
  no behavioural/AMSI detonation. Results reflect the VDM definitions you
  downloaded; refresh them by re-extracting a current `mpam-fe.exe`.
- Bisection assumes detection is monotonic in the kept bytes, which holds for
  content/offset signatures. For structural detections it reports the whole-file
  / broad class instead of a false "tight signature".

## Legal

mpcheck is for analysing your own files and debugging false positives. It does
**not** contain or redistribute any Microsoft code. `mpengine.dll` and the virus
definition (`*.vdm`) files are proprietary to Microsoft and are not included —
download them yourself from the official distribution (the `mpam-fe.exe`
update package) and extract them into the loadlibrary `engine/` directory. The
Defender engine is run entirely offline here: there is no cloud lookup and no
behavioural/AMSI detonation, so results reflect only the local signature
definitions you supply. Respect Microsoft's licence terms for the engine and
definitions.

## Credits

Built on Tavis Ormandy's [loadlibrary](https://github.com/taviso/loadlibrary)
(GPLv2+). Inspired by [gocheck](https://github.com/gatariee/gocheck) (no gocheck
code is used here). The engine-boot and scan-path fixes needed for current
(2024+ signed) engines are in loadlibrary PR
[#123](https://github.com/taviso/loadlibrary/pull/123).

## Licence

This repository is mixed-licence, because the daemon is derived from
loadlibrary:

- **`mpscand/`** (the `mpscand.c` daemon and its build script) is a derivative
  work of loadlibrary's `mpclient.c` and is therefore licensed under the **GNU
  GPL v2 or later** — see [`mpscand/LICENSE`](mpscand/LICENSE). Original
  copyright © 2017 Tavis Ormandy; modifications © 2026 scintilla083.
- **Everything else** (the `mpcheck` Rust crate under `src/`, build config,
  docs) is **MIT** — see [LICENSE](LICENSE). `mpcheck` does not contain or link
  loadlibrary code; it runs `mpscand` as a separate process and talks to it over
  a pipe, so it is a separate work.

`mpengine.dll` and the `*.vdm` definitions are Microsoft's proprietary files and
are **not** part of this repository (see *Legal* above).
