# mpscand

A persistent scanning daemon built on
[taviso/loadlibrary](https://github.com/taviso/loadlibrary). It boots Defender's
`mpengine.dll` once and then scans in-memory buffers fed on stdin, so a
front-end (`mpcheck`) can scan thousands of buffers in a few milliseconds each
instead of paying the engine boot cost every time.

It links against loadlibrary's `peloader`/`intercept`, so it is built **inside**
a loadlibrary checkout.

**Licence:** `mpscand.c` is derived from loadlibrary's `mpclient.c` and is
licensed under the **GNU GPL v2 or later** (see [LICENSE](LICENSE) in this
directory). This is separate from the MIT-licensed `mpcheck` Rust crate.

## Build

You need a working loadlibrary checkout with the 32-bit toolchain set up and the
engine present (`engine/mpengine.dll` + the four `*.vdm` files — these are
Microsoft's and are **not** shipped here; see the main README). Current engines
require the fixes from loadlibrary PR
[#123](https://github.com/taviso/loadlibrary/pull/123), which are merged
upstream.

```
./build.sh /path/to/loadlibrary
```

This copies `mpscand.c` into the checkout, builds loadlibrary's libraries if
needed, and produces `/path/to/loadlibrary/mpscand`.

## Protocol

Little-endian framing. The engine's own logging goes to stderr; stdout carries
only the protocol.

- On start: one `0x00` byte once the engine has booted.
- Request (stdin): `u32 length`, then `length` content bytes.
  `length == 0xFFFFFFFF` means quit.
- Response (stdout): `u8 detected` (0/1), `u8 namelen`, then `namelen` bytes of
  the signature name.
