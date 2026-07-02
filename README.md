# ozlrip

Memory-safe Rust decoder for OpenZL.

## Current Capability

`ozlrip` can inspect and decode a narrow, decoder-first subset of OpenZL
standard-codec frames:

- Stored single-serial-output frames
- Validated single-output transform graphs
- Standard nodes for concat, splitN, flatpack, transpose/interleave-style byte
  layouts, byte-preserving serial/struct conversion, delta, zigzag, bitpack,
  bitunpack, range-pack, constant, zstd through `zrip`, and lz4 through
  `lz4rip`
- Frame metadata inspection without payload decode
- Checked limits for frame size, decoded size, chunks, streams, nodes, transform
  headers, stored streams, buffers, graph depth, and expansion ratio
- Optional decoded and encoded checksum validation
- Upstream `zli` interop tests for generated store, numeric, zstd/lz4-backed,
  SAO, and SDDL2 SAO fixtures when `OZLRIP_ZLI` is set

Unsupported OpenZL features return typed errors. This currently includes custom
transforms, dictionary bundle materialization, multi-output decode, string output
materialization, SDDL parsing, training, and encoding.

## API

```rust
let decoded = ozlrip::decode(frame)?;

let mut dst = Vec::new();
let written = ozlrip::decode_into(frame, &mut dst, ozlrip::Limits::default())?;

let info = ozlrip::inspect(frame)?;
```

For reusable allocation state, create `ozlrip::Decoder` and call
`Decoder::decode_into`.
