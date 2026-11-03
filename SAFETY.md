# Safety

## No unsafe

`ozlrip`, `ozlrip-core`, and `ozlrip-decode` are `#![forbid(unsafe_code)]`.
The zstd and lz4 nodes call `zrip-decode` and `lz4rip-decode`, which forbid
unsafe code too. SIMD dispatch for transpose lanes and the PivCo-Huffman
constant-leaf merge goes through `fearless_simd`, which keeps the
`#[target_feature]` calls inside that crate.

Hot loops avoid bounds checks by construction: fixed-size `[u8; N]` chunks
read with `from_le_bytes`, output slices sized once per node and zipped with
their inputs, and `extend_from_within` for LZ matches.

The `paranoid` feature has no effect today. If a later release adds `unsafe`
for speed, builds with `paranoid` leave it out.

`tools/openzl-shim`, the test and benchmark harness that calls OpenZL C, is
not published and uses `unsafe` for its FFI calls.

Primary defenses:

- Bounded frame, chunk, stream, node, buffer, and graph-depth limits
- Checked arithmetic for every size and offset
- Parse into bounded intermediate types before allocation
- Validate the full graph before node execution
- Borrow stored streams from the input frame
- Allocate regenerated streams only after limit checks
- Return typed `Unsupported` errors for unknown codecs, custom transforms,
  custom dictionary materializers, and non-zstd dictionary materializers

Upstream OpenZL has fixed decoder memory-safety bugs of the kinds these
defenses target, for example a Field-LZ over-copy
([facebook/openzl#544](https://github.com/facebook/openzl/pull/544)), LZ
length and offset overflows
([facebook/openzl#779](https://github.com/facebook/openzl/pull/779)), and a
stack buffer overflow in `decode4`
([facebook/openzl#632](https://github.com/facebook/openzl/pull/632)). No CVE
or GitHub security advisory for OpenZL was published as of 2026-07.
