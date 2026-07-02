# Safety

The workspace denies unsafe code. The `paranoid` feature also applies
`#![forbid(unsafe_code)]` inside each crate.

The baseline implementation uses safe scalar kernels. No wild-copy fast paths,
unchecked indexing, or C bindings are allowed in the decoder baseline.

Primary defenses:

- Bounded frame, chunk, stream, node, buffer, and graph-depth limits
- Checked arithmetic for every size and offset
- Parse into bounded intermediate types before allocation
- Validate the full graph before node execution
- Borrow stored streams from the input frame
- Allocate regenerated streams only after limit checks
- Return typed `Unsupported` errors for unknown codecs, custom decoders,
  dictionaries, and materialized bundles

Regression tests should cover OpenZL memory-safety history recorded in
`info/openzl/VULNS.md`.

