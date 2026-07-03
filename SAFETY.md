# Safety

The default build permits small encapsulated unsafe leaf modules after profiling.
The `paranoid` feature applies `#![forbid(unsafe_code)]` inside each crate and
uses safe fallbacks.

The baseline implementation uses safe scalar kernels unless a hot path has a
documented unsafe leaf. Unsafe code must not call C, widen parser trust, or skip
format validation.

Current unsafe leaves:

- `ozlrip-decode::execute::fast_transpose`: writes validated 2/4/8-lane
  transpose outputs into pre-reserved `Vec<u8>` storage and sets the length
  after all bytes are initialized. The caller validates equal lane lengths,
  output size, allocation limits, and capacity before entry.

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
