# Changelog

## [Unreleased]

- Add `Limits::max_dictionaries` (1024 strict, 64 paranoid) and
  `Limits::max_dictionary_bytes` (64 MiB strict, 16 MiB paranoid). They bound
  all dictionary bundles a `Decoder` holds and are checked from a bundle's
  header, before its dictionaries are parsed. A bundle could declare 65,535
  dictionaries.
- zstd dictionaries build their decode context on first use instead of at
  load, so unused dictionaries hold no decode workspace.
- Verify checksums in frames before format v21. Their flags sit in the chunk
  header, and the compressed checksum covers the whole frame. They were
  skipped, so corrupted or truncated legacy frames could decode.
  `FrameInfo::has_decoded_checksum` and `has_encoded_checksum` now report
  them.
- Reject trailing bytes after a frame in every format version, as upstream
  does. Before, only v21 and later rejected them.
- `huffman_v2` tables with table log 12 return `Unsupported` instead of
  `Malformed`. The format allows log 12, but no upstream encoder since the
  first release writes more than 11, and `zrip` decodes at most 11.
- Deprecated ROLZ nodes reject a rep0 match code that carries an offset
  delta, as upstream does since `cfcdf49`. Upstream's out-of-bounds
  reproducer for that fix is now a regression test.
- A frame that ends right after its header is truncated. It was accepted as
  a frame with no chunks, including v21+ frames without the end-of-frame
  marker. Upstream always reads a chunk before v21 and the marker from v21.
- lz4 nodes reject a declared size above 255 times the block size before
  allocating. No LZ4 block can expand further.
- The `split_by_struct` to `splitn` fast path checks that all `splitn` inputs
  have the same element width, as the general `splitn` decoder does. It
  accepted frames the general path rejects.
- `concat` nodes check their size table against the graph's output count
  before reserving outputs. A large size table could reserve about 16 times
  its own size in stream headers before the mismatch was reported.
- Fix 2-, 4-, and 8-byte delta decoding on big-endian targets: the first
  element was written in native byte order.
- Update codec dependencies: `zrip-decode` 0.8.9 replaces `zrip`, so the zstd
  encoder is no longer built; `zrip-core` 0.11; `lz4rip-decode` 0.10.4
  replaces `lz4rip`; `fearless_simd` 1.0. A fresh resolve no longer builds two
  versions of `zrip-core` or `fearless_simd`.
- The `zstd` and `lz4` features need only `alloc`, so `no_std` builds decode
  zstd and lz4 nodes. `std` still enables runtime CPU feature detection in the
  codecs.
- `paranoid` also enables `paranoid` in `zrip-core`, `zrip-decode`, and
  `lz4rip-decode`.
- lz4 block errors include the codec's error message in their detail.
- Breaking: remove the no-op `checksum` feature from `ozlrip-core`.
- Add `Limits::max_live_bytes`: the most bytes all intermediate streams of
  one chunk may hold at once (512 MiB strict, 128 MiB paranoid). Before, only
  each stream was bounded, so a hostile chunk could hold many buffers of
  `max_buffer_bytes` each. The largest observed need is about 3.5 times the
  chunk output, for a wide CSV sample.
- Check decoded output against the size the frame declares before reserving
  anything, after every chunk, and at the end. A tiny frame that declares a
  huge output now fails on the expansion ratio instead of reserving it, and a
  chunk that overruns the declared size is reported as such instead of as a
  later chunk's checksum failure. zstd output that decodes straight into the
  caller's buffer is capped at the remaining declared size.
- The single-zstd fast path enforces the expansion ratio exactly. It used a
  floor division that accepted slightly more output than allowed.
- Fix quantize and partition decoding of 25- to 32-bit extra bits that start
  mid-byte. Release builds returned wrong values; debug builds panicked.
- Breaking: remove the decoder plan cache, `Options::plan_cache_max_frame_bytes`
  and `DEFAULT_PLAN_CACHE_MAX_FRAME_BYTES`. The cache only helped when the
  exact same frame bytes were decoded again, cost a frame copy and plan clone
  on every miss, and let a reused `Decoder` accept typed-output frames on the
  second call that it rejected on the first.
- Unsupported dictionary use is rejected when a chunk's execution plan is
  built, so direct-append paths can no longer skip the check.
- `decode_into` no longer replaces an empty caller `Vec` that already has
  enough capacity, so reserved capacity is kept.
- Decode OpenZL format v27, the version upstream writes by default, in every
  build. Breaking: remove the `dev-format` feature.
- Match upstream's per-transform format version ranges: `transpose_split` is
  accepted from v11 and `convert_serial_string`/`separate_string_components`
  from v10. Deprecated transforms are rejected after their last version
  (`zstd_fixed` after v10, FastLZ and ROLZ after v12, deprecated FSE and
  Huffman after v14).
- Breaking: `Limits`, `Options`, `FrameInfo`, `ErrorKind`, and
  `FrameValueType` are `#[non_exhaustive]`. Build `Limits` from
  `Limits::strict()`, `Limits::paranoid()`, or `Limits::default()` and set
  fields; build `Options` from `Options::default()` or the new
  `Options::from(limits)`.
- Breaking: `Limits::default()` is always `Limits::strict()`. The `paranoid`
  feature no longer changes it; call `Limits::paranoid()` explicitly.
- Breaking: rename `FrameInfo::inputs` to `FrameInfo::outputs`.
- Breaking: remove `Decoder::load_fat_bundle`; use
  `Decoder::load_dictionary_bundle`.
- Breaking: `FrameInfo` and `FrameValueType` move from `ozlrip-core` to
  `ozlrip-decode`. `FrameValueType` is now re-exported from `ozlrip`.
- `Error::with_detail` takes `impl Into<Cow<'static, str>>`, so static
  details no longer allocate.
- `Error` implements `core::error::Error` without the `std` feature, and its
  `Display` output uses readable kind names instead of `Debug` names.
- `Decoder` implements `Debug` and is checked to be `Send + Sync`.
- Remove the `interop` feature. The upstream interop tests are now ignored
  tests that require `OZLRIP_ZLI` or an `OZLRIP_ZLI_<release>` variable and
  fail when it is missing. Run them with `cargo test --test interop -- --ignored`.
- Release smoke tests only run cases whose profile the release's `zli`
  supports, and now cover OpenZL v0.0.23 and v0.1.0 in CI.

## [0.5.0]

- Update `zrip`, `zrip-core`, `lz4rip`, and `fearless_simd` dependencies.
- Raise the workspace MSRV to Rust 1.89 and update the CI MSRV job.
- Add public error taxonomy coverage for truncated checksum fields and
  compressed checksum mismatches.

## [0.4.0]

- Decode more OpenZL standard graph nodes, including `concat_string`,
  `tokenize_string`, `huffman_struct_v2`, legacy transpose, and legacy zstd
  fixed nodes.
- Decode deprecated entropy and LZ compatibility paths for raw, constant, bit,
  multi-block, FSE, FastLZ, and ROLZ payload shapes.
- Harden malformed deprecated entropy handling, including short FSE state
  outputs and invalid FSE state counts.
- Add focused fuzz targets for entropy v2, FSE ncount, and deprecated
  entropy/LZ nodes.
- Run upstream OpenZL `zli` interop in CI against `dev` and the latest release
  checkpoint.

## [0.3.0]

- Decode OpenZL `prefix` string reconstruction nodes.
- Decode OpenZL `dedup_num` nodes that regenerate multiple numeric streams.
- Decode OpenZL `divide_by` numeric nodes with checked reconstruction.
- Decode OpenZL `splitn_num` numeric split nodes, including empty numeric
  outputs that carry element width in the transform header.

## [0.2.0]

- Accept OpenZL format v27 metadata behind `dev-format`, including
  `pivco_huffman` graph validation, safe scalar payload decode, and std-gated
  SIMD merge acceleration.
- Load OpenZL fat dictionary bundles through `Decoder` and decode
  zstd-dictionary-backed frames.
- Track OpenZL release-checkpoint interop and standard-node fixture coverage in
  committed manifests.
- Add fuzz entry points for public-frame Field-LZ and dispatch-string graphs.
- Decode OpenZL `constant_fixed` typed repeat streams.
- Speed up constant repeat fills and quantized numeric reconstruction.
- Pin public API behavior for custom transforms and unsupported dictionary
  materializers to typed `Unsupported` errors.

## [0.1.0]

- Initial release: decoder-first OpenZL implementation for standard-codec
  frames, with defensive frame parsing, whole-graph validation before
  execution, typed errors, and configurable limits.
- Public API: `decode`, `decode_into`, `decode_with_options`,
  `decode_into_with_options`, `inspect`, and a reusable `Decoder`.
- Stored streams, chunk and output checksums, zstd nodes via `zrip`, and lz4
  nodes via `lz4rip`.
- Graph transforms: concat, splitN, split-by-struct, transpose split, bit
  split, mux lengths, dispatch string, and dispatchN-byTag.
- Numeric and table transforms: endian conversion, delta, zigzag, bitpack,
  bitunpack, range-pack, flatpack, sparse num, partition, and quantize.
- Text and reconstruction transforms: tokenizer, parse-int, LZ, and field-LZ.
- `paranoid` feature as a safe-code correctness baseline, `no_std` support via
  `alloc`, and typed `Unsupported` errors for dictionaries, materialized
  bundles, and custom codecs.
