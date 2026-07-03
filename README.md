# ozlrip

Memory-safe Rust decoder for OpenZL.

## API

```rust
let decoded = ozlrip::decode(frame)?;

let mut dst = Vec::new();
let written = ozlrip::decode_into(frame, &mut dst, ozlrip::Limits::default())?;

let info = ozlrip::inspect(frame)?;
```

For reusable allocation state, create `ozlrip::Decoder` and call
`Decoder::decode_into`.

## Benchmarking

Decode benchmarks report decoded MB/s and append JSONL results under
`~/.cache/ozlrip/<arch>/<impl>.jsonl`.

```sh
cargo bench --manifest-path bench/Cargo.toml --bench decode_profiles
```

The benchmark uses `rust-openzl` as a bench-only dependency to generate upstream
OpenZL frames and compare `ozlrip` against `openzl-c-ffi` in process.
