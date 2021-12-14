[![crates.io](https://img.shields.io/crates/d/itm.svg)](https://crates.io/crates/itm)
[![crates.io](https://img.shields.io/crates/v/itm.svg)](https://crates.io/crates/itm)

# `itm`

**This crate is now deprecated, please refer to [rtic-scope/itm](https://github.com/rtic-scope/itm) instead.**

**See [#589] for details.**

**Versions of `itm` on crates.io after 0.4 refer to the rtic-scope repository
and include a new itm-decode command-line utility.**

[#589]: https://github.com/rust-embedded/wg/pull/589

**Original README:**

> A Rust crate and tool `itmdump` to parse and dump ARM [ITM] packets.

This project is developed and maintained by the [Cortex-M team][team].

[ITM]: http://infocenter.arm.com/help/topic/com.arm.doc.ddi0314h/Chdbicbg.html

## [Documentation](https://docs.rs/crate/itm)

## How to install `itmdump`

```shell
# Install `itmdump` tool
$ cargo install itm

# Check installation
$ itmdump --version
```

## Minimum Supported Rust Version (MSRV)

This crate is guaranteed to compile on stable Rust 1.31.0 and up. It *might*
compile with older versions but that may change in any new patch release.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

## Code of Conduct

Contribution to this crate is organized under the terms of the [Rust Code of
Conduct][CoC], the maintainer of this crate, the [Cortex-M team][team], promises
to intervene to uphold that code of conduct.

[CoC]: CODE_OF_CONDUCT.md
[team]: https://github.com/rust-embedded/wg#the-cortex-m-team
