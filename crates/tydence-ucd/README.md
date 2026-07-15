# tydence-ucd

Compile-time Unicode character tables for
[tydence](https://crates.io/crates/tydence), generated from frozen
Unicode Character Database data.

The character tables a tydence manifest format version depends on
must never move under a dependency or toolchain upgrade, so the
source of truth is a verbatim UCD file frozen under `data/` and
parsed while the proc-macro expands. Category selection happens at
expansion time too: only the selected, already-merged code point
ranges reach the compiled binary. No generated code is committed
anywhere.

This crate is an internal dependency of tydence and releases on its
own clock; depend on `tydence` itself unless these tables are
specifically what you want.

## License

MIT OR Apache-2.0, with the redistributed Unicode Character Database
files under `data/` carrying the [Unicode-3.0
license](data/UNICODE-LICENSE.txt) on top — the package as a whole is
`(MIT OR Apache-2.0) AND Unicode-3.0`.
