//! Compile-time Unicode character tables for tydence.
//!
//! The character tables a manifest format version depends on must
//! never move under a dependency or toolchain upgrade, so the
//! source of truth is a verbatim Unicode Character Database file
//! frozen under `data/` and parsed while the macro expands. No
//! generated code is committed anywhere.
//!
//! Category selection happens at expansion time too, driven by a
//! pattern parameter: only the selected, already-merged ranges
//! reach the compiled binary, instead of the whole category table
//! staying resident for a runtime filter to pick over.

mod expand;
mod parse;
mod select;

use proc_macro::TokenStream;

/// Expands to a `&'static [(u32, u32)]` of inclusive code point
/// ranges holding exactly the general categories of the named
/// frozen UCD version that match the pattern, sorted and with
/// adjacent ranges merged.
///
/// The pattern is a regular expression (`regex` crate syntax) used
/// verbatim as a search over the two-letter category name, so write
/// anchors explicitly: `"^[CZ]"` selects every C* and Z* category,
/// `"^Zs$"` selects exactly Zs. A pattern selecting no category at
/// all fails the build.
// rustc requires #[proc_macro] functions to sit in the crate root,
// so this is a delegation instead of a pub use
#[proc_macro]
pub fn general_category_ranges(input: TokenStream) -> TokenStream {
    expand::general_category_ranges(input)
}
