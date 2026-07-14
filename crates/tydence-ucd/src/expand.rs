use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{LitStr, Token};

use super::parse;
use super::select;

const UCD_17_0_0: &str =
    include_str!("../data/DerivedGeneralCategory-17.0.0.txt");

struct MacroArguments {
    ucd_version: String,
    category_pattern: String,
}

impl Parse for MacroArguments {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let version_literal: LitStr = input.parse()?;
        input.parse::<Token![,]>()?;
        let pattern_literal: LitStr = input.parse()?;
        Ok(MacroArguments {
            ucd_version: version_literal.value(),
            category_pattern: pattern_literal.value(),
        })
    }
}

pub fn general_category_ranges(input: TokenStream) -> TokenStream {
    let arguments = match syn::parse::<MacroArguments>(input) {
        Ok(parsed_arguments) => parsed_arguments,
        Err(parse_error) => {
            return parse_error.to_compile_error().into();
        }
    };
    let ucd_source = match arguments.ucd_version.as_str() {
        "17.0.0" => UCD_17_0_0,
        unsupported_version => panic!(
            "unsupported UCD version {unsupported_version:?}; \
             available: 17.0.0"
        ),
    };
    let categorized_ranges = parse::run(ucd_source);
    let selected_ranges =
        select::run(&categorized_ranges, &arguments.category_pattern);
    let range_tokens = selected_ranges
        .iter()
        .map(|(first, last)| quote! { (#first, #last) });
    quote! { &[ #( #range_tokens ),* ] }.into()
}
