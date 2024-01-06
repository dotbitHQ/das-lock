extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse::Parse, parse::ParseStream, parse_macro_input, ItemFn, LitInt, Result};

struct MacroInput {
    value: LitInt,
}

impl Parse for MacroInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let value: LitInt = input.parse()?;
        Ok(MacroInput { value })
    }
}
#[proc_macro_attribute]
pub fn test_level(attr: TokenStream, item: TokenStream) -> TokenStream {
    //get intput
    let MacroInput { value } = parse_macro_input!(attr as MacroInput);

    //get feature value
    let feature_value = value.base10_parse::<u8>().unwrap_or(0);

    let input_fn = parse_macro_input!(item as ItemFn);

    //get threshold
    let threshold;
    let bound: [u8; 4] = [0, 1, 2, 3];
    //test level
    // single, 3, only test single case
    // partial, 2, some case that need transaction use this,
    // dev, 1, most case should use this
    // all, 0
    if cfg!(feature = "test-single") {
        threshold = bound[3];
    } else if cfg!(feature = "test-partial") {
        threshold = bound[2];
    } else if cfg!(feature = "test-dev") {
        threshold = bound[1];
    } else if cfg!(feature = "test-all") {
        threshold = bound[0];
    } else {
        //default is test none
        threshold = 99;
    }
    println!("f: {}, t: {}", feature_value, threshold);
    let expanded = if feature_value >= threshold {
        quote! {
            #[test_case]
            #input_fn
        }
    } else {
        //warning: don't remove the code below, it's used to comment the function
        quote! {
              // #input_fn
        }
    };

    // return the code as TokenStream
    TokenStream::from(expanded)
}
