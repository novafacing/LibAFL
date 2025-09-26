//! Derives for `LibAFL`

#![no_std]
#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(test, deny(
    missing_debug_implementations,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    //unused_results
))]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]

extern crate alloc;
use alloc::string::{String, ToString};

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Attribute, Data::Struct, DeriveInput, Expr, Field, Fields::Named, PathArguments, Type,
    parse_macro_input,
};

/// Derive macro to implement `SerdeAny`, to use a type in a `SerdeAnyMap`
#[proc_macro_derive(SerdeAny)]
pub fn libafl_serdeany_derive(input: TokenStream) -> TokenStream {
    let name = parse_macro_input!(input as DeriveInput).ident;
    TokenStream::from(quote! {
        libafl_bolts::impl_serdeany!(#name);
    })
}

/// A derive macro to implement `Display`
///
/// Derive macro to implement [`core::fmt::Display`] for a struct where all fields implement `Display`.
/// The result is the space separated concatenation of all fields' display.
/// Order of declaration is preserved.
/// Specifically handled cases:
/// Options: Some => inner type display None => "".
/// Vec: inner type display space separated concatenation.
/// Generics and other more or less exotic stuff are not supported.
///
/// # Examples
///
/// ```rust
/// use libafl_derive;
///
/// #[derive(libafl_derive::Display)]
/// struct MyStruct {
///     foo: String,
///     bar: Option<u32>,
/// }
/// ```
///
/// The above code will expand to:
///
/// ```rust
/// struct MyStruct {
///     foo: String,
///     bar: Option<u32>,
/// }
///
/// impl core::fmt::Display for MyStruct {
///     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
///         f.write_fmt(format_args!(" {0}", self.foo))?;
///         if let Some(opt) = &self.bar {
///             f.write_fmt(format_args!(" {0}", opt))?;
///         }
///         Ok(())
///     }
/// }
/// ```
///
/// # Panics
/// Panics for any non-structs.
#[proc_macro_derive(Display)]
pub fn libafl_display(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input as DeriveInput);

    if let Struct(s) = data {
        if let Named(fields) = s.fields {
            let fields_fmt = fields.named.iter().map(libafl_display_field_by_type);

            return quote! {
                impl core::fmt::Display for #ident {
                    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        #(#fields_fmt)*
                        Ok(())
                    }
                }
            }
            .into();
        }
    }
    return syn::Error::new(ident.span(), "Only structs are supported")
        .to_compile_error()
        .into();
}

fn libafl_display_field_by_type(it: &Field) -> proc_macro2::TokenStream {
    let fmt = " {}";
    let ident = &it.ident;
    if let Type::Path(type_path) = &it.ty {
        if type_path.qself.is_none() && type_path.path.segments.len() == 1 {
            let segment = &type_path.path.segments[0];
            if segment.ident == "Option" {
                return quote! {
                    if let Some(opt) = &self.#ident {
                        write!(f, #fmt, opt)?;
                    }
                };
            } else if segment.ident == "Vec" {
                return quote! {
                    for e in &self.#ident {
                        write!(f, #fmt, e)?;
                    }
                };
            }
        }
    }
    quote! {
        write!(f, #fmt, self.#ident)?;
    }
}

/// Derive a simple libFuzzer-style argument parser.
///
/// Supports:
/// - Fields:
///     * Option<T>
///     * T (non-Option)
/// - Non-Option fields:
///     * If they have `#[libfuzzer_parse(default = EXPR)]`, they are optional (prepopulated).
///     * Without a default they are required; missing flag panics.
/// - Attribute:
///     * `#[libfuzzer_parse(default = 123)]`
///
/// Parsing syntax: `-field_name=value` (flag name is always the field identifier).
#[proc_macro_derive(LibFuzzerParse, attributes(libfuzzer_parse))]
pub fn derive_libfuzzer_parse(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, data, .. } = parse_macro_input!(input as DeriveInput);

    let Struct(ds) = data else {
        return syn::Error::new(ident.span(), "LibFuzzerParse only supports structs")
            .to_compile_error()
            .into();
    };
    let fields = match ds.fields {
        Named(f) => f.named,
        _ => {
            return syn::Error::new(ident.span(), "LibFuzzerParse needs named fields")
                .to_compile_error()
                .into();
        }
    };

    // Token accumulators (avoid Vec<FieldInfo>)
    let mut let_inits_ts = proc_macro2::TokenStream::new();
    let mut match_arms_ts = proc_macro2::TokenStream::new();
    let mut build_fields_ts = proc_macro2::TokenStream::new();

    // Collector (trailing Vec<String>)
    let mut collector_ident: Option<proc_macro2::Ident> = None;
    let mut seen_collector = false; // once true, no further fields allowed

    for f in fields {
        let ident = f.ident.unwrap();
        let ty_clone = f.ty.clone();

        // Detect Vec<String>
        let is_vec_string = match &ty_clone {
            Type::Path(tp) if tp.qself.is_none() && tp.path.segments.len() == 1 => {
                let seg = &tp.path.segments[0];
                if seg.ident == "Vec" {
                    if let PathArguments::AngleBracketed(ab) = &seg.arguments {
                        if let Some(syn::GenericArgument::Type(Type::Path(p))) = ab.args.first() {
                            p.path.segments.last().is_some_and(|s| s.ident == "String")
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false,
        };

        if is_vec_string {
            if collector_ident.is_some() {
                return syn::Error::new(
                    ident.span(),
                    "Only one Vec<String> collector field allowed",
                )
                .to_compile_error()
                .into();
            }
            if seen_collector {
                return syn::Error::new(ident.span(), "Collector must be last field")
                    .to_compile_error()
                    .into();
            }
            let mut tmp_name_c = String::from("__");
            tmp_name_c.push_str(&ident.to_string());
            tmp_name_c.push_str("_collect");
            let var_ident = syn::Ident::new(&tmp_name_c, ident.span());
            collector_ident = Some(var_ident.clone());
            seen_collector = true; // any further field triggers error
            // init collector
            let_inits_ts.extend(quote! { let mut #var_ident: Vec<String> = Vec::new(); });
            // build struct field
            build_fields_ts.extend(quote! { #ident: #var_ident, });
            continue;
        }

        if seen_collector {
            return syn::Error::new(ident.span(), "Collector must be last field")
                .to_compile_error()
                .into();
        }

        let (inner_ty, is_option) = extract_option_inner(&f.ty);

        // Parse attributes (currently only default)
        let mut default_tok = None;
        for attr in f
            .attrs
            .iter()
            .filter(|a| a.path().is_ident("libfuzzer_parse"))
        {
            parse_attr(attr, &mut default_tok);
        }

        let required = !is_option && default_tok.is_none();
        let is_string = matches!(&inner_ty, Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "String"));

        let mut tmp_name_t = String::from("__");
        tmp_name_t.push_str(&ident.to_string());
        tmp_name_t.push_str("_tmp");
        let var_ident = syn::Ident::new(&tmp_name_t, ident.span());
        if let Some(def) = &default_tok {
            let_inits_ts.extend(quote! { let mut #var_ident : Option<#inner_ty> = Some(#def); });
        } else {
            let_inits_ts.extend(quote! { let mut #var_ident : Option<#inner_ty> = None; });
        }

        let lit = syn::LitStr::new(&ident.to_string(), ident.span());
        if is_string {
            match_arms_ts.extend(quote! { #lit => { #var_ident = Some(value.to_string()); } });
        } else {
            match_arms_ts.extend(quote! { #lit => { #var_ident = Some(value.parse::<#inner_ty>().unwrap_or_else(|_| panic!("Invalid value for -{}: {}", #lit, value))); } });
        }

        if is_option {
            build_fields_ts.extend(quote! { #ident: #var_ident, });
        } else if required {
            build_fields_ts.extend(quote! { #ident: #var_ident.expect(concat!("Required flag -", stringify!(#ident), " not provided")), });
        } else {
            build_fields_ts.extend(quote! { #ident: #var_ident.expect("Internal error: value missing (should have default or provided)"), });
        }
    }

    let unknown_arm = if let Some(ref coll) = collector_ident {
        quote! { _ => { #coll.push(original.to_string()); } }
    } else {
        quote! { _ => { } }
    };

    let push_positional = if let Some(ref coll) = collector_ident {
        quote! { #coll.push(original.to_string()); }
    } else {
        quote! {}
    };

    let output = quote! {
        impl #ident {
            pub fn parse_libfuzzer<I, T>(args: I) -> Self
            where
                I: IntoIterator<Item = T>,
                T: AsRef<str>
            {
                #let_inits_ts
                for arg in args {
                    let original = arg.as_ref();
                    if original.starts_with('-') {
                        let body = &original[1..];
                        if let Some((key, value)) = body.split_once('=') {
                            match key {
                                #match_arms_ts
                                #unknown_arm
                            }
                            continue;
                        } else {
                            // Dash but no '=' -> treat whole flag as positional/unknown
                            #push_positional
                            continue;
                        }
                    } else {
                        // Positional argument
                        #push_positional
                        continue;
                    }
                }
                Self { #build_fields_ts }
            }
        }
    };

    output.into()
}

fn extract_option_inner(ty: &Type) -> (Type, bool) {
    if let Type::Path(tp) = ty {
        if tp.qself.is_none() && tp.path.segments.len() == 1 {
            let seg = &tp.path.segments[0];
            if seg.ident == "Option" {
                if let PathArguments::AngleBracketed(ab) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(t)) = ab.args.first() {
                        return (t.clone(), true);
                    }
                }
            }
        }
    }
    (ty.clone(), false)
}

fn parse_attr(attr: &Attribute, default_out: &mut Option<proc_macro2::TokenStream>) {
    let _ = attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("default") {
            if let Ok(lit) = meta.value() {
                let expr: Expr = lit.parse().unwrap();
                *default_out = Some(quote! { #expr });
            }
        }
        Ok(())
    });
}
