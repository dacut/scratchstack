//! The generated modules, accumulated as token streams.

use {
    proc_macro2::TokenStream,
    quote::quote,
    std::{
        fs::File,
        io::{BufWriter, Error as IoError, Result as IoResult, Write},
        path::Path,
    },
};

/// The five modules shapegen emits, each accumulated as Rust tokens.
///
/// Generators append tokens rather than formatted text, so a mismatched brace is a parse error
/// naming the shape that produced it instead of a syntax error somewhere in a three-megabyte file.
#[derive(Clone, Debug, Default)]
pub struct Modules {
    /// `crate::action` -- the `Action` enum and the API version.
    pub action: TokenStream,

    /// `crate::error_meta` -- the service-wide `Error` union.
    pub error_meta: TokenStream,

    /// `crate::operation` -- operation input/output structures and response envelopes.
    pub operation: TokenStream,

    /// `crate::types` -- ordinary structures, enums, unions, and validators.
    pub types: TokenStream,

    /// `crate::types::error` -- error structures.
    pub types_error: TokenStream,
}

impl Modules {
    /// Creates an empty set of modules.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Renders each module and writes it into `dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if a file cannot be created or written.
    ///
    /// # Panics
    ///
    /// Panics if a module's tokens are not parseable as Rust. That is a bug in a generator, and the
    /// message carries the parse error and the offending source.
    pub fn write_to(&self, dir: &Path) -> IoResult<()> {
        for (name, tokens) in [
            ("action.rs", &self.action),
            ("error_meta.rs", &self.error_meta),
            ("operation.rs", &self.operation),
            ("types.rs", &self.types),
            ("types_error.rs", &self.types_error),
        ] {
            let path = dir.join(name);
            let file = File::create(&path)
                .map_err(|e| IoError::new(e.kind(), format!("could not create {}: {e}", path.display())))?;
            let mut writer = BufWriter::new(file);
            writer.write_all(render(name, tokens).as_bytes())?;
            writer.flush()?;
        }

        Ok(())
    }
}

/// Renders a token stream as formatted Rust source.
///
/// # Panics
///
/// Panics if the tokens do not parse. Generated code that cannot be parsed here could not have been
/// compiled either, and failing at generation time says which module is at fault while the previous
/// line-at-a-time writers left it to rustc to report a brace mismatch tens of thousands of lines in.
#[must_use]
pub fn render(module_name: &str, tokens: &TokenStream) -> String {
    match syn::parse2::<syn::File>(tokens.clone()) {
        Ok(file) => prettyplease::unparse(&file),
        Err(e) => panic!("generated {module_name} is not valid Rust: {e}\n\n{tokens}"),
    }
}

/// Renders documentation as `#[doc]` attributes, or `#[allow(missing_docs)]` when there is none.
///
/// Model documentation is a block of HTML prose; each line becomes its own attribute so the result
/// reads like the hand-written `///` comments it replaces. The leading space matters: without it
/// `prettyplease` emits `///text` rather than `/// text`.
#[must_use]
pub fn doc_tokens(documentation: Option<&str>) -> TokenStream {
    let Some(documentation) = documentation else {
        return quote!(#[allow(missing_docs)]);
    };

    let lines = documentation.lines().map(|line| {
        let line = format!(" {}", line.trim());
        quote!(#[doc = #line])
    });

    quote!(#(#lines)*)
}

/// Builds an identifier, preserving the raw form of `r#type` and friends.
///
/// `Ident::new` rejects a keyword outright, so names coming back from
/// [`to_rust_ident`][crate::StrExt::to_rust_ident] have to be split apart again.
///
/// # Panics
///
/// Panics if `name` is not a valid Rust identifier, which would mean a generator built one wrong.
#[must_use]
pub fn ident(name: &str) -> proc_macro2::Ident {
    match name.strip_prefix("r#") {
        Some(bare) => proc_macro2::Ident::new_raw(bare, proc_macro2::Span::call_site()),
        None => proc_macro2::Ident::new(name, proc_macro2::Span::call_site()),
    }
}

/// Parses a rendered type name -- `crate::types::Tag`, `::std::vec::Vec<T>` -- into tokens.
///
/// # Panics
///
/// Panics if the name does not parse as a Rust type.
#[must_use]
pub fn type_tokens(name: &str) -> TokenStream {
    let ty: syn::Type = syn::parse_str(name).unwrap_or_else(|e| panic!("{name} is not a valid Rust type: {e}"));
    quote!(#ty)
}

/// An unsuffixed integer literal, so `3` renders as `3` rather than `3usize`.
#[must_use]
pub fn usize_literal(value: usize) -> proc_macro2::Literal {
    proc_macro2::Literal::usize_unsuffixed(value)
}

/// Doubles braces so a model string can be embedded in a `format!` template.
#[must_use]
pub fn escape_braces(text: &str) -> String {
    text.replace('{', "{{").replace('}', "}}")
}
