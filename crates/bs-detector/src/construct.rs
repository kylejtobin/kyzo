/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * Use of this software is governed by the Business Source License 1.1
 * included in the repository as LICENSE-BSL. See LICENSING.md.
 *
 * Change Date:    2030-07-11
 * Change License: Mozilla Public License, version 2.0
 */

//! AUTHORITY: The approved patterns. Nothing outside this file is approved.
//! SEAT: bs-detector/construct
//! FILE_KIND: closed_set
//!
//! Thirteen constructs. Every item under `crates/` satisfies the conditions of
//! exactly one of them, or it is a violation. To let a kind of item through,
//! someone adds a construct here, in the open, with conditions, and signs the
//! diff.
//!
//! **This file holds the rules and nothing else.** It does not walk a tree and
//! it does not resolve a type. Both were hand-rolled here and both are now
//! [`TypeFacts`]: three questions a real type checker answers exactly, where
//! the deleted machine answered them by matching identifiers against tables.
//!
//! What that machine cost, measured: 19,743 `unproven receiver`, 6,799
//! `unproven macro`, 3,084 `unproven path`, 1,641 `unproven foreign` — 68% of
//! the reported number was a parser without types, not a tree without types.
//! A lint pass runs inside the compiler, after macro expansion, with every
//! path resolved. None of those categories can exist there.
//!
//! Conditions are not a blacklist. They are what make an item that construct
//! at all. There is no good newtype and bad newtype: there is newtype, and
//! there is not-a-newtype.

// --- zone-file:imports ---

use std::collections::{BTreeMap, BTreeSet};


// --- zone-file:types ---

/// What a construct's conditions need to know about a name, and cannot decide
/// from the name itself.
///
/// Every method here was a table lookup or a hand-built symbol map. A real
/// type checker answers all three from resolved definitions, so the
/// implementation of this trait is the only thing a harness must supply.
pub trait TypeFacts {
    /// Does the program declare this type, unambiguously, and is it proven?
    fn provenance(&self, name: &str) -> Provenance;
    /// Does the program declare a trait by this name, exactly once?
    fn declares_trait(&self, name: &str) -> bool;
    /// Does this name resolve to an enum that itself seats as a closed sum?
    fn is_closed_sum(&self, name: &str) -> bool;
    /// Does every call in this body reach only proven receivers and approved
    /// macros? Purity is decided from the receiver's *type*, never its name.
    fn body_is_pure(&self, block: &syn::Block, self_ty: &str, sig: &syn::Signature) -> bool;
    /// Does this body call back into the type it is building? A mint that does
    /// is not the door it claims to be.
    fn calls_into(&self, block: &syn::Block, owner: &str) -> bool;
}

/// Where a name comes from. Silence requires proof: a name that resolves to
/// nothing is `Unproven` and is refused, never assumed benign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// The program declares it.
    Declared,
    /// On the `FOREIGN_PURE` approval table.
    ForeignPure,
    /// Reaches outside the program into ambient authority.
    Ambient,
    /// Resolves to nothing this pass can name.
    Unproven,
}

/// The kinds of item this crate can name. A closed sum we own.
///
/// [`ItemKind::of`] is the only place `syn::Item` is read. Rust requires a
/// wildcard there because `syn::Item` is `#[non_exhaustive]`; that wildcard
/// produces [`ItemKind::Unknown`], which is unconstructible as an approval —
/// no condition function accepts it and the walk reports it as its own
/// violation category. A `syn` upgrade that adds a variant therefore shows up
/// as `unknown-item-kind` in the log rather than as silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Construct {
    /// One primitive, named, carrying its law. Exactly one unnamed private
    /// field whose type is a primitive terminal. No `Default`.
    Newtype,

    /// A composite whose every field is already a lawful type. Named fields,
    /// all private, none a bare primitive / `bool` / `Option`. No `Default`.
    SealedProduct,

    /// A total enumeration. Not `#[non_exhaustive]`; no variant carries a
    /// bare primitive or an `Option`. No `Default`.
    ClosedSum,

    /// Zero size — indexes a state, a brand, or an authority. A unit struct
    /// or a struct of `PhantomData` only. No `Default`: a mintable authority
    /// is no authority.
    Marker,

    /// `Result<Self, Refusal>` — the only way to obtain a value. No receiver;
    /// `Err` names a [`Construct::ClosedSum`] declared in this file; body is
    /// pure; no panic.
    Mint,

    /// `&self -> T`. Reads, computes, changes nothing. Lawful return type,
    /// `Err` a declared closed sum, no `&mut` anywhere, pure body, no panic,
    /// and not a bare field read.
    Derivation,

    /// `self -> T`. Consumes and yields the next state. Same conditions as
    /// [`Construct::Derivation`], with a consuming receiver.
    Transition,

    /// A closed interface, not an extension point. Has a supertrait sealing
    /// it; methods only; no method is a predicate or returns prose.
    SealedTrait,

    /// The one seat where effects are lawful. A free, private, argument-less
    /// `fn main` yielding nothing or `ExitCode`/`Result` — necessary, not
    /// sufficient. What gives the seat meaning is [`Scope::ambient_sites`],
    /// which makes every effect performed outside it a violation at the site.
    CompositionRoot,

    /// A name binding. Private, never a glob, and never renamed: an unbounded
    /// surface is not a binding, a `pub use` is a re-export that belongs only
    /// to the sealed door, and an `as` rename gives one thing a second name
    /// that no reader and no gate can follow.
    Import,

    /// A namespace. Private or crate-visible, never `#[path]`-redirected, and
    /// never inline: a `mod x { .. }` is a second file's worth of seats
    /// hidden inside another file.
    Module,

    /// A handle that cannot outlive its scope. The only seat that may hold a
    /// reference field: it must carry exactly one lifetime parameter, every
    /// reference field must use that lifetime, and a `PhantomData` must carry
    /// the lifetime in an *invariant* position. A covariant brand is not a
    /// brand — see [`brand_is_invariant`].
    Confinement,

    /// A method container. Non-empty, inherent or implementing a trait
    /// declared in *this file* and itself seating as
    /// [`Construct::SealedTrait`], never blanket (`impl<T> _ for T` is an
    /// open extension point), never `#[allow]`.
    ImplBlock,
}

impl Construct {
    /// Every approved pattern. Read by the fixture law, which is the only
    /// caller that needs to enumerate the set.
    #[cfg(test)]
    pub const ALL: [Construct; 13] = [
        Construct::Newtype,
        Construct::SealedProduct,
        Construct::ClosedSum,
        Construct::Marker,
        Construct::Mint,
        Construct::Derivation,
        Construct::Transition,
        Construct::SealedTrait,
        Construct::CompositionRoot,
        Construct::Import,
        Construct::Module,
        Construct::Confinement,
        Construct::ImplBlock,
    ];

    /// Every condition this construct imposes, by name.
    ///
    /// The fixture law requires a `<law_name>.deny-<condition>.fixture` for
    /// each entry, and requires that fixture to fail *this* seat. A condition
    /// stated here with no fixture beside it fails the build, so a condition
    /// cannot be written down and left unenforced.
    #[cfg(test)]
    pub fn conditions(self) -> &'static [&'static str] {
        match self {
            Construct::Newtype => &[
                "public-field",
                "default-door",
                "not-terminal",
                "public-type",
                "unproven-generic",
                "const-generic",
                "lifetime-param",
                "unproven-attr",
                "crate-visible-type",
            ],
            Construct::SealedProduct => &[
                "public-field",
                "primitive-field",
                "option-field",
                "bare-collection",
                "public-type",
                "unproven-generic",
                "unproven-where",
                "reference-field",
                "ambient-field",
                "unproven-field",
                "unproven-attr",
                "crate-visible-field",
                "no-fields",
                "aliased-field",
            ],
            Construct::ClosedSum => &[
                "non-exhaustive",
                "primitive-payload",
                "default-door",
                "bare-collection",
                "public-type",
                "unproven-generic",
                "ambient-payload",
                "unproven-payload",
                "unproven-attr",
                "no-variants",
                "const-generic",
                "lifetime-param",
            ],
            Construct::Marker => &["default-door", "public-type", "unproven-attr"],
            Construct::Mint => &[
                "untyped-err",
                "err-not-in-scope",
                "panics",
                "calls-into-self",
                "duplicate-err",
                "unproven-foreign",
                "unproven-attr",
            ],
            Construct::Derivation => &[
                "primitive-return",
                "accessor",
                "mut-receiver",
                "effect",
                "bare-collection-return",
                "unsafe",
                "async",
                "soft-name-effect",
                "transitive-effect",
                "self-assoc-effect",
                "unproven-foreign",
                "unproven-receiver",
                "unproven-macro",
                "unproven-path",
                "laundered-argument",
                "laundered-chain",
                "laundered-field",
                "unproven-attr",
                "duplicate-method",
                "ambient-param",
                "unproven-param",
                "unbounded-generic",
                "opaque-param",
                "fn-pointer-param",
                "unproven-return-type",
                "foreign-abi",
                "shadowed-binding",
            ],
            Construct::Transition => &[
                "borrowed-receiver",
                "prose-err",
                "primitive-return",
                "bare-collection-return",
                "compound-assign",
                "unproven-foreign",
                "unproven-attr",
                "container-receiver",
            ],
            Construct::SealedTrait => &[
                "no-supertrait",
                "predicate",
                "associated-type",
                "public-type",
                "unsafe",
                "unproven-attr",
                "unproven-return",
                "unlawful-return",
                "unproven-generic",
                "const-generic",
                "lifetime-param",
            ],
            Construct::CompositionRoot => &[
                "not-main",
                "public",
                "takes-args",
                "effect-in-method",
                "effect-via-glob",
                "effect-via-body-glob",
                "unproven-attr",
                "foreign-abi",
                "library-file",
                "nested-position",
            ],
            Construct::Import => &["glob", "rename", "pub-use", "group", "unproven-leaf"],
            Construct::Module => &["path-attr", "inline", "public", "cfg-attr"],
            Construct::Confinement => &[
                "no-lifetime",
                "no-brand",
                "covariant-brand",
                "public-field",
                "two-lifetimes",
                "unbranded-reference",
                "unproven-attr",
            ],
            Construct::ImplBlock => &[
                "foreign-trait",
                "blanket",
                "empty",
                "unsealed-trait",
                "unsafe",
                "unproven-generic",
                "unproven-attr",
                "unproven-self-type",
                "aliased-self-type",
            ],
        }
    }

    /// The fixture stem and display name.
    #[cfg(test)]
    pub fn law_name(self) -> &'static str {
        match self {
            Construct::Newtype => "newtype",
            Construct::SealedProduct => "sealed-product",
            Construct::ClosedSum => "closed-sum",
            Construct::Marker => "marker",
            Construct::Mint => "mint",
            Construct::Derivation => "derivation",
            Construct::Transition => "transition",
            Construct::SealedTrait => "sealed-trait",
            Construct::CompositionRoot => "composition-root",
            Construct::Import => "import",
            Construct::Module => "module",
            Construct::Confinement => "confinement",
            Construct::ImplBlock => "impl-block",
        }
    }
}

/// What one file declares about itself, gathered before anything is judged.
///
/// Two facts the conditions cannot decide without it: which names in this file
/// reach ambient authority (following `use` paths and `as` renames, so an
/// alias is not an escape), and which names are enums that seat as
/// [`Construct::ClosedSum`] (so a typed refusal is proven, not assumed from
/// its capitalisation).
pub fn seat_method(
        facts: &impl TypeFacts,
        attrs: &[syn::Attribute],
        sig: &syn::Signature,
        block: Option<&syn::Block>,
        self_ty: &str,
    ) -> Option<Construct> {
        // An attribute macro replaces the method it sits on, so the body read
        // here is not the body that compiles. `#[tokio::test]` is a different
        // function than the one written down.
        if !attrs_are_proven(attrs) {
            return None;
        }
        // `unsafe` suspends the discipline the seats exist to enforce, and
        // `async` turns a verb into a state machine whose effects run
        // somewhere else, at a time nobody here decides. An `abi` exports the
        // method to callers outside every law in this file — the same surface
        // a `ForeignMod` is refused for, pointing the other way.
        if sig.unsafety.is_some() || sig.asyncness.is_some() || sig.abi.is_some() {
            return None;
        }
        if is_predicate(sig) || has_mut_param(sig) || !err_is_closed_sum(sig, facts) {
            return None;
        }
        // A method's own type parameters are bounds like any other, and its
        // parameters are surface like any other. Neither was read: an
        // unbounded `<T>`, a `File` parameter, an `impl Trait` parameter, and
        // a `fn(File) -> _` parameter all seated. A method that demands
        // authority is a method that only exists in a world that has it,
        // whether or not its body touches what it was handed.
        if !generics_are_proven(&sig.generics, facts) {
            return None;
        }
        // `Self` names the type this method sits on, which the surrounding
        // `impl` already proved by seating.
        let mut bound_here: BTreeSet<String> = sig
            .generics
            .type_params()
            .map(|tp| tp.ident.to_string())
            .collect();
        bound_here.insert("Self".to_string());
        let params_proven = sig.inputs.iter().all(|arg| match arg {
            syn::FnArg::Receiver(_) => true,
            syn::FnArg::Typed(t) => {
                !is_naked(&t.ty) && type_is_proven_with(&t.ty, facts, &bound_here)
            }
        });
        if !params_proven {
            return None;
        }
        // The same return law the sealed trait answers to. Adding it there
        // and not here left the contract stricter than the code implementing
        // it, which is the wrong way round.
        let return_proven = match &sig.output {
            syn::ReturnType::Type(_, ty) => type_is_proven_with(ty, facts, &bound_here),
            syn::ReturnType::Default => true,
        };
        if !return_proven {
            return None;
        }
        if block.is_some_and(|b| !facts.body_is_pure(b, self_ty, sig)) {
            return None;
        }
        let receiver = sig.inputs.iter().find_map(|a| match a {
            syn::FnArg::Receiver(r) => Some(r),
            syn::FnArg::Typed(_) => None,
        });
        let Some(r) = receiver else {
            if !returns_result_of_self(sig) {
                return None;
            }
            // A mint has no value yet. Calling a method on the type it is
            // building means a second door already made one, and this mint is
            // decorating it rather than being the only way in.
            if block.is_some_and(|b| facts.calls_into(b, self_ty)) {
                return None;
            }
            return Some(Construct::Mint);
        };
        if !returns_lawful(sig) {
            return None;
        }
        // An arbitrary self type is a receiver this seat cannot classify.
        // `r.reference` is `None` for `self`, for `self: Self`, and also for
        // `self: Box<Self>` and `self: &Self` — so reading only that field
        // seated a boxed receiver as a transition and an explicitly-borrowed
        // one as a transition too, which is the wrong seat for a borrow. The
        // receiver's *type* decides, like every other surface: `Self` is by
        // value, `&Self` is a borrow, and anything else is a container or a
        // smart pointer that the seat has no reading of.
        if let Some(ty) = &r.colon_token.and(Some(&*r.ty)) {
            return match ty {
                syn::Type::Path(_) if type_head_is(ty, "Self") => {
                    Some(Construct::Transition)
                }
                syn::Type::Reference(inner)
                    if inner.mutability.is_none() && type_head_is(&inner.elem, "Self") =>
                {
                    match block.is_some_and(is_accessor) {
                        true => None,
                        false => Some(Construct::Derivation),
                    }
                }
                _ => None,
            };
        }
        if r.reference.is_none() {
            return Some(Construct::Transition);
        }
        if r.mutability.is_some() {
            return None;
        }
        match block.is_some_and(is_accessor) {
            true => None,
            false => Some(Construct::Derivation),
        }
    }

// --- zone-file:state ---

/// Every type parameter is proven: bounded, and every bound names a trait
/// this file declares that itself seats as [`Construct::SealedTrait`].
///
/// An unbounded `T` is inhabitable by anything, which makes the type around it
/// a promise about nothing. A bound on a trait declared elsewhere cannot be
/// shown sealed from here — same burden as a door's refusal set.
fn generics_are_proven(g: &syn::Generics, facts: &impl TypeFacts) -> bool {
    // Only `type_params()` was ever read here, so a parameter of any other
    // kind passed this law by being invisible to it. `struct X<const N: usize
    // = { .. }>(u64)` seated as a lawful newtype with an unbounded value axis
    // and an arbitrary expression for its default.
    //
    // A const parameter cannot be proven, and not for want of effort: Rust has
    // no bound to put on one. It admits every value of its type, with no mint
    // standing over it and no refusal to return. A type indexed by an
    // unconstrained integer is a family of types nobody enumerated — the same
    // reason a blanket impl is refused, written with a value instead of a type.
    if g.const_params().next().is_some() {
        return false;
    }
    // Bounds may be written inline or in a `where` clause; both are bounds,
    // and reading only one of them is a door.
    let mut where_bounds: BTreeMap<String, Vec<&syn::TypeParamBound>> = BTreeMap::new();
    if let Some(w) = &g.where_clause {
        for pred in &w.predicates {
            let syn::WherePredicate::Type(t) = pred else {
                continue;
            };
            let Some(head) = type_head(&t.bounded_ty) else {
                continue;
            };
            where_bounds.entry(head).or_default().extend(t.bounds.iter());
        }
    }
    g.type_params().all(|tp| {
        let name = tp.ident.to_string();
        let inline = tp.bounds.iter();
        let extra = where_bounds.get(&name).into_iter().flatten().copied();
        let all: Vec<&syn::TypeParamBound> = inline.chain(extra).collect();
        !all.is_empty()
            && all.iter().all(|b| match b {
                syn::TypeParamBound::Trait(t) => t
                    .path
                    .segments
                    .last()
                    .is_some_and(|seg| facts.declares_trait(&seg.ident.to_string())),
                _ => false,
            })
    })
}

/// Any reference anywhere in a type.
fn has_reference(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(_) => true,
        syn::Type::Path(p) => p.path.segments.iter().any(|seg| {
            let syn::PathArguments::AngleBracketed(a) = &seg.arguments else {
                return false;
            };
            a.args.iter().any(|arg| match arg {
                syn::GenericArgument::Type(t) => has_reference(t),
                syn::GenericArgument::Lifetime(_) => true,
                _ => false,
            })
        }),
        syn::Type::Tuple(t) => t.elems.iter().any(has_reference),
        syn::Type::Slice(sl) => has_reference(&sl.elem),
        syn::Type::Array(a) => has_reference(&a.elem),
        _ => false,
    }
}

/// The confinement seat: a handle that cannot outlive or escape its scope.
///
/// Conditions: exactly one lifetime parameter; every reference field bound to
/// it; a `PhantomData` carrying that lifetime in an invariant position; all
/// fields private; no `Default`.
fn seat_confinement(s: &syn::ItemStruct) -> Option<Construct> {
    // Exactly one lifetime parameter. Two lifetimes means two scopes, and a
    // handle that answers to two scopes escapes one of them. What the
    // lifetime is *called* is not the law and is never read.
    let lifetimes: Vec<String> = s
        .generics
        .lifetimes()
        .map(|l| l.lifetime.ident.to_string())
        .collect();
    let [only] = lifetimes.as_slice() else {
        return None;
    };
    // A `PhantomData` must carry the lifetime, and carry it invariantly. A
    // covariant brand is not a brand: see `brand_is_invariant`.
    let carrier = s
        .fields
        .iter()
        .filter_map(|f| phantom_carrier(&f.ty))
        .find(|c| mentions_lifetime(c, only))?;
    if !brand_is_invariant(carrier, only) {
        return None;
    }
    // Every borrow in the struct is on that one lifetime. A reference on
    // anything else is a borrow the brand does not confine.
    let all_bound = s
        .fields
        .iter()
        .all(|f| !has_reference(&f.ty) || lifetime_of(&f.ty).as_deref() == Some(only.as_str()));
    match all_bound {
        true => Some(Construct::Confinement),
        false => None,
    }
}

/// The single type a `PhantomData` carries, if this type is one.
fn phantom_carrier(ty: &syn::Type) -> Option<&syn::Type> {
    let syn::Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last()?;
    if seg.ident != "PhantomData" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(a) = &seg.arguments else {
        return None;
    };
    a.args.iter().find_map(|arg| match arg {
        syn::GenericArgument::Type(t) => Some(t),
        _ => None,
    })
}

/// Whether a type names this lifetime anywhere inside it.
fn mentions_lifetime(ty: &syn::Type, lt: &str) -> bool {
    match ty {
        syn::Type::Reference(r) => {
            r.lifetime.as_ref().is_some_and(|l| l.ident == lt) || mentions_lifetime(&r.elem, lt)
        }
        syn::Type::Path(p) => p.path.segments.iter().any(|seg| {
            let syn::PathArguments::AngleBracketed(a) = &seg.arguments else {
                return false;
            };
            a.args.iter().any(|arg| match arg {
                syn::GenericArgument::Lifetime(l) => l.ident == lt,
                syn::GenericArgument::Type(t) => mentions_lifetime(t, lt),
                _ => false,
            })
        }),
        syn::Type::BareFn(f) => {
            f.inputs.iter().any(|i| mentions_lifetime(&i.ty, lt))
                || match &f.output {
                    syn::ReturnType::Type(_, t) => mentions_lifetime(t, lt),
                    syn::ReturnType::Default => false,
                }
        }
        syn::Type::Ptr(p) => mentions_lifetime(&p.elem, lt),
        syn::Type::Tuple(t) => t.elems.iter().any(|e| mentions_lifetime(e, lt)),
        syn::Type::Slice(s) => mentions_lifetime(&s.elem, lt),
        syn::Type::Array(a) => mentions_lifetime(&a.elem, lt),
        syn::Type::Paren(p) => mentions_lifetime(&p.elem, lt),
        syn::Type::Group(g) => mentions_lifetime(&g.elem, lt),
        _ => false,
    }
}

/// Types that are invariant in what they contain, so a lifetime inside one
/// cannot be widened or narrowed.
const INVARIANT_CELLS: [&str; 3] = ["Cell", "RefCell", "UnsafeCell"];

/// Whether a brand carries the lifetime in a position that makes the whole
/// handle invariant in it.
///
/// This is the difference between a brand and a decoration. `PhantomData<&'a
/// ()>` is **covariant** in `'a`: two handles branded by different scopes
/// unify at the shorter of the two, so a handle minted in one scope is
/// accepted where a handle from another is expected — exactly the escape the
/// seat exists to refuse. Only an invariant position stops that.
fn brand_is_invariant(carrier: &syn::Type, lt: &str) -> bool {
    match carrier {
        // `fn(&'a _) -> &'a _`: contravariant in the input, covariant in the
        // output. A lifetime standing in both cancels to invariant.
        syn::Type::BareFn(f) => {
            let in_input = f.inputs.iter().any(|i| mentions_lifetime(&i.ty, lt));
            let in_output = match &f.output {
                syn::ReturnType::Type(_, t) => mentions_lifetime(t, lt),
                syn::ReturnType::Default => false,
            };
            in_input && in_output
        }
        // `*mut T` is invariant in `T`. `*const T` is not — it is covariant,
        // and is refused here for the same reason a shared reference is.
        syn::Type::Ptr(p) => p.mutability.is_some() && mentions_lifetime(&p.elem, lt),
        // The interior-mutability cells are invariant in their contents.
        syn::Type::Path(_) => {
            INVARIANT_CELLS.iter().any(|c| type_head_is(carrier, c))
                && mentions_lifetime(carrier, lt)
        }
        syn::Type::Paren(p) => brand_is_invariant(&p.elem, lt),
        syn::Type::Group(g) => brand_is_invariant(&g.elem, lt),
        _ => false,
    }
}

/// The first lifetime named anywhere in a type.
fn lifetime_of(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Reference(r) => r.lifetime.as_ref().map(|l| l.ident.to_string()),
        syn::Type::Path(p) => p.path.segments.iter().find_map(|seg| {
            let syn::PathArguments::AngleBracketed(a) = &seg.arguments else {
                return None;
            };
            a.args.iter().find_map(|arg| match arg {
                syn::GenericArgument::Lifetime(l) => Some(l.ident.to_string()),
                syn::GenericArgument::Type(t) => lifetime_of(t),
                _ => None,
            })
        }),
        _ => None,
    }
}

pub fn seat_struct(s: &syn::ItemStruct, facts: &impl TypeFacts) -> Option<Construct> {
    if has_default_door(&s.attrs) || !attrs_are_proven(&s.attrs) || is_public(&s.vis) {
        return None;
    }
    if !generics_are_proven(&s.generics, facts) {
        return None;
    }
    if s.fields.iter().any(|f| is_public(&f.vis)) {
        return None;
    }
    // A struct that holds a reference is a handle, and a handle answers to the
    // confinement seat or to nothing. So does a struct that declares a
    // *lifetime parameter* at all: [`Construct::Confinement`] is the one seat
    // that may carry a lifetime, and it pays for it with exactly one
    // parameter, an invariant brand, and private fields. Reading only the
    // fields let `struct Handle<'scope>(u64)` seat as an ordinary newtype and
    // skip every one of those conditions — the confinement law made optional
    // by declaring the lifetime and not using it in a field.
    if s.fields.iter().any(|f| has_reference(&f.ty)) || s.generics.lifetimes().next().is_some() {
        return seat_confinement(s);
    }
    let all_phantom = s.fields.iter().all(|f| type_head_is(&f.ty, "PhantomData"));
    if matches!(s.fields, syn::Fields::Unit) || (all_phantom && !s.fields.is_empty()) {
        return Some(Construct::Marker);
    }
    if let syn::Fields::Unnamed(u) = &s.fields {
        // The wrapper seat: exactly one terminal, named by the type around it.
        // A container counts — the wrapper's mint is what proves its shape,
        // which is why a bare container is refused everywhere else.
        return match u.unnamed.len() == 1 && is_wrappable_terminal(&u.unnamed[0].ty) {
            true => Some(Construct::Newtype),
            false => None,
        };
    }
    let syn::Fields::Named(n) = &s.fields else {
        return None;
    };
    // `struct X {}` is not a unit struct — it is a product of nothing, and it
    // satisfies every field condition vacuously.
    if n.named.is_empty() {
        return None;
    }
    let lawful = n.named.iter().all(|f| {
        type_head_is(&f.ty, "PhantomData")
            || (!is_naked(&f.ty) && field_type_is_proven(&f.ty, facts))
    });
    match lawful {
        true => Some(Construct::SealedProduct),
        false => None,
    }
}

/// Whether a held type is one the tree can say anything about.
///
/// The same default-deny as [`Scope::provenance`], applied to what a seat
/// *holds* rather than what it calls. The ambient table alone was a blacklist
/// here too: `fjall::Keyspace` as a field is a database handle whether or not
/// anyone thought to write it down, and it sailed through `is_naked` because
/// no list named it.
///
/// Generic arguments are held as much as the head is. `Vec<Keyspace>` holds a
/// `Keyspace`, so a proven head does not launder an unproven argument.
fn field_type_is_proven(ty: &syn::Type, facts: &impl TypeFacts) -> bool {
    type_is_proven_with(ty, facts, &BTreeSet::new())
}

/// The same question with a set of locally-proven names: a method's own type
/// parameters, once [`generics_are_proven`] has shown every one of them is
/// bounded by a trait the tree declares.
fn type_is_proven_with(ty: &syn::Type, facts: &impl TypeFacts, local: &BTreeSet<String>) -> bool {
    match ty {
        syn::Type::Reference(r) => type_is_proven_with(&r.elem, facts, local),
        syn::Type::Paren(p) => type_is_proven_with(&p.elem, facts, local),
        syn::Type::Group(g) => type_is_proven_with(&g.elem, facts, local),
        syn::Type::Tuple(t) => t.elems.iter().all(|e| type_is_proven_with(e, facts, local)),
        syn::Type::Slice(s) => type_is_proven_with(&s.elem, facts, local),
        syn::Type::Array(a) => type_is_proven_with(&a.elem, facts, local),
        syn::Type::Path(p) => {
            let Some(seg) = p.path.segments.last() else {
                return false;
            };
            let name = seg.ident.to_string();
            if !local.contains(&name)
                && matches!(facts.provenance(&name), Provenance::Unproven)
            {
                return false;
            }
            let syn::PathArguments::AngleBracketed(a) = &seg.arguments else {
                return true;
            };
            a.args.iter().all(|arg| match arg {
                syn::GenericArgument::Type(t) => type_is_proven_with(t, facts, local),
                _ => true,
            })
        }
        // A function pointer, a `dyn Trait`, an `impl Trait`, a raw pointer:
        // a field that can do anything, proven by nobody.
        _ => false,
    }
}

pub fn seat_enum(e: &syn::ItemEnum, facts: &impl TypeFacts) -> Option<Construct> {
    if has_default_door(&e.attrs)
        || has_attr(&e.attrs, "non_exhaustive")
        || !attrs_are_proven(&e.attrs)
        || is_public(&e.vis)
    {
        return None;
    }
    if !generics_are_proven(&e.generics, facts) {
        return None;
    }
    // Only [`Construct::Confinement`] may carry a lifetime, and there is no
    // confinement seat for a sum. A borrowed alternative is a handle wearing a
    // `match` arm.
    if e.generics.lifetimes().next().is_some() {
        return None;
    }
    // An enum with no variants states no alternatives, so it refuses nothing
    // and no `match` over it can be total in any useful sense. Same reason an
    // empty `impl` is refused: a construct that refuses nothing is
    // unconstructible.
    if e.variants.is_empty() {
        return None;
    }
    let lawful = e
        .variants
        .iter()
        .flat_map(|v| v.fields.iter())
        .all(|f| !is_naked(&f.ty) && field_type_is_proven(&f.ty, facts));
    match lawful {
        true => Some(Construct::ClosedSum),
        false => None,
    }
}

/// A closed interface: sealed by a supertrait, methods only, and no method
/// asks a predicate question or refuses with an unproven reason.
pub fn seat_trait(t: &syn::ItemTrait, facts: &impl TypeFacts) -> Option<Construct> {
    // Every other seat that can carry generics proves them. This one did not,
    // so `trait Bound<T>: Sealed` handed out an unbounded parameter — the same
    // hole the method seat had, in the one place that was never given the
    // check.
    if !generics_are_proven(&t.generics, facts) {
        return None;
    }
    // A contract parameterised by a borrow outlives nothing it can name. Only
    // [`Construct::Confinement`] carries a lifetime.
    if t.generics.lifetimes().next().is_some() {
        return None;
    }
    if t.supertraits.is_empty()
        || !attrs_are_proven(&t.attrs)
        || is_public(&t.vis)
        || t.unsafety.is_some()
    {
        return None;
    }
    // A sealed trait is methods and nothing else. An associated const or type
    // is a second seat smuggled inside a contract.
    let clean = t.items.iter().all(|i| {
        let syn::TraitItem::Fn(f) = i else {
            return false;
        };
        // A contract's methods answer to the same return law as an `impl`'s.
        // Checking only the predicate and the `Err` left `fn opaque(self) ->
        // impl Iterator` and `fn n(self) -> u64` seating inside a sealed
        // trait, which is the seat law with its return half missing.
        let proven_return = match &f.sig.output {
            syn::ReturnType::Type(_, ty) => field_type_is_proven(ty, facts),
            syn::ReturnType::Default => false,
        };
        !is_predicate(&f.sig)
            && err_is_closed_sum(&f.sig, facts)
            && returns_lawful(&f.sig)
            && proven_return
    });
    match clean {
        true => Some(Construct::SealedTrait),
        false => None,
    }
}

/// A free function is the composition root or it is nothing. Derivations,
/// transitions, and mints take a receiver and live in an `impl`.
///
/// Necessary conditions only. The seat is meaningless without
/// [`Scope::ambient_sites`], which refuses every effect performed outside it.
pub fn seat_free_fn(f: &syn::ItemFn, is_entry_point: bool) -> Option<Construct> {
    // A `main` in a library file is a function with a familiar name, not the
    // program's entry point, and it shelters nothing.
    if !is_entry_point {
        return None;
    }
    if f.sig.ident != "main"
        || is_public(&f.vis)
        || f.sig.abi.is_some()
        || !attrs_are_proven(&f.attrs)
        || f.sig.unsafety.is_some()
        || f.sig.asyncness.is_some()
    {
        return None;
    }
    // The root wires; it does not compute. A root returning a domain value is
    // doing engine work in the one place effects are permitted.
    let yields_nothing = match &f.sig.output {
        syn::ReturnType::Default => true,
        syn::ReturnType::Type(_, ty) => type_head_is(ty, "ExitCode") || type_head_is(ty, "Result"),
    };
    match yields_nothing && f.sig.inputs.is_empty() {
        true => Some(Construct::CompositionRoot),
        false => None,
    }
}

/// One statement, one name, one thing.
///
/// Refused by default. To pass, a `use` must bind exactly one name, that name
/// must be a type (an uppercase leaf), and the statement must carry no
/// visibility and no attribute. Everything else — a glob, a rename, a group,
/// a lowercase leaf that pulls a free function or a module into bare scope, a
/// `pub use`, a `#[cfg]`-conditional import — is a second authority over what
/// a name in this file means.
pub fn seat_use(u: &syn::ItemUse, facts: &impl TypeFacts) -> Option<Construct> {
    if is_public(&u.vis) || !u.attrs.iter().all(is_doc_attr) {
        return None;
    }
    match use_binds_one_proven_name(&u.tree, facts) {
        true => Some(Construct::Import),
        false => None,
    }
}

/// Exactly one leaf, no glob, no rename, no group, and the leaf names
/// something the program can prove is a type.
///
/// This used to test the leaf's first letter for uppercase — a naming
/// convention standing in for a fact, which is the same defect as deciding an
/// effect from a method's name. What it was reaching for is real: a leaf that
/// is a free function or a module drags a name into bare scope where neither
/// a reader nor this gate can see where it came from. The proof is
/// [`Scope::provenance`], the same door every other surface answers to — the
/// tree declares it, or an approval table names it, or it is unproven.
fn use_binds_one_proven_name(t: &syn::UseTree, facts: &impl TypeFacts) -> bool {
    match t {
        syn::UseTree::Glob(_) | syn::UseTree::Rename(_) | syn::UseTree::Group(_) => false,
        syn::UseTree::Path(p) => use_binds_one_proven_name(&p.tree, facts),
        syn::UseTree::Name(n) => {
            let leaf = n.ident.to_string();
            !matches!(facts.provenance(&leaf), Provenance::Unproven)
                || facts.declares_trait(&leaf)
        }
    }
}

/// A namespace with one authority over where its source lives, no public
/// surface of its own, no body, and no condition attached.
///
/// Refused by default. A `mod x { .. }` is a second file's worth of seats
/// inside another file. A `#[cfg]` on a module makes two programs out of one
/// tree, only one of which any gate ever sees.
pub fn seat_mod(m: &syn::ItemMod) -> Option<Construct> {
    if is_public(&m.vis) || m.content.is_some() {
        return None;
    }
    match m.attrs.iter().all(is_doc_attr) {
        true => Some(Construct::Module),
        false => None,
    }
}

/// A doc comment. The only attribute that changes nothing about what an item
/// is or when it exists.
fn is_doc_attr(a: &syn::Attribute) -> bool {
    a.path().is_ident("doc")
}

/// A method container that opens no second door and no extension point.
pub fn seat_impl(i: &syn::ItemImpl, facts: &impl TypeFacts) -> Option<Construct> {
    if !attrs_are_proven(&i.attrs) || i.items.is_empty() || i.unsafety.is_some() {
        return None;
    }
    // A blanket impl (`impl<T> Trait for T`) grants behaviour to types nobody
    // enumerated.
    let self_is_bare_param = match &*i.self_ty {
        syn::Type::Path(p) => {
            p.path.segments.len() == 1 && {
                let head = &p.path.segments[0].ident;
                i.generics.type_params().any(|tp| tp.ident == *head)
            }
        }
        _ => false,
    };
    if self_is_bare_param {
        return None;
    }
    // Every parameter on the impl is proven, not only the blanket case.
    if !generics_are_proven(&i.generics, facts) {
        return None;
    }
    // And the type being implemented *on* is proven. The trait check below
    // asks what contract is being sealed and never asked what it is sealed
    // over, so `impl Bound for fjall::Keyspace` hung local behaviour on a
    // foreign handle and seated.
    if !field_type_is_proven(&i.self_ty, facts) {
        return None;
    }
    let Some((_, path, _)) = &i.trait_ else {
        return Some(Construct::ImplBlock);
    };
    // A trait this file did not declare is a contract this file cannot seal.
    // Same burden as a door's refusal set: the proof must sit beside the
    // thing it proves, so a trait declared elsewhere cannot be shown sealed
    // from here. No blacklist of foreign names — a name that is not in this
    // file's `Scope` is refused whether or not anyone thought to list it.
    let declared_here = path
        .segments
        .last()
        .is_some_and(|s| facts.declares_trait(&s.ident.to_string()));
    match declared_here {
        true => Some(Construct::ImplBlock),
        false => None,
    }
}

/// Any visibility somebody widened on purpose.
///
/// This used to match only `pub`, which left `pub(crate)`, `pub(super)`, and
/// `pub(in path)` sailing through every "not public" and "all fields private"
/// condition in the file — the visibility half of nearly every seat, escapable
/// by typing four more characters. For a library the crate *is* the program,
/// so a `pub(crate)` field is not private, it is public to everyone who could
/// ever reach it. Only an unwritten visibility is private.
fn is_public(v: &syn::Visibility) -> bool {
    !matches!(v, syn::Visibility::Inherited)
}

/// Attributes that carry no code: the only ones an item may wear.
///
/// An attribute macro *replaces the item it sits on*. What this pass reads is
/// not what compiles, so approving an item while ignoring its attributes
/// approves something nobody has looked at. `#[tokio::main]` rewrites a
/// function body; `#[derive(Deserialize)]` adds a constructor that assigns
/// fields straight past the mint; `#[cfg]` makes two programs out of one tree
/// and shows the gate only one of them. A `derive` is also the one way to
/// obtain an `impl` of a trait the tree never declared, which is exactly what
/// the `impl-block` seat refuses when it is written by hand.
///
/// The same door as every other table: a name gets in by being written here.
const PURE_ATTRS: [&str; 1] = ["doc"];

/// Whether every attribute on an item is one that carries no code.
fn attrs_are_proven(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().all(|a| {
        let [seg] = a.path().segments.iter().collect::<Vec<_>>()[..] else {
            // A path-qualified attribute is somebody else's proc macro.
            return false;
        };
        PURE_ATTRS.contains(&seg.ident.to_string().as_str())
    })
}

fn has_attr(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|a| a.path().is_ident(name))
}

/// `#[derive(Default)]` — a second door around the mint. A derive list the
/// gate cannot parse counts as one: nothing hides in token soup.
fn has_default_door(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        let parsed = a.parse_nested_meta(|m| {
            if m.path.is_ident("Default") {
                found = true;
            }
            Ok(())
        });
        parsed.is_err() || found
    })
}

/// A method that answers yes or no instead of producing a proof.
///
/// Decided from the return type, never from the identifier. The old test
/// matched five word stems — `validate`, `check`, `verify`, `is_valid`,
/// `ensure` — which is the same defect as deciding an effect from a method's
/// name, and it cut both ways: a `validate` returning `Result<Self, Refusal>`
/// is a mint and was refused, while a `total` returning `bool` is a predicate
/// and sailed through.
///
/// A `bool` is a discarded proof. Whatever the method learned, the caller
/// receives one bit and has to trust it; a type that could only be built by
/// passing the check carries the same knowledge and cannot be faked.
fn is_predicate(sig: &syn::Signature) -> bool {
    let syn::ReturnType::Type(_, ty) = &sig.output else {
        return false;
    };
    yields_bool(ty)
}

/// A `bool`, or a `bool` inside the containers that carry one out.
fn yields_bool(ty: &syn::Type) -> bool {
    if type_head_is(ty, "bool") {
        return true;
    }
    if type_head_is(ty, "Option") || type_head_is(ty, "Result") {
        return nth_type_arg(ty, 0).is_some_and(yields_bool);
    }
    false
}

fn has_mut_param(sig: &syn::Signature) -> bool {
    sig.inputs.iter().any(|a| match a {
        syn::FnArg::Typed(t) => matches!(&*t.ty, syn::Type::Reference(r) if r.mutability.is_some()),
        syn::FnArg::Receiver(_) => false,
    })
}

fn returns_result_of_self(sig: &syn::Signature) -> bool {
    let syn::ReturnType::Type(_, ty) = &sig.output else {
        return false;
    };
    type_head_is(ty, "Result") && nth_type_arg(ty, 0).is_some_and(|i| type_head_is(i, "Self"))
}

/// A lawful yield: a domain type, or a `Result` over one. Never a bare
/// primitive, never a bare `Option`, never nothing.
fn returns_lawful(sig: &syn::Signature) -> bool {
    let syn::ReturnType::Type(_, ty) = &sig.output else {
        return false;
    };
    if type_head_is(ty, "Result") {
        return nth_type_arg(ty, 0).is_some_and(|ok| !is_naked(ok));
    }
    !is_naked(ty)
}

/// If the yield is a `Result`, its `Err` names an enum declared in this file
/// that satisfies [`Construct::ClosedSum`].
///
/// Not a capitalisation test. A refusal set that lives in another file cannot
/// be proven closed from here, so it is refused — the burden is on the code to
/// keep a door's refusal set beside the door.
fn err_is_closed_sum(sig: &syn::Signature, facts: &impl TypeFacts) -> bool {
    let syn::ReturnType::Type(_, ty) = &sig.output else {
        return true;
    };
    if !type_head_is(ty, "Result") {
        return true;
    }
    let Some(e) = nth_type_arg(ty, 1) else {
        // `Result<T>` with the error defaulted by an alias: the alias hides
        // which refusal set this door answers with.
        return false;
    };
    let syn::Type::Path(p) = e else {
        return false;
    };
    p.path
        .segments
        .last()
        .is_some_and(|s| facts.is_closed_sum(&s.ident.to_string()))
}

/// Count every type and trait name a tree declares, so a name declared twice
/// can be refused as duplicated rather than silently resolving to one of them.
/// Foreign types whose methods are pure. Consulted by a [`TypeFacts`]
/// implementation when it answers [`Provenance::ForeignPure`].
pub const FOREIGN_PURE: [&str; 21] = [
    "String", "str", "Vec", "VecDeque", "HashMap", "HashSet", "BTreeMap", "BTreeSet", "BinaryHeap",
    "LinkedList", "Option", "Result", "Box", "Rc", "Arc", "Cow", "PhantomData", "Ordering",
    "Duration", "Range", "Iterator",
];

/// The bare terminals a domain type may never expose. Also the receivers whose
/// methods reach nothing: `n.abs()` is arithmetic, not authority.
const NAKED_PRIMITIVES: [&str; 18] = [
    "String", "str", "bool", "char", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16",
    "i32", "i64", "i128", "isize", "f32", "f64",
];
/// A body that is one bare field read. Renaming a field is not a derivation:
/// it hands out the inside of the type under a second name, and every caller
/// then depends on the representation the seat exists to hide.
fn is_accessor(block: &syn::Block) -> bool {
    let [syn::Stmt::Expr(e, None)] = &block.stmts[..] else {
        return false;
    };
    match e {
        syn::Expr::Field(f) => matches!(&*f.base, syn::Expr::Path(p) if p.path.is_ident("self")),
        _ => false,
    }
}

fn is_primitive(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(r) => is_primitive(&r.elem),
        _ => NAKED_PRIMITIVES.iter().any(|p| type_head_is(ty, p)),
    }
}

/// A container carrying no proof of its own shape.
fn is_unproven_collection(ty: &syn::Type) -> bool {
    const CONTAINERS: [&str; 9] = [
        "Vec", "VecDeque", "HashMap", "HashSet", "BTreeMap", "BTreeSet", "BinaryHeap",
        "LinkedList", "Box",
    ];
    match ty {
        syn::Type::Reference(r) => is_unproven_collection(&r.elem),
        syn::Type::Slice(_) | syn::Type::Array(_) => true,
        _ => CONTAINERS.iter().any(|c| type_head_is(ty, c)),
    }
}

/// A terminal a [`Construct::Newtype`] may wrap.
fn is_wrappable_terminal(ty: &syn::Type) -> bool {
    is_primitive(ty) || is_unproven_collection(ty)
}

/// A type that reaches outside the program or holds shared mutable state.
fn is_naked(ty: &syn::Type) -> bool {
    is_primitive(ty)
        || is_unproven_collection(ty)
        || type_head_is(ty, "Option")
}

/// The name of a type, for the receiver environment.
pub fn type_name(ty: &syn::Type) -> String {
    type_head(ty).unwrap_or_else(|| "<anonymous>".to_string())
}

/// The last path segment's identifier, when the type is a plain path.
fn type_head(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        syn::Type::Reference(r) => type_head(&r.elem),
        _ => None,
    }
}

fn type_head_is(ty: &syn::Type, name: &str) -> bool {
    match ty {
        syn::Type::Path(p) => p.path.segments.last().is_some_and(|s| s.ident == name),
        _ => false,
    }
}

fn nth_type_arg(ty: &syn::Type, n: usize) -> Option<&syn::Type> {
    let syn::Type::Path(p) = ty else { return None };
    let syn::PathArguments::AngleBracketed(a) = &p.path.segments.last()?.arguments else {
        return None;
    };
    a.args
        .iter()
        .filter_map(|arg| match arg {
            syn::GenericArgument::Type(t) => Some(t),
            _ => None,
        })
        .nth(n)
}
