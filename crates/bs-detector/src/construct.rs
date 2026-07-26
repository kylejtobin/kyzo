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
//! The detector passes nothing by default. It approves exactly what this file
//! approves — to let a kind of item through, someone must add a construct
//! here, in the open, with conditions, and sign the diff.
//!
//! Two functions can be *called* to obtain an approval: [`Scope::seat_item`]
//! and [`Scope::seat_method`]. Both are in this file, and so is every
//! condition function they delegate to (`seat_struct`, `seat_enum`,
//! `seat_trait`, `seat_free_fn`, `seat_use`, `seat_mod`, `seat_impl`) — those
//! also return `Option<Construct>`, they are private, and nothing outside this
//! module can reach them. `main.rs` contains no function returning
//! `Option<Construct>`.
//!
//! Neither door can decide anything the surrounding file has not proven. A
//! `Result`'s `Err` must name an enum **this file** declares that itself seats
//! as [`Construct::ClosedSum`]. An `impl` may only implement a trait **this
//! file** declares *and* which itself seats as [`Construct::SealedTrait`] —
//! declaration alone authorises nothing. The proof sits beside the thing it
//! proves; a file cannot borrow a proof from a file it cannot see.
//!
//! Approval runs on [`ItemKind`], a closed sum this crate owns — never on
//! `syn::Item` directly. [`ItemKind::of`] is the one place the foreign type is
//! read, and everything it cannot name becomes [`ItemKind::Unknown`], which no
//! condition can approve and which the walk reports as its own
//! `unknown-item-kind` violation. `syn` is pinned exactly so the mirror cannot
//! drift behind a caret range.
//!
//! Conditions are not a blacklist. They are what make an item that construct
//! at all. There is no good newtype and bad newtype: there is newtype, and
//! there is not-a-newtype.

// --- zone-file:imports ---

use std::collections::{BTreeMap, BTreeSet};

use syn::spanned::Spanned;

// --- zone-file:types ---

/// The kinds of item this crate can name. A closed sum we own.
///
/// [`ItemKind::of`] is the only place `syn::Item` is read. Rust requires a
/// wildcard there because `syn::Item` is `#[non_exhaustive]`; that wildcard
/// produces [`ItemKind::Unknown`], which is unconstructible as an approval —
/// no condition function accepts it and the walk reports it as its own
/// violation category. A `syn` upgrade that adds a variant therefore shows up
/// as `unknown-item-kind` in the log rather than as silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Const,
    Enum,
    ExternCrate,
    Fn,
    ForeignMod,
    Impl,
    Macro,
    Mod,
    Static,
    Struct,
    Trait,
    TraitAlias,
    Type,
    Union,
    Use,
    Verbatim,
    /// A `syn::Item` variant this crate has never been taught. Approved by
    /// nothing, forever.
    Unknown,
}

/// The owned view of one item: the kind, and the payload the conditions need.
///
/// [`Seat::of`] is the **only** place in the program that reads `syn::Item`.
/// Everything downstream matches on this enum, which this crate owns and which
/// is therefore exhaustive without a wildcard.
pub enum Seat<'a> {
    Const,
    Enum(&'a syn::ItemEnum),
    ExternCrate,
    Fn(&'a syn::ItemFn),
    ForeignMod,
    Impl(&'a syn::ItemImpl),
    Macro,
    Mod(&'a syn::ItemMod),
    Static,
    Struct(&'a syn::ItemStruct),
    Trait(&'a syn::ItemTrait),
    TraitAlias,
    Type,
    Union,
    Use(&'a syn::ItemUse),
    Verbatim,
    /// A `syn::Item` variant this crate has never been taught.
    Unknown,
}

impl<'a> Seat<'a> {
    /// The one reading of the foreign type. Nothing else in the program
    /// matches on `syn::Item`.
    pub fn of(item: &'a syn::Item) -> Seat<'a> {
        match item {
            syn::Item::Const(_) => Seat::Const,
            syn::Item::Enum(e) => Seat::Enum(e),
            syn::Item::ExternCrate(_) => Seat::ExternCrate,
            syn::Item::Fn(f) => Seat::Fn(f),
            syn::Item::ForeignMod(_) => Seat::ForeignMod,
            syn::Item::Impl(i) => Seat::Impl(i),
            syn::Item::Macro(_) => Seat::Macro,
            syn::Item::Mod(m) => Seat::Mod(m),
            syn::Item::Static(_) => Seat::Static,
            syn::Item::Struct(s) => Seat::Struct(s),
            syn::Item::Trait(t) => Seat::Trait(t),
            syn::Item::TraitAlias(_) => Seat::TraitAlias,
            syn::Item::Type(_) => Seat::Type,
            syn::Item::Union(_) => Seat::Union,
            syn::Item::Use(u) => Seat::Use(u),
            syn::Item::Verbatim(_) => Seat::Verbatim,
            _ => Seat::Unknown,
        }
    }

    /// The kind this seat is. Total over `Seat`, no wildcard.
    pub fn kind(&self) -> ItemKind {
        match self {
            Seat::Const => ItemKind::Const,
            Seat::Enum(_) => ItemKind::Enum,
            Seat::ExternCrate => ItemKind::ExternCrate,
            Seat::Fn(_) => ItemKind::Fn,
            Seat::ForeignMod => ItemKind::ForeignMod,
            Seat::Impl(_) => ItemKind::Impl,
            Seat::Macro => ItemKind::Macro,
            Seat::Mod(_) => ItemKind::Mod,
            Seat::Static => ItemKind::Static,
            Seat::Struct(_) => ItemKind::Struct,
            Seat::Trait(_) => ItemKind::Trait,
            Seat::TraitAlias => ItemKind::TraitAlias,
            Seat::Type => ItemKind::Type,
            Seat::Union => ItemKind::Union,
            Seat::Use(_) => ItemKind::Use,
            Seat::Verbatim => ItemKind::Verbatim,
            Seat::Unknown => ItemKind::Unknown,
        }
    }
}

impl ItemKind {
    /// Every kind this crate can name, `Unknown` last.
    pub const ALL: [ItemKind; 17] = [
        ItemKind::Const,
        ItemKind::Enum,
        ItemKind::ExternCrate,
        ItemKind::Fn,
        ItemKind::ForeignMod,
        ItemKind::Impl,
        ItemKind::Macro,
        ItemKind::Mod,
        ItemKind::Static,
        ItemKind::Struct,
        ItemKind::Trait,
        ItemKind::TraitAlias,
        ItemKind::Type,
        ItemKind::Union,
        ItemKind::Use,
        ItemKind::Verbatim,
        ItemKind::Unknown,
    ];

    /// The kinds mirrored from `syn::Item`, excluding our own `Unknown`.
    pub const MIRRORED: usize = ItemKind::ALL.len() - 1;
}

/// Drift guard, enforced at compile time.
///
/// `build.rs` counts the variants of `pub enum Item` in the pinned `syn`
/// source and hands the number here. If a `syn` upgrade adds a variant, this
/// assertion fails and the crate does not build until [`ItemKind`] and
/// [`Seat`] are taught the new kind. The mirror cannot drift silently.
const _: () = assert!(
    parse_usize(env!("SYN_ITEM_VARIANTS")) == ItemKind::MIRRORED
        || parse_usize(env!("SYN_ITEM_VARIANTS")) == 0,
    "syn::Item's variant set moved: teach ItemKind and Seat the new kind, \
     then update the count. A zero means build.rs could not find the pinned \
     syn source, which is a broken guard, not a passing one."
);

/// `str::parse` is not const, so the guard parses its own digits.
const fn parse_usize(s: &str) -> usize {
    let bytes = s.as_bytes();
    let mut n = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        n = n * 10 + (bytes[i] - b'0') as usize;
        i += 1;
    }
    n
}

impl ItemKind {

    /// The name this kind answers to in a violation.
    pub fn law_name(self) -> &'static str {
        match self {
            ItemKind::Const => "const",
            ItemKind::Enum => "enum",
            ItemKind::ExternCrate => "extern-crate",
            ItemKind::Fn => "fn",
            ItemKind::ForeignMod => "foreign-mod",
            ItemKind::Impl => "impl",
            ItemKind::Macro => "macro",
            ItemKind::Mod => "mod",
            ItemKind::Static => "static",
            ItemKind::Struct => "struct",
            ItemKind::Trait => "trait",
            ItemKind::TraitAlias => "trait-alias",
            ItemKind::Type => "type-alias",
            ItemKind::Union => "union",
            ItemKind::Use => "use",
            ItemKind::Verbatim => "verbatim",
            ItemKind::Unknown => "unknown-item-kind",
        }
    }
}

/// The approved patterns. An item satisfying none of them is a violation.
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
    /// reference field: it must carry a lifetime parameter, every reference
    /// field must use that lifetime, and a `PhantomData` brand must make the
    /// lifetime invariant so the handle cannot be widened.
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
            ],
            Construct::ClosedSum => &[
                "non-exhaustive",
                "primitive-payload",
                "default-door",
                "bare-collection",
                "public-type",
                "unproven-generic",
                "ambient-payload",
            ],
            Construct::Marker => &["default-door", "public-type"],
            Construct::Mint => &[
                "untyped-err",
                "err-not-in-scope",
                "panics",
                "calls-into-self",
                "duplicate-err",
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
            ],
            Construct::Transition => &[
                "borrowed-receiver",
                "prose-err",
                "primitive-return",
                "bare-collection-return",
                "compound-assign",
            ],
            Construct::SealedTrait => &[
                "no-supertrait",
                "predicate",
                "associated-type",
                "public-type",
                "unsafe",
            ],
            Construct::CompositionRoot => &[
                "not-main",
                "public",
                "takes-args",
                "effect-in-method",
                "effect-via-glob",
            ],
            Construct::Import => &["glob", "rename", "pub-use", "group", "lowercase-leaf"],
            Construct::Module => &["path-attr", "inline", "public", "cfg-attr"],
            Construct::Confinement => &[
                "no-lifetime",
                "no-brand",
                "public-field",
                "two-lifetimes",
                "unbranded-reference",
            ],
            Construct::ImplBlock => &[
                "foreign-trait",
                "blanket",
                "empty",
                "unsealed-trait",
                "unsafe",
                "unproven-generic",
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
pub struct Scope {
    /// Enum idents declared in this file that satisfy [`Construct::ClosedSum`].
    closed_sums: BTreeSet<String>,
    /// Every other type name declared in this file: structs, unions, aliases,
    /// and enums that failed the closed-sum conditions.
    declared_not_sums: BTreeSet<String>,
    /// Trait idents declared in this file. An `impl` may only implement one of
    /// these — a contract declared elsewhere cannot be shown sealed here.
    declared_traits: BTreeSet<String>,
    /// Field types of every struct declared in this file, so `self.x.f()`
    /// resolves to the type of `x` rather than to nothing.
    struct_fields: BTreeMap<String, BTreeMap<String, String>>,
    /// What each method declared in this file yields, keyed by owner and
    /// name, so a chain `a.b().c()` keeps its type instead of losing it at
    /// the first link.
    method_returns: BTreeMap<(String, String), String>,
    /// Payload types of every enum variant declared in this file, keyed by
    /// variant name, so a binding taken out of a `match` arm resolves.
    variant_payloads: BTreeMap<String, String>,
    /// Every method declared in this file that is impure — directly, or
    /// because something it calls is. Closed under calls: purity is
    /// transitive, so a method cannot launder an effect by putting one more
    /// call between itself and the world.
    impure_methods: BTreeSet<(String, String)>,
    /// Every method and function declared in scope, so a call to one that is
    /// *not* here is unresolved rather than assumed pure. Free functions are
    /// keyed under [`FREE`].
    declared_methods: BTreeSet<(String, String)>,
    /// Names declared more than once anywhere in the tree.
    ///
    /// Not "declared twice with disagreeing seats" — a duplicate proves
    /// nothing even when both declarations seat identically. Two enums named
    /// `Refusal` that both seat as [`Construct::ClosedSum`] are still two
    /// different refusal sets, and `Result<_, Refusal>` cannot say which one
    /// it answers with. Unresolvable is refused.
    duplicated: BTreeSet<String>,
}

impl Scope {
    /// A scope that has read nothing.
    fn empty() -> Self {
        Scope {
            closed_sums: BTreeSet::new(),
            declared_not_sums: BTreeSet::new(),
            declared_traits: BTreeSet::new(),
            struct_fields: BTreeMap::new(),
            method_returns: BTreeMap::new(),
            variant_payloads: BTreeMap::new(),
            impure_methods: BTreeSet::new(),
            declared_methods: BTreeSet::new(),
            duplicated: BTreeSet::new(),
        }
    }

    /// Read the whole tree's declarations, then decide purity across all of
    /// them. The unit of proof is the tree, not the file: a call that crosses
    /// a module boundary is still a call, and refusing it for ignorance told
    /// the operator nothing about the callee's body.
    ///
    /// A name declared more than once anywhere in the tree proves nothing and
    /// is refused, whether or not the declarations agree.
    pub fn of_tree(files: &[Vec<syn::Item>]) -> Self {
        let mut scope = Scope::empty();
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for items in files {
            count_names(items, &mut seen);
        }
        scope.duplicated = seen
            .into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(name, _)| name)
            .collect();
        for items in files {
            scope.absorb(items);
        }
        let mut edges: BTreeMap<(String, String), BTreeSet<(String, String)>> = BTreeMap::new();
        let mut direct: BTreeSet<(String, String)> = BTreeSet::new();
        for items in files {
            scope.collect_methods(items, &mut edges, &mut direct);
        }
        scope.close_purity(edges, direct);
        scope
    }

    /// Read one file's declarations as a tree of one, so the duplicate-name
    /// law applies to a fixture exactly as it applies to the tree.
    #[cfg(test)]
    pub fn of(items: &[syn::Item]) -> Self {
        Scope::of_tree(std::slice::from_ref(&items.to_vec()))
    }

    /// Fixpoint: impurity flows backwards along every call edge.
    fn close_purity(
        &mut self,
        edges: BTreeMap<(String, String), BTreeSet<(String, String)>>,
        direct: BTreeSet<(String, String)>,
    ) {
        self.impure_methods = direct;
        loop {
            let before = self.impure_methods.len();
            for (caller, callees) in &edges {
                if callees.iter().any(|c| self.impure_methods.contains(c)) {
                    self.impure_methods.insert(caller.clone());
                }
            }
            if self.impure_methods.len() == before {
                break;
            }
        }
    }

    fn collect_methods(
        &mut self,
        items: &[syn::Item],
        edges: &mut BTreeMap<(String, String), BTreeSet<(String, String)>>,
        direct: &mut BTreeSet<(String, String)>,
    ) {
        for item in items {
            if let syn::Item::Mod(m) = item {
                if let Some((_, inner)) = &m.content {
                    self.collect_methods(inner, edges, direct);
                }
                continue;
            }
            if let syn::Item::Trait(t) = item {
                let owner = t.ident.to_string();
                for member in &t.items {
                    let syn::TraitItem::Fn(f) = member else {
                        continue;
                    };
                    let key = (owner.clone(), f.sig.ident.to_string());
                    self.declared_methods.insert(key.clone());
                    let Some(body) = &f.default else {
                        // A method with no body cannot be shown pure from
                        // here, and unproven is refused.
                        direct.insert(key);
                        continue;
                    };
                    let mut env = TypeEnv::new(&owner, self);
                    env.learn_params(&f.sig);
                    env.learn(body);
                    env.learn_patterns(body);
                    let (is_direct, called) = survey_body(body, &env);
                    if is_direct {
                        direct.insert(key.clone());
                    }
                    edges.insert(key, called);
                }
                continue;
            }
            if let syn::Item::Fn(f) = item {
                // A free function belongs to no type, but its body is still a
                // body: a caller must be judged on what it actually does, not
                // on the caller's ignorance of it.
                let key = (FREE.to_string(), f.sig.ident.to_string());
                self.declared_methods.insert(key.clone());
                let mut env = TypeEnv::new(FREE, self);
                env.learn_params(&f.sig);
                env.learn(&f.block);
                env.learn_patterns(&f.block);
                let (is_direct, called) = survey_body(&f.block, &env);
                if is_direct {
                    direct.insert(key.clone());
                }
                edges.insert(key, called);
                self.collect_methods(
                    &f.block
                        .stmts
                        .iter()
                        .filter_map(|st| match st {
                            syn::Stmt::Item(i) => Some(i.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    edges,
                    direct,
                );
                continue;
            }
            let syn::Item::Impl(i) = item else { continue };
            let owner = type_name(&i.self_ty);
            for member in &i.items {
                let syn::ImplItem::Fn(f) = member else {
                    continue;
                };
                let key = (owner.clone(), f.sig.ident.to_string());
                self.declared_methods.insert(key.clone());
                let mut env = TypeEnv::new(&owner, self);
                env.learn_params(&f.sig);
                env.learn(&f.block);
                env.learn_patterns(&f.block);
                let (is_direct, called) = survey_body(&f.block, &env);
                if is_direct {
                    direct.insert(key.clone());
                }
                edges.insert(key, called);
            }
        }
    }

    /// Whether a method declared in this file is known impure.
    fn method_is_impure(&self, owner: &str, name: &str) -> bool {
        self.impure_methods
            .contains(&(owner.to_string(), name.to_string()))
    }

    /// Whether this file declares `owner::name` at all.
    fn declares_method(&self, owner: &str, name: &str) -> bool {
        if self.duplicated.contains(owner) {
            return false;
        }
        self.declared_methods
            .contains(&(owner.to_string(), name.to_string()))
    }

    fn absorb(&mut self, items: &[syn::Item]) {
        for item in items {
            match item {
                syn::Item::Enum(e) => {
                    for v in &e.variants {
                        if let Some(f) = v.fields.iter().next() {
                            if let Some(t) = type_head(&f.ty) {
                                self.variant_payloads.insert(v.ident.to_string(), t);
                            }
                        }
                    }
                    let name = e.ident.to_string();
                    match seat_enum(e, self).is_some() {
                        true => self.closed_sums.insert(name),
                        false => self.declared_not_sums.insert(name),
                    };
                }
                syn::Item::Struct(s) => {
                    let name = s.ident.to_string();
                    // Named fields by name, unnamed by index, so `self.0.f()`
                    // resolves exactly as `self.page.f()` does.
                    let fields: BTreeMap<String, String> = s
                        .fields
                        .iter()
                        .enumerate()
                        .filter_map(|(i, f)| {
                            let key = match &f.ident {
                                Some(id) => id.to_string(),
                                None => i.to_string(),
                            };
                            type_head(&f.ty).map(|t| (key, t))
                        })
                        .collect();
                    self.struct_fields.insert(name.clone(), fields);
                    self.declared_not_sums.insert(name);
                }
                syn::Item::Union(u) => {
                    self.declared_not_sums.insert(u.ident.to_string());
                }
                syn::Item::Type(t) => {
                    self.declared_not_sums.insert(t.ident.to_string());
                }
                syn::Item::Trait(t) => {
                    for member in &t.items {
                        let syn::TraitItem::Fn(f) = member else {
                            continue;
                        };
                        let syn::ReturnType::Type(_, ty) = &f.sig.output else {
                            continue;
                        };
                        let yielded = match type_head(ty).as_deref() {
                            Some("Self") => Some(t.ident.to_string()),
                            Some(other) => Some(other.to_string()),
                            None => None,
                        };
                        if let Some(y) = yielded {
                            self.method_returns
                                .insert((t.ident.to_string(), f.sig.ident.to_string()), y);
                        }
                    }
                    // Only a trait that *seats* as SealedTrait is recorded. A
                    // trait that merely exists proves nothing — an `impl` of
                    // an unsealed contract is the open extension point the
                    // seat was written to refuse.
                    if seat_trait(t, self).is_some() {
                        self.declared_traits.insert(t.ident.to_string());
                    }
                }
                syn::Item::Impl(i) => {
                    let owner = type_name(&i.self_ty);
                    for member in &i.items {
                        let syn::ImplItem::Fn(f) = member else {
                            continue;
                        };
                        let syn::ReturnType::Type(_, ty) = &f.sig.output else {
                            continue;
                        };
                        // A method yielding `Self` yields its owner.
                        let yielded = match type_head(ty).as_deref() {
                            Some("Self") => Some(owner.clone()),
                            Some(other) => Some(other.to_string()),
                            None => None,
                        };
                        if let Some(y) = yielded {
                            self.method_returns
                                .insert((owner.clone(), f.sig.ident.to_string()), y);
                        }
                    }
                }
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        self.absorb(inner);
                    }
                }
                _ => {}
            }
        }
    }

    /// Whether `name` is proven in this file to be a closed sum.
    ///
    /// A name this file never declared cannot be proven here, so it is
    /// refused: the burden is on the code to keep a door's refusal set beside
    /// the door.
    fn is_closed_sum(&self, name: &str) -> bool {
        !self.duplicated.contains(name) && self.closed_sums.contains(name)
    }

    /// The type of `owner`'s field `field`, when this file declared `owner`.
    fn field_type(&self, owner: &str, field: &str) -> Option<String> {
        if self.duplicated.contains(owner) {
            return None;
        }
        self.struct_fields.get(owner)?.get(field).cloned()
    }

    /// What `owner::method` yields, when this file declared it.
    fn method_return(&self, owner: &str, method: &str) -> Option<String> {
        if self.duplicated.contains(owner) {
            return None;
        }
        self.method_returns
            .get(&(owner.to_string(), method.to_string()))
            .cloned()
    }

    /// The payload type of a variant declared in this file.
    fn variant_payload(&self, variant: &str) -> Option<String> {
        self.variant_payloads.get(variant).cloned()
    }

    /// Whether this file declares the trait `name`.
    fn declares_trait(&self, name: &str) -> bool {
        !self.duplicated.contains(name) && self.declared_traits.contains(name)
    }

    /// Every ambient-authority site inside a body, with its line.
    ///
    /// This is the [`Construct::CompositionRoot`] law stated as its inverse:
    /// `fn main` is where effects are lawful, so an effect anywhere else is a
    /// violation at the site that performs it.
    ///
    /// Names are resolved through this file's imports first, so `use std::env
    /// as e;` and `use std::env::var;` are the same finding as `env::var`.
    pub fn ambient_sites(&self, imports: &Imports, block: &syn::Block) -> Vec<(usize, String)> {
        struct Scan<'a> {
            imports: &'a Imports,
            env: TypeEnv<'a>,
            hits: Vec<(usize, String)>,
        }
        impl<'ast> syn::visit::Visit<'ast> for Scan<'_> {
            fn visit_path(&mut self, p: &'ast syn::Path) {
                for s in &p.segments {
                    let name = s.ident.to_string();
                    if self.imports.ambient_names.contains(&name) {
                        let root = self
                            .imports
                            .ambient_reason
                            .get(&name)
                            .cloned()
                            .unwrap_or(name);
                        self.hits
                            .push((line_of(s.ident.span()), format!("ambient {root}")));
                        syn::visit::visit_path(self, p);
                        return;
                    }
                }
                // With a glob in scope, every unqualified name in this file
                // may be one the glob bound — a call, a value, a `let`
                // binding, a type position, anything. The file cannot prove
                // which, so all of them are the glob's.
                if let Some(root) = &self.imports.ambient_glob {
                    if p.segments.len() == 1 && p.leading_colon.is_none() {
                        let bare = &p.segments[0].ident;
                        if !is_local_word(&bare.to_string()) {
                            self.hits.push((
                                line_of(bare.span()),
                                format!("ambient {root} (via glob)"),
                            ));
                        }
                    }
                }
                syn::visit::visit_path(self, p);
            }
            fn visit_expr_method_call(&mut self, c: &'ast syn::ExprMethodCall) {
                // The call reaches the world when its *receiver* does. The
                // method's name never enters the decision: a domain method
                // called `spawn` is not an effect, and a wrapped effect called
                // `advance` is one.
                if let Some(ty) = self.env.resolve(&c.receiver) {
                    if AMBIENT.contains(&ty.as_str()) {
                        self.hits
                            .push((line_of(c.method.span()), format!("ambient {ty}")));
                    }
                }
                syn::visit::visit_expr_method_call(self, c);
            }
            fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
                // With an ambient glob in scope, an unqualified call is one of
                // the names that glob bound until the file proves otherwise,
                // and the file recorded nothing that could prove it.
                if let Some(root) = &self.imports.ambient_glob {
                    if let syn::Expr::Path(p) = c.func.as_ref() {
                        if p.path.segments.len() == 1 {
                            self.hits.push((
                                line_of(p.path.span()),
                                format!("ambient {root} (via glob)"),
                            ));
                        }
                    }
                }
                syn::visit::visit_expr_call(self, c);
            }
            fn visit_macro(&mut self, m: &'ast syn::Macro) {
                if let Some(name) = AMBIENT_MACROS.iter().find(|p| m.path.is_ident(p)) {
                    self.hits
                        .push((line_of(m.path.span()), format!("ambient {name}!")));
                }
                syn::visit::visit_macro(self, m);
            }
        }
        let mut env = TypeEnv::new("Self", self);
        env.learn(block);
        let mut scan = Scan {
            imports,
            env,
            hits: Vec::new(),
        };
        syn::visit::Visit::visit_block(&mut scan, block);
        scan.hits
    }

    // --- zone-file:verbs ---

    /// The only approval door for a file-level item. `None` is a violation.
    ///
    /// Takes [`Seat`], the owned view. `syn::Item` is read once, by
    /// [`Seat::of`], and never again — this match is exhaustive over a sum
    /// this crate owns, with no wildcard anywhere in it.
    pub fn seat_item(&self, seat: &Seat<'_>) -> Option<Construct> {
        match seat {
            // --- approving kinds: conditions decide ---
            Seat::Struct(s) => seat_struct(s, self),
            Seat::Enum(e) => seat_enum(e, self),
            Seat::Trait(t) => seat_trait(t, self),
            Seat::Fn(f) => seat_free_fn(f),
            Seat::Use(u) => seat_use(u),
            Seat::Mod(m) => seat_mod(m),
            Seat::Impl(i) => seat_impl(i, self),

            // --- refusing kinds: one reason each ---
            // A value with no mint: of a domain type it bypasses the smart
            // constructor, of a primitive it is a magic number with a name.
            Seat::Const => None,
            // Shared state with no owner and no epoch. Ambient by construction.
            Seat::Static => None,
            // An alias carries no law: it renames a type without being able to
            // refuse anything the original accepted.
            Seat::Type => None,
            // No discriminant, so no total match is possible over it.
            Seat::Union => None,
            // Code the type system never sees until after expansion.
            Seat::Macro => None,
            // A 2015-edition door. Dependencies arrive through `use`.
            Seat::ExternCrate => None,
            // Unstable surface naming a bound set with no owner.
            Seat::TraitAlias => None,
            // A foreign ABI block: surface the discipline cannot reach across.
            Seat::ForeignMod => None,
            // Tokens `syn` could not structure. Nothing hides in token soup.
            Seat::Verbatim => None,
            // A `syn::Item` this crate has never been taught. Unconstructible
            // as an approval, forever.
            Seat::Unknown => None,
        }
    }

    /// The only approval door for a method. `None` is a violation.
    pub fn seat_method(
        &self,
        sig: &syn::Signature,
        block: Option<&syn::Block>,
        self_ty: &str,
    ) -> Option<Construct> {
        // `unsafe` suspends the discipline the seats exist to enforce, and
        // `async` turns a verb into a state machine whose effects run
        // somewhere else, at a time nobody here decides.
        if sig.unsafety.is_some() || sig.asyncness.is_some() {
            return None;
        }
        if is_predicate(sig) || has_mut_param(sig) || !err_is_closed_sum(sig, self) {
            return None;
        }
        if block.is_some_and(|b| !body_is_pure(b, self, self_ty, sig)) {
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
            if block.is_some_and(|b| calls_into(b, self_ty, self)) {
                return None;
            }
            return Some(Construct::Mint);
        };
        if !returns_lawful(sig) {
            return None;
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
}

// --- zone-file:state ---

/// Every type parameter is proven: bounded, and every bound names a trait
/// this file declares that itself seats as [`Construct::SealedTrait`].
///
/// An unbounded `T` is inhabitable by anything, which makes the type around it
/// a promise about nothing. A bound on a trait declared elsewhere cannot be
/// shown sealed from here — same burden as a door's refusal set.
fn generics_are_proven(g: &syn::Generics, scope: &Scope) -> bool {
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
                    .is_some_and(|seg| scope.declares_trait(&seg.ident.to_string())),
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
/// it; a `PhantomData` field carrying that lifetime, which is what makes it
/// invariant so the handle cannot be widened; all fields private; no `Default`.
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
    // A `PhantomData` carrying that lifetime is what makes it invariant, so
    // the handle cannot be widened to outlive the scope that lent it.
    let branded = s
        .fields
        .iter()
        .any(|f| type_head_is(&f.ty, "PhantomData") && lifetime_of(&f.ty).as_deref() == Some(only.as_str()));
    if !branded {
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

fn seat_struct(s: &syn::ItemStruct, scope: &Scope) -> Option<Construct> {
    if has_default_door(&s.attrs) || has_attr(&s.attrs, "allow") || is_public(&s.vis) {
        return None;
    }
    if !generics_are_proven(&s.generics, scope) {
        return None;
    }
    if s.fields.iter().any(|f| is_public(&f.vis)) {
        return None;
    }
    // A struct that holds a reference is a handle, and a handle answers to the
    // confinement seat or to nothing.
    if s.fields.iter().any(|f| has_reference(&f.ty)) {
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
    let lawful = n
        .named
        .iter()
        .all(|f| type_head_is(&f.ty, "PhantomData") || !is_naked(&f.ty));
    match lawful {
        true => Some(Construct::SealedProduct),
        false => None,
    }
}

fn seat_enum(e: &syn::ItemEnum, scope: &Scope) -> Option<Construct> {
    if has_default_door(&e.attrs)
        || has_attr(&e.attrs, "non_exhaustive")
        || has_attr(&e.attrs, "allow")
        || is_public(&e.vis)
    {
        return None;
    }
    if !generics_are_proven(&e.generics, scope) {
        return None;
    }
    let lawful = e
        .variants
        .iter()
        .flat_map(|v| v.fields.iter())
        .all(|f| !is_naked(&f.ty));
    match lawful {
        true => Some(Construct::ClosedSum),
        false => None,
    }
}

/// A closed interface: sealed by a supertrait, methods only, and no method
/// asks a predicate question or refuses with an unproven reason.
fn seat_trait(t: &syn::ItemTrait, scope: &Scope) -> Option<Construct> {
    if t.supertraits.is_empty()
        || has_attr(&t.attrs, "allow")
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
        !is_predicate(&f.sig) && err_is_closed_sum(&f.sig, scope)
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
fn seat_free_fn(f: &syn::ItemFn) -> Option<Construct> {
    if f.sig.ident != "main"
        || is_public(&f.vis)
        || has_attr(&f.attrs, "allow")
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
fn seat_use(u: &syn::ItemUse) -> Option<Construct> {
    if is_public(&u.vis) || !u.attrs.iter().all(is_doc_attr) {
        return None;
    }
    match use_binds_one_type(&u.tree) {
        true => Some(Construct::Import),
        false => None,
    }
}

/// Exactly one leaf, no glob, no rename, no group, and the leaf names a type.
///
/// A lowercase leaf is a function or a module dragged into bare scope, where
/// a reader — and this gate — can no longer see where it came from. Call it
/// through its path instead.
fn use_binds_one_type(t: &syn::UseTree) -> bool {
    match t {
        syn::UseTree::Glob(_) | syn::UseTree::Rename(_) | syn::UseTree::Group(_) => false,
        syn::UseTree::Path(p) => use_binds_one_type(&p.tree),
        syn::UseTree::Name(n) => n
            .ident
            .to_string()
            .chars()
            .next()
            .is_some_and(char::is_uppercase),
    }
}

/// A namespace with one authority over where its source lives, no public
/// surface of its own, no body, and no condition attached.
///
/// Refused by default. A `mod x { .. }` is a second file's worth of seats
/// inside another file. A `#[cfg]` on a module makes two programs out of one
/// tree, only one of which any gate ever sees.
fn seat_mod(m: &syn::ItemMod) -> Option<Construct> {
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
fn seat_impl(i: &syn::ItemImpl, scope: &Scope) -> Option<Construct> {
    if has_attr(&i.attrs, "allow") || i.items.is_empty() || i.unsafety.is_some() {
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
    if !generics_are_proven(&i.generics, scope) {
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
        .is_some_and(|s| scope.declares_trait(&s.ident.to_string()));
    match declared_here {
        true => Some(Construct::ImplBlock),
        false => None,
    }
}

fn is_public(v: &syn::Visibility) -> bool {
    matches!(v, syn::Visibility::Public(_))
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

fn is_predicate(sig: &syn::Signature) -> bool {
    const WORDS: [&str; 5] = ["validate", "check", "verify", "is_valid", "ensure"];
    let name = sig.ident.to_string();
    WORDS.iter().any(|w| name.starts_with(w))
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
fn err_is_closed_sum(sig: &syn::Signature, scope: &Scope) -> bool {
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
        .is_some_and(|s| scope.is_closed_sum(&s.ident.to_string()))
}

/// Count every type and trait name a tree declares, so a name declared twice
/// can be refused as duplicated rather than silently resolving to one of them.
fn count_names(items: &[syn::Item], seen: &mut BTreeMap<String, usize>) {
    for item in items {
        let name = match item {
            syn::Item::Struct(s) => Some(s.ident.to_string()),
            syn::Item::Enum(e) => Some(e.ident.to_string()),
            syn::Item::Trait(t) => Some(t.ident.to_string()),
            syn::Item::Union(u) => Some(u.ident.to_string()),
            syn::Item::Type(t) => Some(t.ident.to_string()),
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    count_names(inner, seen);
                }
                None
            }
            _ => None,
        };
        if let Some(n) = name {
            *seen.entry(n).or_insert(0) += 1;
        }
    }
}

/// What one file's `use` statements bring into that file's scope.
///
/// Separate from [`Scope`] on purpose. Declarations and the call graph are
/// facts about the tree; an import is a fact about one file. `use std::env as
/// e` in one file says nothing about the name `e` in another, and a glob in
/// one file taints only that file.
pub struct Imports {
    /// Local names bound to a path that reaches outside the program.
    ambient_names: BTreeSet<String>,
    /// Local name to the ambient root it reaches, for the violation message.
    ambient_reason: BTreeMap<String, String>,
    /// The ambient root a glob in this file pulled in, if any.
    ambient_glob: Option<String>,
}

impl Imports {
    /// Read one file's `use` statements.
    pub fn of(items: &[syn::Item]) -> Self {
        let mut imports = Imports {
            ambient_names: BTreeSet::new(),
            ambient_reason: BTreeMap::new(),
            ambient_glob: None,
        };
        imports.absorb(items);
        for root in AMBIENT {
            imports.ambient_names.insert(root.to_string());
            imports
                .ambient_reason
                .insert(root.to_string(), root.to_string());
        }
        imports
    }

    fn absorb(&mut self, items: &[syn::Item]) {
        for item in items {
            match item {
                syn::Item::Use(u) => self.absorb_use(&u.tree, &mut Vec::new()),
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        self.absorb(inner);
                    }
                }
                _ => {}
            }
        }
    }

    fn absorb_use(&mut self, tree: &syn::UseTree, path: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(p) => {
                path.push(p.ident.to_string());
                self.absorb_use(&p.tree, path);
                path.pop();
            }
            syn::UseTree::Group(g) => {
                for t in &g.items {
                    self.absorb_use(t, path);
                }
            }
            syn::UseTree::Name(n) => {
                let leaf = n.ident.to_string();
                self.bind(&leaf, &leaf, path);
            }
            syn::UseTree::Rename(r) => {
                let leaf = r.ident.to_string();
                let local = r.rename.to_string();
                self.bind(&local, &leaf, path);
            }
            syn::UseTree::Glob(_) => {
                // A glob binds names nobody wrote down, so this file cannot
                // say what came in. When the glob reaches outside the crate,
                // every unqualified name in *this file* is that glob's until
                // it is deleted. `crate::*`, `self::*`, and `super::*` stay
                // inside the program by construction — still refused as
                // imports, never called ambient.
                let inside = path
                    .first()
                    .is_some_and(|s| s == "crate" || s == "self" || s == "super");
                if !inside {
                    let root = path.last().cloned().unwrap_or_else(|| "*".to_string());
                    self.ambient_names.insert(root.clone());
                    self.ambient_glob = Some(root);
                }
            }
        }
    }

    fn bind(&mut self, local: &str, leaf: &str, path: &[String]) {
        let reached = path
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(leaf))
            .find(|s| AMBIENT.contains(s));
        if let Some(root) = reached {
            self.ambient_names.insert(local.to_string());
            self.ambient_reason
                .insert(local.to_string(), root.to_string());
        }
    }
}

/// The owner key for a free function: it belongs to no type.
const FREE: &str = "<free>";

/// A local type environment: what each name in a body is known to be.
///
/// Seeded from the signature's declared parameter types, from `let x: T = ..`,
/// from `let x = T::assoc(..)`, from `match` arm bindings, and from `self`. A
/// name this environment cannot resolve is exactly that — unresolved — and
/// unresolved is refused, because purity that cannot be shown is not purity.
struct TypeEnv<'a> {
    bindings: BTreeMap<String, String>,
    self_ty: String,
    scope: &'a Scope,
}

impl<'a> TypeEnv<'a> {
    fn new(self_ty: &str, scope: &'a Scope) -> Self {
        Self {
            bindings: BTreeMap::new(),
            self_ty: self_ty.to_string(),
            scope,
        }
    }

    /// A parameter's declared type is information the file already wrote down.
    fn learn_params(&mut self, sig: &syn::Signature) {
        for arg in &sig.inputs {
            let syn::FnArg::Typed(t) = arg else { continue };
            let syn::Pat::Ident(id) = t.pat.as_ref() else {
                continue;
            };
            if let Some(head) = type_head(&t.ty) {
                self.bindings.insert(id.ident.to_string(), head);
            }
        }
    }

    /// Names bound by a `match` arm carry the payload type of the variant
    /// they destructure, when this file declared that variant.
    fn learn_patterns(&mut self, block: &syn::Block) {
        struct Arms<'a, 'b> {
            env: &'a mut TypeEnv<'b>,
        }
        impl<'ast> syn::visit::Visit<'ast> for Arms<'_, '_> {
            fn visit_arm(&mut self, a: &'ast syn::Arm) {
                if let syn::Pat::TupleStruct(ts) = &a.pat {
                    if let Some(variant) = ts.path.segments.last() {
                        if let Some(ty) = self.env.scope.variant_payload(&variant.ident.to_string())
                        {
                            for p in &ts.elems {
                                if let syn::Pat::Ident(id) = p {
                                    self.env.bindings.insert(id.ident.to_string(), ty.clone());
                                }
                            }
                        }
                    }
                }
                syn::visit::visit_arm(self, a);
            }
        }
        let mut arms = Arms { env: self };
        syn::visit::Visit::visit_block(&mut arms, block);
    }

    fn learn(&mut self, block: &syn::Block) {
        for stmt in &block.stmts {
            let syn::Stmt::Local(l) = stmt else { continue };
            let syn::Pat::Ident(id) = strip_pat(&l.pat) else {
                continue;
            };
            let name = id.ident.to_string();
            if let syn::Pat::Type(t) = &l.pat {
                if let Some(head) = type_head(&t.ty) {
                    self.bindings.insert(name, head);
                    continue;
                }
            }
            if let Some(init) = &l.init {
                if let Some(head) = producing_type(&init.expr) {
                    self.bindings.insert(name, head);
                }
            }
        }
    }

    /// The type a receiver expression is known to be, if it is known at all.
    fn resolve(&self, expr: &syn::Expr) -> Option<String> {
        match expr {
            syn::Expr::Path(p) => {
                let seg = p.path.segments.last()?;
                let name = seg.ident.to_string();
                if name == "self" {
                    return Some(self.self_ty.clone());
                }
                if p.path.segments.len() > 1 {
                    return Some(p.path.segments[p.path.segments.len() - 2].ident.to_string());
                }
                self.bindings.get(&name).cloned()
            }
            syn::Expr::Field(f) => {
                let owner = self.resolve(&f.base)?;
                let key = match &f.member {
                    syn::Member::Named(n) => n.to_string(),
                    syn::Member::Unnamed(i) => i.index.to_string(),
                };
                self.scope.field_type(&owner, &key)
            }
            syn::Expr::MethodCall(c) => {
                // Follow the chain: resolve the receiver, then ask what that
                // type's method yields. A link this file never declared ends
                // the chain at nothing, which is refused.
                let owner = self.resolve(&c.receiver)?;
                self.scope.method_return(&owner, &c.method.to_string())
            }
            syn::Expr::Reference(r) => self.resolve(&r.expr),
            syn::Expr::Paren(p) => self.resolve(&p.expr),
            syn::Expr::Call(c) => producing_type(&syn::Expr::Call(c.clone())),
            _ => None,
        }
    }
}

/// Strip a typed pattern down to the ident.
fn strip_pat(p: &syn::Pat) -> &syn::Pat {
    match p {
        syn::Pat::Type(t) => strip_pat(&t.pat),
        other => other,
    }
}

/// The type named by a producing expression: `T::new(..)` yields `T`.
fn producing_type(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Call(c) => match c.func.as_ref() {
            syn::Expr::Path(p) if p.path.segments.len() >= 2 => {
                Some(p.path.segments[p.path.segments.len() - 2].ident.to_string())
            }
            _ => None,
        },
        syn::Expr::Struct(st) => st.path.segments.last().map(|s| s.ident.to_string()),
        syn::Expr::Reference(r) => producing_type(&r.expr),
        syn::Expr::Paren(p) => producing_type(&p.expr),
        _ => None,
    }
}

/// No panic, no effect, no hidden mutation — decided from types, never names,
/// and closed under calls.
///
/// A body is pure when it is not directly impure and everything it calls is
/// pure. Purity is transitive: an effect one call away is an effect.
fn body_is_pure(
    block: &syn::Block,
    scope: &Scope,
    self_ty: &str,
    sig: &syn::Signature,
) -> bool {
    let mut env = TypeEnv::new(self_ty, scope);
    env.learn_params(sig);
    env.learn(block);
    env.learn_patterns(block);
    let (direct, called) = survey_body(block, &env);
    !direct && !called.iter().any(|(o, m)| scope.method_is_impure(o, m))
}

/// One pass over a body: is it *directly* impure, and what does it call?
///
/// Direct impurity is what the body does itself — reach an ambient path,
/// panic, write to the world, assign, or open `unsafe`. A call to something
/// this file declares becomes an edge instead, so purity can be closed under
/// calls afterwards. A call this file cannot resolve is direct impurity: the
/// file offers no proof, and unproven is refused.
fn survey_body(block: &syn::Block, env: &TypeEnv<'_>) -> (bool, BTreeSet<(String, String)>) {
    struct Scan<'a> {
        env: &'a TypeEnv<'a>,
        direct: bool,
        called: BTreeSet<(String, String)>,
    }
    impl<'ast> syn::visit::Visit<'ast> for Scan<'_> {
        fn visit_expr_method_call(&mut self, c: &'ast syn::ExprMethodCall) {
            let name = c.method.to_string();
            match self.env.resolve(&c.receiver) {
                Some(ty) if AMBIENT.contains(&ty.as_str()) => self.direct = true,
                Some(ty) if self.env.scope.declares_method(&ty, &name) => {
                    self.called.insert((ty, name));
                }
                _ => self.direct = true,
            }
            syn::visit::visit_expr_method_call(self, c);
        }
        fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
            // `T::assoc(..)` and `free(..)` are calls. Leaving them unsurveyed
            // let every constructor and every helper launder an effect.
            if let syn::Expr::Path(p) = c.func.as_ref() {
                let segs: Vec<String> =
                    p.path.segments.iter().map(|s| s.ident.to_string()).collect();
                match segs.as_slice() {
                    [name] => {
                        // A tuple-struct or enum-variant constructor is a
                        // value, not a call into a body.
                        let is_ctor = name.chars().next().is_some_and(char::is_uppercase);
                        if !is_ctor {
                            match self.env.scope.declares_method(FREE, name) {
                                true => {
                                    self.called.insert((FREE.to_string(), name.clone()));
                                }
                                false => self.direct = true,
                            }
                        }
                    }
                    [.., owner, name] => {
                        let is_variant = name.chars().next().is_some_and(char::is_uppercase);
                        if !is_variant {
                            // `Self::helper()` is a call on the surrounding
                            // type. Reading it as an unknown owner let a
                            // method launder an effect through its own
                            // associated function.
                            let owner = match owner.as_str() {
                                "Self" => self.env.self_ty.clone(),
                                other => other.to_string(),
                            };
                            match self.env.scope.declares_method(&owner, name) {
                                true => {
                                    self.called.insert((owner, name.clone()));
                                }
                                false => self.direct = true,
                            }
                        }
                    }
                    [] => {}
                }
            }
            syn::visit::visit_expr_call(self, c);
        }
        fn visit_macro(&mut self, m: &'ast syn::Macro) {
            if PANIC_MACROS.iter().any(|p| m.path.is_ident(p))
                || AMBIENT_MACROS.iter().any(|p| m.path.is_ident(p))
            {
                self.direct = true;
            }
            syn::visit::visit_macro(self, m);
        }
        fn visit_path(&mut self, p: &'ast syn::Path) {
            if p.segments
                .iter()
                .any(|s| AMBIENT.iter().any(|a| s.ident == a))
            {
                self.direct = true;
            }
            syn::visit::visit_path(self, p);
        }
        fn visit_expr_assign(&mut self, a: &'ast syn::ExprAssign) {
            self.direct = true;
            syn::visit::visit_expr_assign(self, a);
        }
        fn visit_expr_binary(&mut self, b: &'ast syn::ExprBinary) {
            // `x += 1` mutates exactly as `x = x + 1` does.
            if matches!(
                b.op,
                syn::BinOp::AddAssign(_)
                    | syn::BinOp::SubAssign(_)
                    | syn::BinOp::MulAssign(_)
                    | syn::BinOp::DivAssign(_)
                    | syn::BinOp::RemAssign(_)
                    | syn::BinOp::BitXorAssign(_)
                    | syn::BinOp::BitAndAssign(_)
                    | syn::BinOp::BitOrAssign(_)
                    | syn::BinOp::ShlAssign(_)
                    | syn::BinOp::ShrAssign(_)
            ) {
                self.direct = true;
            }
            syn::visit::visit_expr_binary(self, b);
        }
        fn visit_expr_unsafe(&mut self, u: &'ast syn::ExprUnsafe) {
            self.direct = true;
            syn::visit::visit_expr_unsafe(self, u);
        }
    }
    let mut scan = Scan {
        env,
        direct: false,
        called: BTreeSet::new(),
    };
    syn::visit::Visit::visit_block(&mut scan, block);
    (scan.direct, scan.called)
}

/// Whether a body calls a method on `owner` — the type it is building.
fn calls_into(block: &syn::Block, owner: &str, scope: &Scope) -> bool {
    struct Scan<'a> {
        env: TypeEnv<'a>,
        owner: String,
        hit: bool,
    }
    impl<'ast> syn::visit::Visit<'ast> for Scan<'_> {
        fn visit_expr_method_call(&mut self, c: &'ast syn::ExprMethodCall) {
            if self.env.resolve(&c.receiver).as_deref() == Some(self.owner.as_str()) {
                self.hit = true;
            }
            syn::visit::visit_expr_method_call(self, c);
        }
    }
    let mut env = TypeEnv::new(owner, scope);
    env.learn(block);
    let mut scan = Scan {
        env,
        owner: owner.to_string(),
        hit: false,
    };
    syn::visit::Visit::visit_block(&mut scan, block);
    scan.hit
}

/// A body that is exactly `self.field` or `&self.field`: a getter.
fn is_accessor(block: &syn::Block) -> bool {
    let [syn::Stmt::Expr(expr, None)] = block.stmts.as_slice() else {
        return false;
    };
    let inner = match expr {
        syn::Expr::Reference(r) => r.expr.as_ref(),
        other => other,
    };
    matches!(inner, syn::Expr::Field(f) if matches!(f.base.as_ref(), syn::Expr::Path(p) if p.path.is_ident("self")))
}

/// Every surface that reaches outside the program. Lawful only in the
/// composition root.
const AMBIENT: [&str; 52] = [
    // modules
    "env", "fs", "io", "net", "process", "thread", "time", "sync", "ffi", "os", "path", "alloc",
    "rand", "tokio", "signal",
    // filesystem
    "File", "OpenOptions", "DirBuilder", "ReadDir", "Metadata", "Permissions", "PathBuf",
    "TempDir",
    // clock and entropy
    "SystemTime", "Instant", "UNIX_EPOCH", "random", "ThreadRng", "OsRng",
    // network
    "TcpStream", "TcpListener", "UdpSocket", "SocketAddr", "UnixStream", "UnixListener",
    // process and threads
    "Command", "Child", "JoinHandle", "Builder", "exit", "abort",
    // shared mutable state: ambient authority with no owner
    "Mutex", "RwLock", "RefCell", "Cell", "OnceLock", "OnceCell", "LazyLock", "AtomicUsize",
    "AtomicBool", "AtomicU64",
    // terminal
    "stdout",
];

/// Macros that write to the world.
const AMBIENT_MACROS: [&str; 5] = ["print", "println", "eprint", "eprintln", "dbg"];

/// Macros that abandon the program.
const PANIC_MACROS: [&str; 4] = ["panic", "todo", "unimplemented", "unreachable"];

fn line_of(span: proc_macro2::Span) -> usize {
    span.start().line
}

/// Names the language owns, which a glob cannot have bound.
fn is_local_word(name: &str) -> bool {
    const KEYWORDS: [&str; 8] = ["self", "Self", "crate", "super", "None", "Some", "Ok", "Err"];
    KEYWORDS.contains(&name)
}

/// The bare terminals a domain type may never expose.
fn is_primitive(ty: &syn::Type) -> bool {
    const NAKED: [&str; 18] = [
        "String", "str", "bool", "char", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16",
        "i32", "i64", "i128", "isize", "f32", "f64",
    ];
    match ty {
        syn::Type::Reference(r) => is_primitive(&r.elem),
        _ => NAKED.iter().any(|p| type_head_is(ty, p)),
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
fn is_ambient_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(r) => is_ambient_type(&r.elem),
        syn::Type::Path(p) => p
            .path
            .segments
            .iter()
            .any(|seg| AMBIENT.contains(&seg.ident.to_string().as_str())),
        _ => false,
    }
}

/// A type no domain seat may hold naked.
fn is_naked(ty: &syn::Type) -> bool {
    is_primitive(ty)
        || is_unproven_collection(ty)
        || type_head_is(ty, "Option")
        || is_ambient_type(ty)
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
