/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The grammar: the operator-approved law seat of the default-deny gate.
//!
//! `grammar.toml` declares four kinds of law:
//! - banned-shape predicates (waivable and absolute),
//! - the kind table (TRUTH item 1): every `syn::Item` kind and every
//!   impl/trait interior kind is SEATED to named constructs or CONDEMNED
//!   with its own law entry — a kind in neither list refuses to load,
//!   because a silent kind is the hole everything else drains into,
//! - the structural constructs each seated kind must classify against,
//! - declared receiverless-fn seats (`[seats].fns`), each binding file,
//!   fn path, AND a blake3 site hash — a declared file greens nothing,
//!   only declared fns do.
//!
//! Fixture law (item 1): every construct must ship
//! `fixtures/<name>.pass.rs` and `fixtures/<name>.deny.rs` (zero-freedom
//! cells are exempt from deny — nothing can hide in them), and every
//! condemned kind must ship `fixtures/<kind>.deny.rs`. A missing fixture
//! is a load error; an unrecognized file in `fixtures/` is a load error,
//! so nothing rides along unexecuted.
//!
//! `laws.toml` retains every lie-shape law with the mechanism that
//! catches it now; a check running without a law entry is a coverage
//! violation and the run refuses.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::engines::shape;

/// Every kind of item syn can hand the classifier, closed at the pinned
/// syn major version. Impl/trait interior kinds are first-class entries;
/// `Verbatim` names the unparseable-token kind at ALL positions (item,
/// impl interior, trait interior). Growing this enum is an operator
/// ruling, not a convenience.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KindName {
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
    ImplConst,
    ImplFn,
    ImplType,
    ImplMacro,
    TraitConst,
    TraitFn,
    TraitType,
    TraitMacro,
}

/// The full closed set the kind table must cover. The totality proof at
/// load walks exactly this list.
pub const ALL_KINDS: [KindName; 24] = [
    KindName::Const,
    KindName::Enum,
    KindName::ExternCrate,
    KindName::Fn,
    KindName::ForeignMod,
    KindName::Impl,
    KindName::Macro,
    KindName::Mod,
    KindName::Static,
    KindName::Struct,
    KindName::Trait,
    KindName::TraitAlias,
    KindName::Type,
    KindName::Union,
    KindName::Use,
    KindName::Verbatim,
    KindName::ImplConst,
    KindName::ImplFn,
    KindName::ImplType,
    KindName::ImplMacro,
    KindName::TraitConst,
    KindName::TraitFn,
    KindName::TraitType,
    KindName::TraitMacro,
];

impl KindName {
    /// The kebab name as the grammar file and fixtures spell it.
    pub fn kebab(self) -> &'static str {
        match self {
            KindName::Const => "const",
            KindName::Enum => "enum",
            KindName::ExternCrate => "extern-crate",
            KindName::Fn => "fn",
            KindName::ForeignMod => "foreign-mod",
            KindName::Impl => "impl",
            KindName::Macro => "macro",
            KindName::Mod => "mod",
            KindName::Static => "static",
            KindName::Struct => "struct",
            KindName::Trait => "trait",
            KindName::TraitAlias => "trait-alias",
            KindName::Type => "type",
            KindName::Union => "union",
            KindName::Use => "use",
            KindName::Verbatim => "verbatim",
            KindName::ImplConst => "impl-const",
            KindName::ImplFn => "impl-fn",
            KindName::ImplType => "impl-type",
            KindName::ImplMacro => "impl-macro",
            KindName::TraitConst => "trait-const",
            KindName::TraitFn => "trait-fn",
            KindName::TraitType => "trait-type",
            KindName::TraitMacro => "trait-macro",
        }
    }

    /// The laws.toml / check name a condemnation of this kind reports
    /// under. `None` means the kind has no registered condemnation law
    /// and may not appear in the condemned list.
    pub fn condemned_law_name(self) -> Option<&'static str> {
        match self {
            KindName::ExternCrate => Some("extern_crate"),
            KindName::ForeignMod => Some("foreign_mod"),
            KindName::Union => Some("union"),
            KindName::TraitAlias => Some("trait_alias"),
            KindName::Verbatim => Some("verbatim"),
            KindName::Macro => Some("macro_item"),
            KindName::ImplMacro => Some("impl_item_macro"),
            KindName::TraitMacro => Some("trait_item_macro"),
            KindName::Const
            | KindName::Enum
            | KindName::Fn
            | KindName::Impl
            | KindName::Mod
            | KindName::Static
            | KindName::Struct
            | KindName::Trait
            | KindName::Type
            | KindName::Use
            | KindName::ImplConst
            | KindName::ImplFn
            | KindName::ImplType
            | KindName::TraitConst
            | KindName::TraitFn
            | KindName::TraitType => None,
        }
    }

    /// Which construct family a seat for this kind must come from.
    /// `None` for kinds that cannot be seated (no construct family
    /// exists for them — they are condemned or nothing).
    pub fn family(self) -> Option<ConstructFamily> {
        match self {
            KindName::Struct => Some(ConstructFamily::Struct),
            KindName::Enum => Some(ConstructFamily::Enum),
            KindName::Fn | KindName::ImplFn | KindName::TraitFn => Some(ConstructFamily::Fn),
            KindName::Type | KindName::ImplType | KindName::TraitType => {
                Some(ConstructFamily::Alias)
            }
            KindName::Use => Some(ConstructFamily::Import),
            KindName::Const
            | KindName::Static
            | KindName::ImplConst
            | KindName::TraitConst => Some(ConstructFamily::Constant),
            KindName::Mod => Some(ConstructFamily::Module),
            KindName::Impl => Some(ConstructFamily::ImplContainer),
            KindName::Trait => Some(ConstructFamily::TraitContainer),
            KindName::ExternCrate
            | KindName::ForeignMod
            | KindName::Macro
            | KindName::TraitAlias
            | KindName::Union
            | KindName::Verbatim
            | KindName::ImplMacro
            | KindName::TraitMacro => None,
        }
    }
}

/// The item family a construct classifies within. Closed: growing this
/// enum is an operator ruling, not a convenience.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConstructFamily {
    Struct,
    Enum,
    Fn,
    Alias,
    Import,
    Constant,
    Module,
    ImplContainer,
    TraitContainer,
}

/// The structural rule a construct demands. Closed sum; each variant has
/// exactly one implementation in `classify.rs` and an executed deny
/// fixture proving its in-cell refusal — except zero-freedom cells,
/// which have no interior for a violation to hide in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructuralRule {
    /// newtype-scalar: tuple struct, exactly one field, private.
    TupleSinglePrivateField,
    /// sealed-struct: named fields, all private, none string-terminal
    /// (item 4's structural walk decides string-carrying).
    NamedAllPrivateNoStringTerminal,
    /// unit-marker: a unit struct. Zero interior freedom — deny-exempt.
    UnitStruct,
    /// sum-type: no variant field resolves to a string terminal.
    NoStringVariantFields,
    /// alias: the aliased type resolves to no banned terminal.
    AliasNoBannedTerminal,
    /// import: no glob (`use ...::*` defeats rename/import accounting).
    ImportNoGlob,
    /// constant: `static mut` is red, absolute.
    ConstantNoStaticMut,
    /// module: any `mod` item seats here. `#[path = …]` is banned under
    /// bans_attribute `path` (item 5) — one jurisdiction, not this rule.
    ModuleNoPathAttr,
    /// containers: interior items classify individually; condemned
    /// interior kinds (macro, verbatim) red inside the container.
    InteriorsClassify,
    /// composition-root: `main` body is let-bindings of calls, `?`, one
    /// tail call (POSITIVE body law); `if`/`match`/`loop`/`await` red.
    CompositionRootBody,
    /// derivation (`&self`): assignment, `await`/`async`, `unsafe` red.
    DerivationBans,
    /// transition (`&mut self`): nested place assign, `await`/`async` red.
    TransitionBans,
    /// consuming-verb (`self`, return not Self): nested place assign,
    /// `await`/`async` red; returning Self is a builder chain, red.
    ConsumingVerbBans,
    /// admission-door (receiverless in impl, returns Self-shaped):
    /// `await`/`async` red.
    AdmissionDoorBans,
    /// declared-fn: receiverless fn matching a `[seats].fns` entry by
    /// file, fn path, and site hash; drift red; async only where the
    /// seat says `io = true`.
    DeclaredFnSeat,
}

impl StructuralRule {
    /// The family this rule can lawfully be attached to.
    pub fn family(self) -> ConstructFamily {
        match self {
            StructuralRule::TupleSinglePrivateField
            | StructuralRule::NamedAllPrivateNoStringTerminal
            | StructuralRule::UnitStruct => ConstructFamily::Struct,
            StructuralRule::NoStringVariantFields => ConstructFamily::Enum,
            StructuralRule::AliasNoBannedTerminal => ConstructFamily::Alias,
            StructuralRule::ImportNoGlob => ConstructFamily::Import,
            StructuralRule::ConstantNoStaticMut => ConstructFamily::Constant,
            StructuralRule::ModuleNoPathAttr => ConstructFamily::Module,
            // InteriorsClassify serves both container families; family
            // compatibility for it is checked specially in load.
            StructuralRule::InteriorsClassify => ConstructFamily::ImplContainer,
            StructuralRule::CompositionRootBody
            | StructuralRule::DerivationBans
            | StructuralRule::TransitionBans
            | StructuralRule::ConsumingVerbBans
            | StructuralRule::AdmissionDoorBans
            | StructuralRule::DeclaredFnSeat => ConstructFamily::Fn,
        }
    }

    /// Zero-interior-freedom cells cannot host a violation, so the
    /// preamble exempts them from in-cell refusal and therefore from a
    /// deny fixture. Everything else must be able to refuse.
    pub fn deny_exempt(self) -> bool {
        // UnitStruct: zero interior. ModuleNoPathAttr: #[path] moved to
        // bans_attribute `path` (item 5) — the module seat itself has no
        // remaining in-cell refusal.
        matches!(
            self,
            StructuralRule::UnitStruct | StructuralRule::ModuleNoPathAttr
        )
    }

    /// Body-ban names this rule still enforces inside `classify.rs`.
    /// Construct-scoped bans in `construct.bans` must be disjoint from
    /// this list — otherwise one ban has two authorities (item 5 tip 511).
    pub fn body_bans_enforced_in_classify(self) -> &'static [&'static str] {
        match self {
            // Derivation still refuses `unsafe` in-cell (deny fixture).
            // assignment / await / nested_place_assign live only in
            // construct.bans + run.rs span containment.
            StructuralRule::DerivationBans => &["unsafe"],
            StructuralRule::TransitionBans
            | StructuralRule::ConsumingVerbBans
            | StructuralRule::AdmissionDoorBans
            | StructuralRule::CompositionRootBody
            | StructuralRule::DeclaredFnSeat
            | StructuralRule::TupleSinglePrivateField
            | StructuralRule::NamedAllPrivateNoStringTerminal
            | StructuralRule::UnitStruct
            | StructuralRule::NoStringVariantFields
            | StructuralRule::AliasNoBannedTerminal
            | StructuralRule::ImportNoGlob
            | StructuralRule::ConstantNoStaticMut
            | StructuralRule::ModuleNoPathAttr
            | StructuralRule::InteriorsClassify => &[],
        }
    }

    /// Prove this rule is parse-fact-disjoint from `other` (item 3).
    /// Same-kind pairs only: a pair without a proof case is a load Err —
    /// two constructs that can both match one item is the soft drain.
    /// Identical rules are never disjoint.
    pub fn disjoint_with(self, other: Self) -> Result<(), &'static str> {
        use StructuralRule::*;
        if self == other {
            return Err("identical rules share every parse fact — not disjoint");
        }
        match (self, other) {
            // Struct partition: tuple / named / unit are mutually exclusive
            // field shapes (item 3).
            (TupleSinglePrivateField, NamedAllPrivateNoStringTerminal)
            | (NamedAllPrivateNoStringTerminal, TupleSinglePrivateField)
            | (TupleSinglePrivateField, UnitStruct)
            | (UnitStruct, TupleSinglePrivateField)
            | (NamedAllPrivateNoStringTerminal, UnitStruct)
            | (UnitStruct, NamedAllPrivateNoStringTerminal) => Ok(()),

            // Fn partition (item 2): receiver form + return shape + the
            // composition-root / declared-fn seat discriminators. Every
            // non-identical pair of skeleton rules has a proof case here.
            (CompositionRootBody, DerivationBans)
            | (DerivationBans, CompositionRootBody)
            | (CompositionRootBody, TransitionBans)
            | (TransitionBans, CompositionRootBody)
            | (CompositionRootBody, ConsumingVerbBans)
            | (ConsumingVerbBans, CompositionRootBody)
            | (CompositionRootBody, AdmissionDoorBans)
            | (AdmissionDoorBans, CompositionRootBody)
            | (CompositionRootBody, DeclaredFnSeat)
            | (DeclaredFnSeat, CompositionRootBody)
            | (DerivationBans, TransitionBans)
            | (TransitionBans, DerivationBans)
            | (DerivationBans, ConsumingVerbBans)
            | (ConsumingVerbBans, DerivationBans)
            | (DerivationBans, AdmissionDoorBans)
            | (AdmissionDoorBans, DerivationBans)
            | (DerivationBans, DeclaredFnSeat)
            | (DeclaredFnSeat, DerivationBans)
            | (TransitionBans, ConsumingVerbBans)
            | (ConsumingVerbBans, TransitionBans)
            | (TransitionBans, AdmissionDoorBans)
            | (AdmissionDoorBans, TransitionBans)
            | (TransitionBans, DeclaredFnSeat)
            | (DeclaredFnSeat, TransitionBans)
            | (ConsumingVerbBans, AdmissionDoorBans)
            | (AdmissionDoorBans, ConsumingVerbBans)
            | (ConsumingVerbBans, DeclaredFnSeat)
            | (DeclaredFnSeat, ConsumingVerbBans)
            | (AdmissionDoorBans, DeclaredFnSeat)
            | (DeclaredFnSeat, AdmissionDoorBans) => Ok(()),

            // Cross-family pairs are not competed at one item; callers
            // skip unequal ConstructFamily. Same-family singles (one enum
            // rule, one alias rule, …) never reach a pair. Anything else
            // same-family without a case above is an unproven overlap.
            _unproven_same_kind_pair => Err(
                "no disjointness proof for this same-kind rule pair — grow the match or refuse the grammar",
            ),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructDef {
    pub name: String,
    pub kind: ConstructFamily,
    pub rule: StructuralRule,
    /// Construct-scoped bans (TRUTH item 5 jurisdiction (c)). Empty by
    /// default; attributed by span containment in `run.rs`.
    #[serde(default)]
    pub bans: Vec<String>,
}

/// One declared receiverless-fn seat: file + fn path + site hash, all
/// three, or the seat matches nothing. `io = true` is the ONLY lawful
/// home of `async`/`await` (the transport boundary).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FnSeat {
    pub file: String,
    pub fn_path: String,
    pub site_hash: String,
    pub io: bool,
}

/// A host crate's sealed-public-door import allowlist (item 2 relational).
/// Every `use` whose first path segment is not `crate`/`super`/`self` must
/// name a segment in `allowed_imports`, or it is red.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDoor {
    /// Repo-root-relative directory prefix, e.g. `crates/kyzo-bin/`.
    pub path: String,
    pub allowed_imports: Vec<String>,
}

/// Config-once seat for one binary crate (item 2 relational): env/args
/// call sites under `path` must number exactly one, and that one must
/// sit inside the fn named by `fn_path` (module::fn or bare fn ident).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigOnceSeat {
    pub path: String,
    pub fn_path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KindsSection {
    condemned: Vec<KindName>,
    seated: BTreeMap<KindName, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SeatsSection {
    fns: Vec<FnSeat>,
    // Required keys (no serde default): empty lists refuse at load; silent
    // missing-section soft-pass is the hole item 2 closed.
    hosts: Vec<HostDoor>,
    config_once: Vec<ConfigOnceSeat>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrammarFile {
    bans_absolute: Vec<String>,
    bans: Vec<String>,
    bans_attribute: Vec<String>,
    kinds: KindsSection,
    construct: Vec<ConstructDef>,
    seats: SeatsSection,
}

/// What the kind table says about one kind.
pub enum Disposition<'a> {
    /// Red on sight, reported under this laws.toml check name.
    Condemned(&'static str),
    /// May classify only as one of these construct names.
    Seated(&'a [String]),
}

/// The loaded, validated grammar.
///
/// Fields are private (TRUTH item 9). [`Grammar::load`] is the sole
/// admission door; engines read through accessors.
pub struct Grammar {
    /// Banned shapes no waiver can cover (expression jurisdiction).
    bans_absolute: Vec<String>,
    /// Banned shapes a waiver may cover, one entry per hit (expression).
    bans: Vec<String>,
    /// Attribute-jurisdiction bans (item- and crate-level attributes).
    bans_attribute: Vec<String>,
    constructs: Vec<ConstructDef>,
    condemned: BTreeSet<KindName>,
    seated: BTreeMap<KindName, Vec<String>>,
    fn_seats: Vec<FnSeat>,
    hosts: Vec<HostDoor>,
    config_once: Vec<ConfigOnceSeat>,
}

impl Grammar {
    /// Load and validate. Refuses: a ban with no registered matcher or no
    /// `bite_<name>` detonation; a name in two ban jurisdictions; a matcher
    /// in no jurisdiction (TRUTH item 5); a duplicate or orphaned construct;
    /// an empty section; a kind neither seated nor condemned (or in both
    /// lists); a seat naming an unknown construct or one from the wrong
    /// family; a condemned kind with no registered law name; a malformed
    /// fn seat; and any fixture-law violation (missing pass/deny fixture,
    /// unexpected file in `fixtures/`).
    pub fn load(path: &Path, bite_src: &str, fixtures_dir: &Path) -> Result<Grammar> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let parsed: GrammarFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if parsed.bans.is_empty()
            || parsed.bans_absolute.is_empty()
            || parsed.bans_attribute.is_empty()
            || parsed.construct.is_empty()
        {
            bail!("grammar with an empty section certifies nothing — refuse to load");
        }

        // Item 5: every ban in exactly one jurisdiction. The same name on
        // two constructs is still one jurisdiction (construct.bans); a
        // second *kind* of seat is the soft drain.
        let mut jurisdiction: BTreeMap<String, &'static str> = BTreeMap::new();
        let mut place = |name: &str, seat: &'static str| -> Result<()> {
            match jurisdiction.get(name) {
                Some(prior) if *prior != seat => {
                    bail!(
                        "ban `{name}` is in both `{prior}` and `{seat}` — one ban, one jurisdiction"
                    );
                }
                Some(_) => Ok(()),
                None => {
                    jurisdiction.insert(name.to_string(), seat);
                    Ok(())
                }
            }
        };
        for name in &parsed.bans_absolute {
            place(name.as_str(), "bans_absolute")?;
        }
        for name in &parsed.bans {
            place(name.as_str(), "bans")?;
        }
        for name in &parsed.bans_attribute {
            place(name.as_str(), "bans_attribute")?;
        }
        for c in &parsed.construct {
            for name in &c.bans {
                place(name.as_str(), "construct.bans")?;
            }
        }
        for name in jurisdiction.keys() {
            if shape::matcher_by_name(name).is_none() {
                bail!("ban `{name}` has no registered matcher — a law that cannot fire");
            }
            if !bite_src.contains(&format!("fn bite_{name}")) {
                bail!("ban `{name}` has no bite proof — an unproven law may not run");
            }
        }
        // Every registered matcher is a ban somewhere, or the matcher is
        // ambient law with no jurisdiction (item 5 Proof: nested_place_assign
        // in no list → load Err).
        for m in shape::MATCHERS {
            if !jurisdiction.contains_key(m.name) {
                bail!(
                    "ban `{}` is in no list — ambient scope is forbidden; refuse to load",
                    m.name
                );
            }
        }

        let mut constructs_by_name: BTreeMap<&str, &ConstructDef> = BTreeMap::new();
        for c in &parsed.construct {
            if constructs_by_name.insert(c.name.as_str(), c).is_some() {
                bail!("duplicate construct `{}`", c.name);
            }
            let compatible = c.rule.family() == c.kind
                || (c.rule == StructuralRule::InteriorsClassify
                    && matches!(
                        c.kind,
                        ConstructFamily::ImplContainer | ConstructFamily::TraitContainer
                    ));
            if !compatible {
                bail!(
                    "construct `{}` binds rule {:?} to family {:?} — a rule cannot judge a family it was not written for",
                    c.name,
                    c.rule,
                    c.kind
                );
            }
            // Item 5 tip 511: a construct.bans name also BodyBan-enforced in
            // classify is dual authority for one ban — refuse.
            for ban in &c.bans {
                if c.rule
                    .body_bans_enforced_in_classify()
                    .iter()
                    .any(|b| *b == ban.as_str())
                {
                    bail!(
                        "ban `{ban}` on construct `{}` is also BodyBan-enforced in classify — dual authority, refuse",
                        c.name
                    );
                }
            }
        }

        // Item 3: every same-kind construct pair is proven disjoint from
        // parse facts. A pair without a proof case → load Err (two
        // named-all-private struct rules is the executed specimen).
        for (i, a) in parsed.construct.iter().enumerate() {
            for b in parsed.construct.iter().skip(i + 1) {
                if a.kind != b.kind {
                    continue;
                }
                if let Err(why) = a.rule.disjoint_with(b.rule) {
                    bail!(
                        "constructs `{}` and `{}` (kind {:?}) are not proven disjoint: {why}",
                        a.name,
                        b.name,
                        a.kind
                    );
                }
            }
        }

        // Item 1 totality: every kind seated or condemned; nothing silent,
        // nothing double-booked.
        let condemned: BTreeSet<KindName> = parsed.kinds.condemned.iter().copied().collect();
        for kind in &condemned {
            if kind.condemned_law_name().is_none() {
                bail!(
                    "kind `{}` is condemned but has no registered condemnation law — a red with no law entry",
                    kind.kebab()
                );
            }
        }
        for kind in ALL_KINDS {
            let is_condemned = condemned.contains(&kind);
            let is_seated = parsed.kinds.seated.contains_key(&kind);
            if is_condemned && is_seated {
                bail!(
                    "kind `{}` is both seated and condemned — one kind, one disposition",
                    kind.kebab()
                );
            }
            if !is_condemned && !is_seated {
                bail!(
                    "kind `{}` is neither seated nor condemned — a silent kind is the drain every law pours into; refuse to load",
                    kind.kebab()
                );
            }
        }
        for (kind, seats) in &parsed.kinds.seated {
            if seats.is_empty() {
                bail!("kind `{}` is seated to nothing — that is silence in a chair", kind.kebab());
            }
            let Some(family) = kind.family() else {
                bail!(
                    "kind `{}` has no construct family and cannot be seated — condemn it or grow the law",
                    kind.kebab()
                );
            };
            for seat in seats {
                let Some(c) = constructs_by_name.get(seat.as_str()) else {
                    bail!("kind `{}` is seated to unknown construct `{seat}`", kind.kebab());
                };
                let compatible = c.kind == family
                    || (family == ConstructFamily::TraitContainer
                        && c.kind == ConstructFamily::TraitContainer);
                if !compatible {
                    bail!(
                        "kind `{}` (family {:?}) is seated to construct `{seat}` of family {:?}",
                        kind.kebab(),
                        family,
                        c.kind
                    );
                }
            }
        }
        // No orphan constructs: a construct no kind can reach is dead law.
        for c in &parsed.construct {
            let referenced = parsed
                .kinds
                .seated
                .values()
                .any(|seats| seats.iter().any(|s| s == &c.name));
            if !referenced {
                bail!("construct `{}` is seated for no kind — dead law, refuse", c.name);
            }
        }

        // Declared fn seats: all three coordinates, well-formed hash.
        let mut seat_keys: BTreeSet<(&str, &str)> = BTreeSet::new();
        for s in &parsed.seats.fns {
            if s.file.trim().is_empty() || s.fn_path.trim().is_empty() {
                bail!("a [seats].fns entry with an empty file or fn_path matches nothing");
            }
            if s.site_hash.len() != 64 || !s.site_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!(
                    "seat `{}` in `{}` has a malformed site_hash — 64 hex chars or nothing",
                    s.fn_path,
                    s.file
                );
            }
            if !seat_keys.insert((s.file.as_str(), s.fn_path.as_str())) {
                bail!("duplicate seat for `{}` in `{}`", s.fn_path, s.file);
            }
        }

        // Item 2 relational seats: empty host/config_once lists are silence
        // (sealed-public-door and config-once would never fire). Refuse.
        if parsed.seats.hosts.is_empty() {
            bail!(
                "[seats].hosts is empty — sealed-public-door with no host is a silent law; refuse"
            );
        }
        if parsed.seats.config_once.is_empty() {
            bail!(
                "[seats].config_once is empty — config-once with no binary is a silent law; refuse"
            );
        }
        let mut host_paths: BTreeSet<&str> = BTreeSet::new();
        for h in &parsed.seats.hosts {
            if h.path.trim().is_empty() {
                bail!("a [seats].hosts entry with an empty path matches nothing");
            }
            if !h.path.ends_with('/') {
                bail!(
                    "host path `{}` must end in `/` — a prefix without a slash silently overlaps neighbors",
                    h.path
                );
            }
            if !host_paths.insert(h.path.as_str()) {
                bail!("duplicate [seats].hosts path `{}`", h.path);
            }
        }
        let mut cfg_paths: BTreeSet<&str> = BTreeSet::new();
        for c in &parsed.seats.config_once {
            if c.path.trim().is_empty() || c.fn_path.trim().is_empty() {
                bail!("a [seats].config_once entry with an empty path or fn_path matches nothing");
            }
            if !c.path.ends_with('/') {
                bail!(
                    "config_once path `{}` must end in `/`",
                    c.path
                );
            }
            if !cfg_paths.insert(c.path.as_str()) {
                bail!("duplicate [seats].config_once path `{}`", c.path);
            }
        }

        // Fixture law: pass+deny per construct (zero-freedom cells are
        // deny-exempt), deny per condemned kind, deny per construct-scoped
        // ban (item 5), nothing unrecognized.
        let mut expected: BTreeSet<String> = BTreeSet::new();
        for c in &parsed.construct {
            expected.insert(format!("{}.pass.rs", c.name));
            if !c.rule.deny_exempt() {
                expected.insert(format!("{}.deny.rs", c.name));
            }
            for ban in &c.bans {
                expected.insert(format!("{ban}.deny.rs"));
            }
        }
        for kind in &condemned {
            expected.insert(format!("{}.deny.rs", kind.kebab()));
        }
        // Tip 689 anti-fake-up gap-fill: seated kinds whose hard
        // `unclassified-<kind>` check is NOT already proven by a construct
        // deny/pass under full classify. Closed list — do not mint pairs that
        // duplicate an existing construct fixture (fraudulent double-proof).
        // Vacuous seats (const / mod / impl-const / trait-const) ship PASS only;
        // a DENY that cannot detonate would itself be a fake-up.
        for name in [
            "unclassified-const.pass.rs",
            "unclassified-impl-const.pass.rs",
            "unclassified-trait-const.pass.rs",
            "unclassified-impl-type.pass.rs",
            "unclassified-impl-type.deny.rs",
            "unclassified-trait-type.pass.rs",
            "unclassified-trait-type.deny.rs",
            "unclassified-trait-fn.deny.rs",
        ] {
            expected.insert(name.to_string());
        }
        let entries = std::fs::read_dir(fixtures_dir)
            .with_context(|| format!("reading fixtures dir {}", fixtures_dir.display()))?;
        let mut present: BTreeSet<String> = BTreeSet::new();
        for entry in entries {
            let entry = entry.with_context(|| "walking fixtures dir")?;
            present.insert(entry.file_name().to_string_lossy().to_string());
        }
        for want in &expected {
            if !present.contains(want) {
                bail!("fixture `{want}` is missing — an unexecuted rule is an unproven rule");
            }
        }
        for have in &present {
            if !expected.contains(have) {
                bail!("fixtures/ contains unrecognized `{have}` — nothing rides along unexecuted");
            }
        }

        Ok(Grammar {
            bans_absolute: parsed.bans_absolute,
            bans: parsed.bans,
            bans_attribute: parsed.bans_attribute,
            constructs: parsed.construct,
            condemned,
            seated: parsed.kinds.seated,
            fn_seats: parsed.seats.fns,
            hosts: parsed.seats.hosts,
            config_once: parsed.seats.config_once,
        })
    }

    /// The kind table's ruling for one kind. Totality was proven at load,
    /// so a `None` here can only mean the table was mutated post-load —
    /// callers treat it as red, never as pass.
    pub fn disposition(&self, kind: KindName) -> Option<Disposition<'_>> {
        if self.condemned.contains(&kind) {
            return kind.condemned_law_name().map(Disposition::Condemned);
        }
        self.seated.get(&kind).map(|s| Disposition::Seated(s.as_slice()))
    }

    /// Whether `construct` is a lawful seat for `kind`.
    pub fn seat_allows(&self, kind: KindName, construct: &str) -> bool {
        self.seated
            .get(&kind)
            .is_some_and(|seats| seats.iter().any(|s| s == construct))
    }

    /// The declared seat for a receiverless fn, if any.
    pub fn fn_seat(&self, file: &str, fn_path: &str) -> Option<&FnSeat> {
        self.fn_seats
            .iter()
            .find(|s| s.file == file && s.fn_path == fn_path)
    }

    pub fn bans_absolute(&self) -> &[String] {
        &self.bans_absolute
    }

    pub fn bans(&self) -> &[String] {
        &self.bans
    }

    pub fn bans_attribute(&self) -> &[String] {
        &self.bans_attribute
    }

    pub fn constructs(&self) -> &[ConstructDef] {
        &self.constructs
    }

    pub fn condemned(&self) -> &BTreeSet<KindName> {
        &self.condemned
    }

    pub fn hosts(&self) -> &[HostDoor] {
        &self.hosts
    }

    pub fn config_once(&self) -> &[ConfigOnceSeat] {
        &self.config_once
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LawEntry {
    name: String,
    law: String,
    caught_by: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LawsFile {
    law: Vec<LawEntry>,
}

/// The retained law ledger: check name → law text. `require` is the
/// mechanical form of the coverage law: a check about to run with no law
/// entry refuses the whole run.
pub struct Laws {
    by_name: BTreeMap<String, String>,
}

impl Laws {
    pub fn load(path: &Path) -> Result<Laws> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let parsed: LawsFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let mut by_name = BTreeMap::new();
        for e in parsed.law {
            if e.caught_by.trim().is_empty() {
                bail!("law `{}` names no catching mechanism — coverage unproven", e.name);
            }
            if by_name.insert(e.name.clone(), e.law).is_some() {
                bail!("duplicate law entry `{}`", e.name);
            }
        }
        Ok(Laws { by_name })
    }

    pub fn require(&self, check: &str) -> Result<&str> {
        match self.by_name.get(check) {
            Some(law) => Ok(law.as_str()),
            None => bail!(
                "check `{check}` has no entry in laws.toml — a check without a retained law may not run"
            ),
        }
    }

    /// Lookup for citation resolve (TRUTH item 7): a laws.toml law name
    /// citation hashes this text.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.by_name.get(name).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn crate_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn real_grammar_text() -> String {
        std::fs::read_to_string(crate_dir().join("grammar.toml")).expect("grammar.toml readable")
    }

    fn real_bite_src() -> String {
        std::fs::read_to_string(crate_dir().join("tests/bite_proofs.rs")).expect("bite src")
    }

    fn load_text(text: &str) -> Result<Grammar> {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(text.as_bytes()).expect("write fixture");
        Grammar::load(f.path(), &real_bite_src(), &crate_dir().join("fixtures"))
    }

    /// Clone the live fixture dir, apply one mutation, load against it.
    fn load_with_mutated_fixtures(mutate: impl FnOnce(&std::path::Path)) -> Result<Grammar> {
        let dir = tempfile::tempdir().expect("tempdir");
        for entry in std::fs::read_dir(crate_dir().join("fixtures")).expect("fixtures dir") {
            let entry = entry.expect("entry");
            std::fs::copy(entry.path(), dir.path().join(entry.file_name())).expect("copy");
        }
        mutate(dir.path());
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(real_grammar_text().as_bytes()).expect("write");
        Grammar::load(f.path(), &real_bite_src(), dir.path())
    }

    #[test]
    fn the_real_grammar_loads() {
        let g = load_text(&real_grammar_text()).expect("the checked-in grammar must load");
        assert_eq!(g.condemned().len(), 8, "exactly the eight condemned kinds");
    }

    #[test]
    fn proof_const_kind_neither_seated_nor_condemned_is_a_load_error() {
        // TRUTH item 1 Proof fixture: `const` kind silent → load Err.
        // Anchor on the seated-table line break so `impl-const`/`trait-const`
        // are not mangled by a substring replace.
        let text = real_grammar_text().replace("\nconst = [\"constant\"]\n", "\n");
        let e = load_text(&text);
        assert!(e.is_err(), "a silent kind must refuse to load");
        let msg = format!("{:?}", e.err());
        assert!(msg.contains("neither seated nor condemned"), "refusal names the law: {msg}");
    }

    #[test]
    fn a_kind_in_both_lists_is_a_load_error() {
        // Seat a kind that is already condemned (and has a condemnation law).
        // Adding a seated-only kind to `condemned` fails earlier: seated kinds
        // have no registered condemnation law name.
        let text = real_grammar_text().replace(
            "[kinds.seated]\n",
            "[kinds.seated]\nunion = [\"sum-type\"]\n",
        );
        let e = load_text(&text);
        assert!(e.is_err(), "seated+condemned must refuse");
        let msg = format!("{:?}", e.err());
        assert!(msg.contains("both seated and condemned"), "refusal names the law: {msg}");
    }

    #[test]
    fn item_3_proof_two_named_all_private_struct_rules_is_a_load_error() {
        // Item 3 Proof: Grammar declaring two named-all-private struct rules
        // → load Err (identical parse facts — not disjoint).
        let text = real_grammar_text()
            .replace(
                "struct = [\"newtype-scalar\", \"sealed-struct\", \"unit-marker\"]\n",
                "struct = [\"newtype-scalar\", \"sealed-struct\", \"unit-marker\", \"sealed-struct-twin\"]\n",
            )
            .replace(
                "name = \"sealed-struct\"\nkind = \"struct\"\nrule = \"named-all-private-no-string-terminal\"\n",
                "name = \"sealed-struct\"\nkind = \"struct\"\nrule = \"named-all-private-no-string-terminal\"\n\n[[construct]]\nname = \"sealed-struct-twin\"\nkind = \"struct\"\nrule = \"named-all-private-no-string-terminal\"\n",
            );
        let dir = tempfile::tempdir().expect("tempdir");
        for entry in std::fs::read_dir(crate_dir().join("fixtures")).expect("fixtures dir") {
            let entry = entry.expect("entry");
            std::fs::copy(entry.path(), dir.path().join(entry.file_name())).expect("copy");
        }
        std::fs::copy(
            crate_dir().join("fixtures/sealed-struct.pass.rs"),
            dir.path().join("sealed-struct-twin.pass.rs"),
        )
        .expect("twin pass");
        std::fs::copy(
            crate_dir().join("fixtures/sealed-struct.deny.rs"),
            dir.path().join("sealed-struct-twin.deny.rs"),
        )
        .expect("twin deny");
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(text.as_bytes()).expect("write");
        let err = Grammar::load(f.path(), &real_bite_src(), dir.path());
        assert!(err.is_err(), "two named-all-private rules must refuse");
        let msg = format!("{:?}", err.err());
        assert!(
            msg.contains("not proven disjoint") || msg.contains("identical rules"),
            "refusal names the disjoint law: {msg}"
        );
    }

    #[test]
    fn a_missing_fixture_is_a_load_error() {
        // Copy the real fixtures, delete one deny, expect refusal.
        let e = load_with_mutated_fixtures(|dir| {
            std::fs::remove_file(dir.join("sealed-struct.deny.rs")).expect("remove");
        });
        assert!(e.is_err(), "missing fixture must refuse to load");
    }

    #[test]
    fn an_unrecognized_fixture_file_is_a_load_error() {
        let e = load_with_mutated_fixtures(|dir| {
            std::fs::write(dir.join("rogue.rs"), "fn smuggled() {}\n").expect("write rogue");
        });
        assert!(e.is_err(), "a file the fixture law does not expect must refuse");
    }

    #[test]
    fn item_5_proof_nested_place_assign_in_no_list_is_a_load_error() {
        // TRUTH item 5 Proof: nested_place_assign in no jurisdiction → load Err.
        let text = real_grammar_text()
            .replace(
                "bans = [\"nested_place_assign\", \"await\"]\n",
                "bans = [\"await\"]\n",
            );
        let e = load_text(&text);
        assert!(e.is_err(), "ambient nested_place_assign must refuse to load");
        let msg = format!("{:?}", e.err());
        assert!(
            msg.contains("nested_place_assign") && msg.contains("no list"),
            "refusal names the jurisdiction law: {msg}"
        );
    }

    #[test]
    fn item_5_proof_ban_in_two_jurisdictions_is_a_load_error() {
        let text = real_grammar_text().replace(
            "bans_attribute = [\n  \"allow_dead_code\",",
            "bans_attribute = [\n  \"unwrap\",\n  \"allow_dead_code\",",
        );
        let e = load_text(&text);
        assert!(e.is_err(), "dual jurisdiction must refuse");
        let msg = format!("{:?}", e.err());
        assert!(
            msg.contains("both") || msg.contains("unwrap"),
            "refusal names the dual seat: {msg}"
        );
    }

    #[test]
    fn item_5_proof_cross_mechanism_dual_is_refused() {
        // Tip 511: construct.bans ∩ classify BodyBan for the same name → refuse.
        // Live Transition/ConsumingVerb/Admission enforce nothing in classify
        // for await/nested_place (empty). Derivation still enforces `unsafe`
        // in classify — listing it on construct.bans is the dual specimen.
        assert!(
            StructuralRule::TransitionBans
                .body_bans_enforced_in_classify()
                .is_empty()
        );
        assert!(
            StructuralRule::ConsumingVerbBans
                .body_bans_enforced_in_classify()
                .is_empty()
        );
        assert!(
            StructuralRule::AdmissionDoorBans
                .body_bans_enforced_in_classify()
                .is_empty()
        );
        assert_eq!(
            StructuralRule::DerivationBans.body_bans_enforced_in_classify(),
            &["unsafe"]
        );
        // Direct refuse path used by Grammar::load:
        let refuse = |rule: StructuralRule, ban: &str| {
            rule.body_bans_enforced_in_classify()
                .iter()
                .any(|b| *b == ban)
        };
        assert!(
            refuse(StructuralRule::DerivationBans, "unsafe"),
            "unsafe BodyBan ∩ construct.bans must be detectable"
        );
        assert!(
            !refuse(StructuralRule::TransitionBans, "nested_place_assign"),
            "nested_place must not remain BodyBan-enforced"
        );
        assert!(!refuse(StructuralRule::DerivationBans, "assignment"));
        assert!(!refuse(StructuralRule::DerivationBans, "await"));
    }

    #[test]
    fn grammar_refuses_unknown_ban_and_missing_bite_proof() {
        let no_matcher = real_grammar_text().replace("\"unwrap\",", "\"no_such_matcher\",");
        assert!(load_text(&no_matcher).is_err(), "unknown matcher must refuse");

        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(real_grammar_text().as_bytes()).expect("write");
        let e = Grammar::load(f.path(), "fn bite_nothing() {}", &crate_dir().join("fixtures"));
        assert!(e.is_err(), "ban without bite proof must refuse");
    }

    #[test]
    fn laws_require_refuses_a_lawless_check() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(
            b"[[law]]\nname = \"unwrap\"\nlaw = \"a panic where refusal is owed\"\ncaught_by = \"grammar ban\"\n",
        )
        .expect("write fixture");
        let laws = Laws::load(f.path()).expect("loads");
        assert!(laws.require("unwrap").is_ok());
        assert!(laws.require("ghost_check").is_err(), "no law entry = refuse");
    }
}
