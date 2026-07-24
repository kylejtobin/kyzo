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

use crate::boundary::{Label, RelPath};
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

/// Refuse reasons for [`StructuralRule::disjoint_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisjointRefuse {
    IdenticalRules,
    UnprovenPair,
}

impl std::fmt::Display for DisjointRefuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DisjointRefuse::IdenticalRules => {
                f.write_str("identical rules share every parse fact — not disjoint")
            }
            DisjointRefuse::UnprovenPair => f.write_str(
                "no disjointness proof for this same-kind rule pair — grow the match or refuse the grammar",
            ),
        }
    }
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
    pub fn disjoint_with(self, other: Self) -> Result<(), DisjointRefuse> {
        use StructuralRule::{
            AdmissionDoorBans, CompositionRootBody, ConsumingVerbBans, DeclaredFnSeat,
            DerivationBans, NamedAllPrivateNoStringTerminal, TransitionBans,
            TupleSinglePrivateField, UnitStruct,
        };
        if self == other {
            return Err(DisjointRefuse::IdenticalRules);
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
            _unproven_same_kind_pair => Err(DisjointRefuse::UnprovenPair),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructDef {
    name: Label,
    kind: ConstructFamily,
    rule: StructuralRule,
    /// Construct-scoped bans (TRUTH item 5 jurisdiction (c)). Required key —
    /// empty list is written `bans = []`, never serde-default silence.
    bans: Vec<Label>,
}

impl ConstructDef {
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn kind(&self) -> ConstructFamily {
        self.kind
    }

    pub fn rule(&self) -> StructuralRule {
        self.rule
    }

    pub fn bans(&self) -> &[Label] {
        &self.bans
    }
}

/// One declared receiverless-fn seat: file + fn path + site hash, all
/// three, or the seat matches nothing. `io = true` is the ONLY lawful
/// home of `async`/`await` (the transport boundary).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FnSeat {
    file: RelPath,
    fn_path: Label,
    site_hash: Label,
    io: bool,
}

impl FnSeat {
    pub fn file(&self) -> &str {
        self.file.as_str()
    }

    pub fn fn_path(&self) -> &str {
        self.fn_path.as_str()
    }

    pub fn site_hash(&self) -> &str {
        self.site_hash.as_str()
    }

    pub fn io(&self) -> bool {
        self.io
    }
}

/// A host crate's sealed-public-door import allowlist (item 2 relational).
/// Every `use` whose first path segment is not `crate`/`super`/`self` must
/// name a segment in `allowed_imports`, or it is red.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDoor {
    /// Repo-root-relative directory prefix, e.g. `crates/kyzo-bin/`.
    path: RelPath,
    allowed_imports: Vec<Label>,
}

impl HostDoor {
    /// Sole non-deserialize admission (tests / harnesses).
    pub fn admit(path: impl Into<RelPath>, allowed_imports: Vec<Label>) -> Self {
        Self {
            path: path.into(),
            allowed_imports,
        }
    }

    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    pub fn allowed_imports(&self) -> &[Label] {
        &self.allowed_imports
    }
}

/// Config-once seat for one binary crate (item 2 relational): env/args
/// call sites under `path` must number exactly one, and that one must
/// sit inside the fn named by `fn_path` (module::fn or bare fn ident).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigOnceSeat {
    path: RelPath,
    fn_path: Label,
}

impl ConfigOnceSeat {
    /// Sole non-deserialize admission (tests / harnesses).
    pub fn admit(path: impl Into<RelPath>, fn_path: impl Into<Label>) -> Self {
        Self {
            path: path.into(),
            fn_path: fn_path.into(),
        }
    }

    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    pub fn fn_path(&self) -> &str {
        self.fn_path.as_str()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KindsSection {
    condemned: Vec<KindName>,
    seated: BTreeMap<KindName, Vec<Label>>,
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
    bans_absolute: Vec<Label>,
    bans: Vec<Label>,
    bans_attribute: Vec<Label>,
    kinds: KindsSection,
    construct: Vec<ConstructDef>,
    seats: SeatsSection,
}

/// What the kind table says about one kind.
pub enum Disposition<'a> {
    /// Red on sight, reported under this laws.toml check name.
    Condemned { law: Label },
    /// May classify only as one of these construct names.
    Seated(&'a [Label]),
}

/// The loaded, validated grammar.
///
/// Fields are private (TRUTH item 9). [`Grammar::load`] is the sole
/// admission door; engines read through accessors.
pub struct Grammar {
    /// Banned shapes no waiver can cover (expression jurisdiction).
    bans_absolute: Vec<Label>,
    /// Banned shapes a waiver may cover, one entry per hit (expression).
    bans: Vec<Label>,
    /// Attribute-jurisdiction bans (item- and crate-level attributes).
    bans_attribute: Vec<Label>,
    constructs: Vec<ConstructDef>,
    condemned: BTreeSet<KindName>,
    seated: BTreeMap<KindName, Vec<Label>>,
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
            if shape::MATCHER_LOOKUP.by_name(name).is_none() {
                bail!("ban `{name}` has no registered matcher — a law that cannot fire");
            }
            // Exact door: `fn bite_{name}(` on a trimmed line. Soft
            // `contains("fn bite_unwrap")` matched `fn bite_unwrap_or` and
            // let a deleted bite ride on a prefix neighbor (tip 686 drain).
            let bite_fn = format!("fn bite_{name}(");
            if !bite_src
                .lines()
                .any(|line| line.trim_start().starts_with(bite_fn.as_str()))
            {
                bail!("ban `{name}` has no bite proof — an unproven law may not run");
            }
        }
        // Every registered matcher is a ban somewhere, or the matcher is
        // ambient law with no jurisdiction (item 5 Proof: nested_place_assign
        // in no list → load Err).
        for m in shape::MATCHERS {
            if !jurisdiction.contains_key(m.name()) {
                bail!(
                    "ban `{}` is in no list — ambient scope is forbidden; refuse to load",
                    m.name()
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
            if s.file.as_str().trim().is_empty() || s.fn_path.as_str().trim().is_empty() {
                bail!("a [seats].fns entry with an empty file or fn_path matches nothing");
            }
            if s.site_hash.as_str().len() != 64
                || !s.site_hash.as_str().chars().all(|c| c.is_ascii_hexdigit())
            {
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
            if h.path.as_str().trim().is_empty() {
                bail!("a [seats].hosts entry with an empty path matches nothing");
            }
            if !h.path.ends_with("/") {
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
            if c.path.as_str().trim().is_empty() || c.fn_path.as_str().trim().is_empty() {
                bail!("a [seats].config_once entry with an empty path or fn_path matches nothing");
            }
            if !c.path.ends_with("/") {
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
            let name = entry.file_name().to_string_lossy().to_string();
            let ft = entry
                .file_type()
                .with_context(|| format!("fixtures/ entry `{name}` file_type"))?;
            // Refuse, do not skip: a directory/symlink named like a fixture
            // would satisfy presence and silent-green an unproven rule.
            if !ft.is_file() {
                bail!(
                    "fixtures/ entry `{name}` is not a regular file — a directory or symlink cannot prove a rule"
                );
            }
            let meta = entry
                .metadata()
                .with_context(|| format!("fixtures/ entry `{name}` metadata"))?;
            if meta.len() == 0 {
                bail!("fixtures/ `{name}` is empty — an empty specimen proves nothing");
            }
            present.insert(name);
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
            return kind.condemned_law_name().map(|law| Disposition::Condemned {
                law: Label::admit(law),
            });
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
            .find(|s| s.file.as_str() == file && s.fn_path.as_str() == fn_path)
    }

    pub fn bans_absolute(&self) -> &[Label] {
        &self.bans_absolute
    }

    pub fn bans(&self) -> &[Label] {
        &self.bans
    }

    pub fn bans_attribute(&self) -> &[Label] {
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
    name: Label,
    law: Label,
    caught_by: Label,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignEntry {
    name: Label,
    artifact: RelPath,
    freshness_bound_secs: u64,
    sources: Vec<RelPath>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LawsFile {
    law: Vec<LawEntry>,
    /// Required key — empty ledger is `campaign = []`, never serde-default silence.
    campaign: Vec<CampaignEntry>,
}

/// The retained law ledger: check name → law text. `require` is the
/// mechanical form of the coverage law: a check about to run with no law
/// entry refuses the whole run.
pub struct Laws {
    by_name: BTreeMap<Label, Label>,
    campaigns: Vec<crate::engines::behavior::campaign::CampaignSeat>,
}

impl Laws {
    pub fn load(path: &Path) -> Result<Laws> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let parsed: LawsFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let mut by_name = BTreeMap::new();
        for e in parsed.law {
            if e.caught_by.as_str().trim().is_empty() {
                bail!("law `{}` names no catching mechanism — coverage unproven", e.name);
            }
            if by_name.insert(e.name.clone(), e.law).is_some() {
                bail!("duplicate law entry `{}`", e.name);
            }
        }
        let mut campaigns = Vec::new();
        for c in parsed.campaign {
            if c.sources.is_empty() {
                bail!("campaign `{}` declares no sources — refuse vacuous seat", c.name);
            }
            if c.artifact.as_str().trim().is_empty() {
                bail!("campaign `{}` declares no artifact path", c.name);
            }
            if !by_name.keys().any(|k| k.as_str() == c.name.as_str()) {
                bail!(
                    "campaign `{}` has no [[law]] entry — a campaign without a retained law may not seat",
                    c.name
                );
            }
            campaigns.push(crate::engines::behavior::campaign::CampaignSeat::admit(
                c.name,
                c.artifact,
                c.freshness_bound_secs,
                c.sources,
            ));
        }
        Ok(Laws { by_name, campaigns })
    }

    pub fn require(&self, check: &str) -> Result<&str> {
        match self
            .by_name
            .iter()
            .find(|(k, _)| k.as_str() == check)
            .map(|(_, v)| v.as_str())
        {
            Some(law) => Ok(law),
            None => bail!(
                "check `{check}` has no entry in laws.toml — a check without a retained law may not run"
            ),
        }
    }

    /// Lookup for citation resolve (TRUTH item 7): a laws.toml law name
    /// citation hashes this text.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.by_name
            .iter()
            .find(|(k, _)| k.as_str() == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn campaigns(&self) -> &[crate::engines::behavior::campaign::CampaignSeat] {
        &self.campaigns
    }
}

/// Typed test refusal — file-level so `total_refusal` indexes it as a workspace
/// enum (tip 777). Nested inside `mod tests` was `not-workspace-enum`.
#[cfg(test)]
#[derive(Debug)]
enum GrammarProofRefuse {
    ReadGrammar,
    ReadBite,
    Tempfile,
    Tempdir,
    WriteFixture,
    FixturesDir,
    FixtureEntry,
    FixtureCopy,
    TwinPass,
    TwinDeny,
    Load,
    LoadSilent,
    CondemnedCount,
    NeitherSeatedUnnamed,
    BothSeatedUnnamed,
    DisjointUnnamed,
    RemoveFixture,
    WriteRogue,
    NestedPlaceUnnamed,
    DualSeatUnnamed,
    TransitionBodyBans,
    ConsumingVerbBodyBans,
    AdmissionDoorBodyBans,
    DerivationUnsafeSeat,
    UnsafeDualDetectable,
    NestedPlaceStillBodyBan,
    DerivationAssignmentBodyBan,
    DerivationAwaitBodyBan,
    UnknownMatcherSilent,
    MissingBiteSilent,
    BiteUnwrapMissing,
    BiteUnwrapSuccessor,
    SoftContainsStillPass,
    ExactUnwrapStillPresent,
    PrefixBiteSilent,
    BiteMsgMismatch,
    DirMasquerade,
    DirMasqueradeSilent,
    DirMasqueradeMsg,
    LawsLoad,
    LawsRequireOk,
    LawlessSilent,
}
#[cfg(test)]
impl GrammarProofRefuse {
    fn require(self, cond: bool) -> Result<(), GrammarProofRefuse> {
        if cond {
            Ok(())
        } else {
            Err(self)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::{Grammar, GrammarProofRefuse, Laws, Result, StructuralRule};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    type TestResult = std::result::Result<(), GrammarProofRefuse>;

    /// Receiver for grammar test helpers (tip 806/896).
    struct GrammarProofs;

    impl GrammarProofs {
        fn real_grammar_text(&self) -> std::result::Result<String, GrammarProofRefuse> {
            std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("grammar.toml"))
                .map_err(|_| GrammarProofRefuse::ReadGrammar)
        }

        fn real_bite_src(&self) -> std::result::Result<String, GrammarProofRefuse> {
            std::fs::read_to_string(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bite_proofs.rs"),
            )
            .map_err(|_| GrammarProofRefuse::ReadBite)
        }

        /// Stage text to a tempfile and return the production `Grammar::load` Result
        /// (error messages preserved for adversary proofs).
        fn probe_text(&self, text: &str) -> std::result::Result<Result<Grammar>, GrammarProofRefuse> {
            let mut f = tempfile::NamedTempFile::new().map_err(|_| GrammarProofRefuse::Tempfile)?;
            f.write_all(text.as_bytes())
                .map_err(|_| GrammarProofRefuse::WriteFixture)?;
            Ok(Grammar::load(
                f.path(),
                &self.real_bite_src()?,
                &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures"),
            ))
        }

        fn load_text(&self, text: &str) -> std::result::Result<Grammar, GrammarProofRefuse> {
            self.probe_text(text)?.map_err(|_| GrammarProofRefuse::Load)
        }

        /// Load that must fail — Ok maps to `silent`, production Err is success.
        fn must_refuse_text(&self, text: &str, silent: GrammarProofRefuse) -> TestResult {
            match self.load_text(text) {
                Ok(_) => Err(silent),
                Err(GrammarProofRefuse::Load) => Ok(()),
                Err(e) => Err(e),
            }
        }

        /// Clone the live fixture dir, apply one mutation, return production load Result.
        fn probe_with_mutated_fixtures(
            &self,
            mutate: impl FnOnce(&Path) -> TestResult,
        ) -> std::result::Result<Result<Grammar>, GrammarProofRefuse> {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let dir = tempfile::tempdir().map_err(|_| GrammarProofRefuse::Tempdir)?;
            for entry in std::fs::read_dir(manifest.join("fixtures"))
                .map_err(|_| GrammarProofRefuse::FixturesDir)?
            {
                let entry = entry.map_err(|_| GrammarProofRefuse::FixtureEntry)?;
                std::fs::copy(entry.path(), dir.path().join(entry.file_name()))
                    .map_err(|_| GrammarProofRefuse::FixtureCopy)?;
            }
            mutate(dir.path())?;
            let mut f = tempfile::NamedTempFile::new().map_err(|_| GrammarProofRefuse::Tempfile)?;
            f.write_all(self.real_grammar_text()?.as_bytes())
                .map_err(|_| GrammarProofRefuse::WriteFixture)?;
            Ok(Grammar::load(f.path(), &self.real_bite_src()?, dir.path()))
        }

        /// Shared load-Err + message check for grammar mutation proofs (tip 1010).
        fn assert_load_err_msg(
            &self,
            text: &str,
            msg_ok: impl FnOnce(&str) -> bool,
            msg_refuse: GrammarProofRefuse,
        ) -> TestResult {
            let e = self.probe_text(text)?;
            GrammarProofRefuse::LoadSilent.require(e.is_err())?;
            let msg = format!("{:?}", e.err());
            msg_refuse.require(msg_ok(&msg))
        }

        /// Shared fixture-mutation load-Err proof (tip 1010).
        fn assert_mutated_fixtures_load_err(
            &self,
            mutate: impl FnOnce(&Path) -> TestResult,
        ) -> TestResult {
            let e = self.probe_with_mutated_fixtures(mutate)?;
            GrammarProofRefuse::LoadSilent.require(e.is_err())
        }
    }

    const G: GrammarProofs = GrammarProofs;

    #[test]
    fn the_real_grammar_loads() -> TestResult {
        let g = G.load_text(&G.real_grammar_text()?)?;
        GrammarProofRefuse::CondemnedCount.require(g.condemned().len() == 8)
    }

    #[test]
    fn proof_const_kind_neither_seated_nor_condemned_is_a_load_error() -> TestResult {
        // TRUTH item 1 Proof fixture: `const` kind silent → load Err.
        // Anchor on the seated-table line break so `impl-const`/`trait-const`
        // are not mangled by a substring replace.
        let text = G.real_grammar_text()?.replace("\nconst = [\"constant\"]\n", "\n");
        G.assert_load_err_msg(
            &text,
            |msg| msg.contains("neither seated nor condemned"),
            GrammarProofRefuse::NeitherSeatedUnnamed,
        )
    }

    #[test]
    fn a_kind_in_both_lists_is_a_load_error() -> TestResult {
        // Seat a kind that is already condemned (and has a condemnation law).
        // Adding a seated-only kind to `condemned` fails earlier: seated kinds
        // have no registered condemnation law name.
        let text = G.real_grammar_text()?.replace(
            "[kinds.seated]\n",
            "[kinds.seated]\nunion = [\"sum-type\"]\n",
        );
        G.assert_load_err_msg(
            &text,
            |msg| msg.contains("both seated and condemned"),
            GrammarProofRefuse::BothSeatedUnnamed,
        )
    }

    #[test]
    fn item_3_proof_two_named_all_private_struct_rules_is_a_load_error() -> TestResult {
        // Item 3 Proof: Grammar declaring two named-all-private struct rules
        // → load Err (identical parse facts — not disjoint).
        let text = G.real_grammar_text()?
            .replace(
                "struct = [\"newtype-scalar\", \"sealed-struct\", \"unit-marker\"]\n",
                "struct = [\"newtype-scalar\", \"sealed-struct\", \"unit-marker\", \"sealed-struct-twin\"]\n",
            )
            .replace(
                "name = \"sealed-struct\"\nkind = \"struct\"\nrule = \"named-all-private-no-string-terminal\"\nbans = []\n",
                "name = \"sealed-struct\"\nkind = \"struct\"\nrule = \"named-all-private-no-string-terminal\"\nbans = []\n\n[[construct]]\nname = \"sealed-struct-twin\"\nkind = \"struct\"\nrule = \"named-all-private-no-string-terminal\"\nbans = []\n",
            );
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let dir = tempfile::tempdir().map_err(|_| GrammarProofRefuse::Tempdir)?;
        for entry in std::fs::read_dir(manifest.join("fixtures"))
            .map_err(|_| GrammarProofRefuse::FixturesDir)?
        {
            let entry = entry.map_err(|_| GrammarProofRefuse::FixtureEntry)?;
            std::fs::copy(entry.path(), dir.path().join(entry.file_name()))
                .map_err(|_| GrammarProofRefuse::FixtureCopy)?;
        }
        std::fs::copy(
            manifest.join("fixtures/sealed-struct.pass.rs"),
            dir.path().join("sealed-struct-twin.pass.rs"),
        )
        .map_err(|_| GrammarProofRefuse::TwinPass)?;
        std::fs::copy(
            manifest.join("fixtures/sealed-struct.deny.rs"),
            dir.path().join("sealed-struct-twin.deny.rs"),
        )
        .map_err(|_| GrammarProofRefuse::TwinDeny)?;
        let mut f = tempfile::NamedTempFile::new().map_err(|_| GrammarProofRefuse::Tempfile)?;
        f.write_all(text.as_bytes())
            .map_err(|_| GrammarProofRefuse::WriteFixture)?;
        let err = Grammar::load(f.path(), &G.real_bite_src()?, dir.path());
        GrammarProofRefuse::LoadSilent.require(err.is_err())?;
        let msg = format!("{:?}", err.err());
        GrammarProofRefuse::DisjointUnnamed.require(msg.contains("not proven disjoint") || msg.contains("identical rules"))
    }

    #[test]
    fn a_missing_fixture_is_a_load_error() -> TestResult {
        // Copy the real fixtures, delete one deny, expect refusal.
        G.assert_mutated_fixtures_load_err(|dir| {
            std::fs::remove_file(dir.join("sealed-struct.deny.rs"))
                .map_err(|_| GrammarProofRefuse::RemoveFixture)?;
            Ok(())
        })
    }

    #[test]
    fn an_unrecognized_fixture_file_is_a_load_error() -> TestResult {
        G.assert_mutated_fixtures_load_err(|dir| {
            std::fs::write(dir.join("rogue.rs"), "fn smuggled() {}\n")
                .map_err(|_| GrammarProofRefuse::WriteRogue)?;
            Ok(())
        })
    }

    #[test]
    fn item_5_proof_nested_place_assign_in_no_list_is_a_load_error() -> TestResult {
        // TRUTH item 5 Proof: nested_place_assign in no jurisdiction → load Err.
        let text = G.real_grammar_text()?.replace(
            "bans = [\"nested_place_assign\", \"await\"]\n",
            "bans = [\"await\"]\n",
        );
        let e = G.probe_text(&text)?;
        GrammarProofRefuse::LoadSilent.require(e.is_err())?;
        let msg = format!("{:?}", e.err());
        GrammarProofRefuse::NestedPlaceUnnamed.require(msg.contains("nested_place_assign") && msg.contains("no list"))
    }

    #[test]
    fn item_5_proof_ban_in_two_jurisdictions_is_a_load_error() -> TestResult {
        let text = G.real_grammar_text()?.replace(
            "bans_attribute = [\n  \"allow_dead_code\",",
            "bans_attribute = [\n  \"unwrap\",\n  \"allow_dead_code\",",
        );
        let e = G.probe_text(&text)?;
        GrammarProofRefuse::LoadSilent.require(e.is_err())?;
        let msg = format!("{:?}", e.err());
        GrammarProofRefuse::DualSeatUnnamed.require(msg.contains("both") || msg.contains("unwrap"))
    }

    #[test]
    fn item_5_proof_cross_mechanism_dual_is_refused() -> TestResult {
        // Tip 511: construct.bans ∩ classify BodyBan for the same name → refuse.
        // Live Transition/ConsumingVerb/Admission enforce nothing in classify
        // for await/nested_place (empty). Derivation still enforces `unsafe`
        // in classify — listing it on construct.bans is the dual specimen.
        GrammarProofRefuse::TransitionBodyBans.require(
            StructuralRule::TransitionBans
                .body_bans_enforced_in_classify()
                .is_empty(),
        )?;
        GrammarProofRefuse::ConsumingVerbBodyBans.require(StructuralRule::ConsumingVerbBans
                .body_bans_enforced_in_classify()
                .is_empty())?;
        GrammarProofRefuse::AdmissionDoorBodyBans.require(StructuralRule::AdmissionDoorBans
                .body_bans_enforced_in_classify()
                .is_empty())?;
        GrammarProofRefuse::DerivationUnsafeSeat.require(StructuralRule::DerivationBans.body_bans_enforced_in_classify() == ["unsafe"])?;
        // Direct refuse path used by Grammar::load:
        let refuse = |rule: StructuralRule, ban: &str| {
            rule.body_bans_enforced_in_classify()
                .iter()
                .any(|b| *b == ban)
        };
        GrammarProofRefuse::UnsafeDualDetectable.require(refuse(StructuralRule::DerivationBans, "unsafe"))?;
        GrammarProofRefuse::NestedPlaceStillBodyBan.require(!refuse(StructuralRule::TransitionBans, "nested_place_assign"))?;
        GrammarProofRefuse::DerivationAssignmentBodyBan.require(!refuse(StructuralRule::DerivationBans, "assignment"))?;
        GrammarProofRefuse::DerivationAwaitBodyBan.require(!refuse(StructuralRule::DerivationBans, "await"))
    }

    #[test]
    fn grammar_refuses_unknown_ban_and_missing_bite_proof() -> TestResult {
        let no_matcher = G.real_grammar_text()?.replace("\"unwrap\",", "\"no_such_matcher\",");
        G.must_refuse_text(&no_matcher, GrammarProofRefuse::UnknownMatcherSilent)?;

        let mut f = tempfile::NamedTempFile::new().map_err(|_| GrammarProofRefuse::Tempfile)?;
        f.write_all(G.real_grammar_text()?.as_bytes())
            .map_err(|_| GrammarProofRefuse::WriteFixture)?;
        let e = Grammar::load(
            f.path(),
            "fn bite_nothing() {}",
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures"),
        );
        GrammarProofRefuse::MissingBiteSilent.require(e.is_err())
    }

    /// Soft `contains("fn bite_unwrap")` matched `fn bite_unwrap_or`. Exact
    /// proof demands `fn bite_{name}(` on a trimmed line (tip 686).
    #[test]
    fn soft_contains_bite_prefix_is_not_a_proof() -> TestResult {
        let mut bite = G.real_bite_src()?;
        let start = bite
            .find("fn bite_unwrap()")
            .ok_or(GrammarProofRefuse::BiteUnwrapMissing)?;
        let rest = &bite[start + 1..];
        let rel_end = rest
            .find("\nfn bite_")
            .ok_or(GrammarProofRefuse::BiteUnwrapSuccessor)?;
        bite.replace_range(start..start + 1 + rel_end, "");
        GrammarProofRefuse::SoftContainsStillPass.require(
            bite.lines()
                .any(|l| l.trim_start().starts_with("fn bite_unwrap_or(")),
        )?;
        GrammarProofRefuse::ExactUnwrapStillPresent.require(
            !bite
                .lines()
                .any(|l| l.trim_start().starts_with("fn bite_unwrap(")),
        )?;
        let mut f = tempfile::NamedTempFile::new().map_err(|_| GrammarProofRefuse::Tempfile)?;
        f.write_all(G.real_grammar_text()?.as_bytes())
            .map_err(|_| GrammarProofRefuse::WriteFixture)?;
        let Err(err) = Grammar::load(
            f.path(),
            &bite,
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures"),
        ) else {
            return Err(GrammarProofRefuse::PrefixBiteSilent);
        };
        GrammarProofRefuse::BiteMsgMismatch.require(format!("{err}") == "ban `unwrap` has no bite proof — an unproven law may not run")
    }

    /// A directory named like an expected fixture must not count as present.
    #[test]
    fn fixture_directory_masquerade_is_a_load_error() -> TestResult {
        let e = G.probe_with_mutated_fixtures(|dir| {
            std::fs::remove_file(dir.join("sealed-struct.deny.rs"))
                .map_err(|_| GrammarProofRefuse::RemoveFixture)?;
            std::fs::create_dir(dir.join("sealed-struct.deny.rs"))
                .map_err(|_| GrammarProofRefuse::DirMasquerade)?;
            Ok(())
        })?;
        let Err(err) = e else {
            return Err(GrammarProofRefuse::DirMasqueradeSilent);
        };
        GrammarProofRefuse::DirMasqueradeMsg.require(format!("{err}")
                == "fixtures/ entry `sealed-struct.deny.rs` is not a regular file — a directory or symlink cannot prove a rule")
    }

    #[test]
    fn laws_require_refuses_a_lawless_check() -> TestResult {
        let mut f = tempfile::NamedTempFile::new().map_err(|_| GrammarProofRefuse::Tempfile)?;
        f.write_all(
            b"campaign = []\n[[law]]\nname = \"unwrap\"\nlaw = \"a panic where refusal is owed\"\ncaught_by = \"grammar ban\"\n",
        )
        .map_err(|_| GrammarProofRefuse::WriteFixture)?;
        let laws = Laws::load(f.path()).map_err(|_| GrammarProofRefuse::LawsLoad)?;
        GrammarProofRefuse::LawsRequireOk.require(laws.require("unwrap").is_ok())?;
        GrammarProofRefuse::LawlessSilent.require(laws.require("ghost_check").is_err())
    }
}
