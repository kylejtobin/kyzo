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
    /// module: a `#[path = ...]` attribute is red (file-identity spoof).
    ModuleNoPathAttr,
    /// containers: interior items classify individually; condemned
    /// interior kinds (macro, verbatim) red inside the container.
    InteriorsClassify,
    /// composition-root: `main` body is let-bindings of calls, `?`, one
    /// tail call; `if`/`match`/`loop` red.
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
        matches!(self, StructuralRule::UnitStruct)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructDef {
    pub name: String,
    pub kind: ConstructFamily,
    pub rule: StructuralRule,
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrammarFile {
    bans_absolute: Vec<String>,
    bans: Vec<String>,
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
pub struct Grammar {
    /// Banned shapes no waiver can cover.
    pub bans_absolute: Vec<String>,
    /// Banned shapes a waiver may cover, one entry per hit.
    pub bans: Vec<String>,
    pub constructs: Vec<ConstructDef>,
    pub condemned: BTreeSet<KindName>,
    pub seated: BTreeMap<KindName, Vec<String>>,
    pub fn_seats: Vec<FnSeat>,
}

impl Grammar {
    /// Load and validate. Refuses: a ban with no registered matcher or no
    /// `bite_<name>` detonation; a name in both ban lists; a duplicate or
    /// orphaned construct; an empty section; a kind neither seated nor
    /// condemned (or in both lists); a seat naming an unknown construct or
    /// one from the wrong family; a condemned kind with no registered law
    /// name; a malformed fn seat; and any fixture-law violation (missing
    /// pass/deny fixture, unexpected file in `fixtures/`).
    pub fn load(path: &Path, bite_src: &str, fixtures_dir: &Path) -> Result<Grammar> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let parsed: GrammarFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if parsed.bans.is_empty() || parsed.bans_absolute.is_empty() || parsed.construct.is_empty()
        {
            bail!("grammar with an empty section certifies nothing — refuse to load");
        }
        for name in parsed.bans_absolute.iter().chain(parsed.bans.iter()) {
            if shape::matcher_by_name(name).is_none() {
                bail!("ban `{name}` has no registered matcher — a law that cannot fire");
            }
            if !bite_src.contains(&format!("fn bite_{name}")) {
                bail!("ban `{name}` has no bite proof — an unproven law may not run");
            }
        }
        for name in &parsed.bans_absolute {
            if parsed.bans.contains(name) {
                bail!("ban `{name}` is in both lists — absolute and waivable cannot both hold");
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

        // Fixture law: pass+deny per construct (zero-freedom cells are
        // deny-exempt), deny per condemned kind, nothing unrecognized.
        let mut expected: BTreeSet<String> = BTreeSet::new();
        for c in &parsed.construct {
            expected.insert(format!("{}.pass.rs", c.name));
            if !c.rule.deny_exempt() {
                expected.insert(format!("{}.deny.rs", c.name));
            }
        }
        for kind in &condemned {
            expected.insert(format!("{}.deny.rs", kind.kebab()));
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
            constructs: parsed.construct,
            condemned,
            seated: parsed.kinds.seated,
            fn_seats: parsed.seats.fns,
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
        match self.seated.get(&kind) {
            Some(seats) => seats.iter().any(|s| s == construct),
            None => false,
        }
    }

    /// The declared seat for a receiverless fn, if any.
    pub fn fn_seat(&self, file: &str, fn_path: &str) -> Option<&FnSeat> {
        self.fn_seats
            .iter()
            .find(|s| s.file == file && s.fn_path == fn_path)
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

    #[test]
    fn the_real_grammar_loads() {
        let g = load_text(&real_grammar_text()).expect("the checked-in grammar must load");
        assert_eq!(g.condemned.len(), 8, "exactly the eight condemned kinds");
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
    fn a_missing_fixture_is_a_load_error() {
        // Copy the real fixtures, delete one deny, expect refusal.
        let dir = tempfile::tempdir().expect("tempdir");
        for entry in std::fs::read_dir(crate_dir().join("fixtures")).expect("fixtures dir") {
            let entry = entry.expect("entry");
            std::fs::copy(entry.path(), dir.path().join(entry.file_name())).expect("copy");
        }
        std::fs::remove_file(dir.path().join("sealed-struct.deny.rs")).expect("remove");
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(real_grammar_text().as_bytes()).expect("write");
        let e = Grammar::load(f.path(), &real_bite_src(), dir.path());
        assert!(e.is_err(), "missing fixture must refuse to load");
    }

    #[test]
    fn an_unrecognized_fixture_file_is_a_load_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        for entry in std::fs::read_dir(crate_dir().join("fixtures")).expect("fixtures dir") {
            let entry = entry.expect("entry");
            std::fs::copy(entry.path(), dir.path().join(entry.file_name())).expect("copy");
        }
        std::fs::write(dir.path().join("rogue.rs"), "fn smuggled() {}\n").expect("write rogue");
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(real_grammar_text().as_bytes()).expect("write");
        let e = Grammar::load(f.path(), &real_bite_src(), dir.path());
        assert!(e.is_err(), "a file the fixture law does not expect must refuse");
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
