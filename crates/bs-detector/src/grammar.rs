/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The grammar: the operator-approved law seat of the default-deny gate.
//!
//! `grammar.toml` declares, and `Grammar::load` refuses anything less than
//! all of: every item kind seated, condemned, or a container (nothing
//! silent); every ban resolved to a registered matcher in exactly one
//! jurisdiction (expression, attribute, or construct-scoped) with a bite
//! proof; every same-kind construct pair proven disjoint from parse facts;
//! every construct backed by a pass and a deny fixture file; every
//! declared-fn seat carrying a well-formed site hash. `laws.toml` retains
//! every lie-shape law with the mechanism that catches it now; a check
//! running without a law entry refuses the whole run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::classify;
use crate::engines::shape;

/// The kinds the grammar seats with constructs. Closed: growing this enum
/// is an operator ruling, not a convenience.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConstructKind {
    Struct,
    Enum,
    Fn,
    Type,
    Use,
    Const,
    Static,
    Mod,
}

impl ConstructKind {
    pub const ALL: [ConstructKind; 8] = [
        ConstructKind::Struct,
        ConstructKind::Enum,
        ConstructKind::Fn,
        ConstructKind::Type,
        ConstructKind::Use,
        ConstructKind::Const,
        ConstructKind::Static,
        ConstructKind::Mod,
    ];
}

/// Kinds red on sight, each with a laws.toml entry. Fixed law: grammar.toml
/// must state exactly this set — drift in either direction refuses.
pub const CONDEMNED_KINDS: [&str; 8] = [
    "extern-crate",
    "foreign-mod",
    "union",
    "trait-alias",
    "verbatim",
    "macro",
    "impl-item-macro",
    "trait-item-macro",
];

/// Kinds that are pure containers: their interior items classify
/// individually (fns as skeletons, consts/types by their rules, interior
/// macros condemned), so the container itself has no unjudged freedom.
pub const CONTAINER_KINDS: [&str; 2] = ["impl", "trait"];

/// The structural rule a construct demands. Closed sum; each variant has
/// exactly one implementation in `classify.rs` and fixture-pair proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructuralRule {
    // struct
    TupleSinglePrivateField,
    NamedFieldsAllPrivate,
    UnitStruct,
    // enum
    NoStringVariantFields,
    // fn skeletons
    MainInBin,
    ReceiverSharedRef,
    ReceiverUniqueRef,
    ReceiverOwnedNotSelfReturn,
    AdmissionDoor,
    DeclaredFn,
    // type / use / const / static / mod
    AliasNotStringCarrying,
    NoGlobImport,
    ConstNotStringCarrying,
    StaticImmutableNotString,
    ModNoPathAttr,
}

impl StructuralRule {
    /// The kind a rule may lawfully be seated under. A rule seated under a
    /// foreign kind is a category error the loader refuses.
    pub fn kind(self) -> ConstructKind {
        use StructuralRule::*;
        match self {
            TupleSinglePrivateField | NamedFieldsAllPrivate | UnitStruct => ConstructKind::Struct,
            NoStringVariantFields => ConstructKind::Enum,
            MainInBin | ReceiverSharedRef | ReceiverUniqueRef | ReceiverOwnedNotSelfReturn
            | AdmissionDoor | DeclaredFn => ConstructKind::Fn,
            AliasNotStringCarrying => ConstructKind::Type,
            NoGlobImport => ConstructKind::Use,
            ConstNotStringCarrying => ConstructKind::Const,
            StaticImmutableNotString => ConstructKind::Static,
            ModNoPathAttr => ConstructKind::Mod,
        }
    }

    /// The disjointness proof: for two rules of one kind, the parse fact
    /// that no item satisfies both. Returning false means no proof exists
    /// and the loader refuses the grammar. Total over same-kind pairs.
    pub fn disjoint_with(self, other: StructuralRule) -> bool {
        use StructuralRule::*;
        if self == other {
            return false; // one rule seated twice partitions nothing
        }
        match (self, other) {
            // struct rules: syn::Fields is Unnamed xor Named xor Unit.
            (TupleSinglePrivateField, NamedFieldsAllPrivate)
            | (NamedFieldsAllPrivate, TupleSinglePrivateField)
            | (TupleSinglePrivateField, UnitStruct)
            | (UnitStruct, TupleSinglePrivateField)
            | (NamedFieldsAllPrivate, UnitStruct)
            | (UnitStruct, NamedFieldsAllPrivate) => true,
            // fn skeletons: one fn has exactly one receiver form; main-in-bin
            // is excluded from every receiverless rule by the explicit
            // is-main clause; admission-door (inside an impl) and
            // declared-fn (module level) are position-exclusive.
            (MainInBin, r) | (r, MainInBin) if r.kind() == ConstructKind::Fn => true,
            (ReceiverSharedRef, r) | (r, ReceiverSharedRef) if r.kind() == ConstructKind::Fn => {
                true
            }
            (ReceiverUniqueRef, r) | (r, ReceiverUniqueRef) if r.kind() == ConstructKind::Fn => {
                true
            }
            (ReceiverOwnedNotSelfReturn, r) | (r, ReceiverOwnedNotSelfReturn)
                if r.kind() == ConstructKind::Fn =>
            {
                true
            }
            (AdmissionDoor, DeclaredFn) | (DeclaredFn, AdmissionDoor) => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructDef {
    pub name: String,
    pub kind: ConstructKind,
    pub rule: StructuralRule,
    /// Construct-scoped bans: jurisdiction is items classified as this
    /// construct, attributed by span containment.
    #[serde(default)]
    pub bans: Vec<String>,
}

/// One declared receiverless-fn seat: the ONLY green for a module-level fn.
/// Binds file + fn path + content hash — a declared file greens nothing,
/// only declared fns do, and a body edit reds the fn until re-declared.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeatFn {
    /// Repo-root-relative file.
    pub file: String,
    /// The fn ident (module-level fns only; impl fns classify as skeletons).
    pub path: String,
    /// blake3 of the fn's identity rendering (identity.rs), lowercase hex.
    pub hash: String,
    /// Whether this seat is a transport-boundary fn allowed `async`/`await`.
    pub io: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seats {
    pub fns: Vec<SeatFn>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BansFile {
    expression: Vec<String>,
    attribute: Vec<String>,
    /// Names (from any jurisdiction) no waiver can cover.
    absolute: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrammarFile {
    condemned: Vec<String>,
    bans: BansFile,
    construct: Vec<ConstructDef>,
    seats: Seats,
}

/// The loaded, validated grammar.
pub struct Grammar {
    /// Expression-jurisdiction bans: every expression position, every item.
    pub bans_expression: Vec<String>,
    /// Attribute-jurisdiction bans: every attribute position, item- and
    /// crate-level.
    pub bans_attribute: Vec<String>,
    /// The no-waiver marker set (names from any jurisdiction).
    pub absolute: BTreeSet<String>,
    pub constructs: Vec<ConstructDef>,
    pub seats: Seats,
}

impl Grammar {
    /// True if hits of `check` may never be waived.
    pub fn is_absolute(&self, check: &str) -> bool {
        self.absolute.contains(check)
    }

    /// The declared seat for a module-level fn, if any.
    pub fn seat_for(&self, file: &str, fn_path: &str) -> Option<&SeatFn> {
        self.seats
            .fns
            .iter()
            .find(|s| s.file == file && s.path == fn_path)
    }

    fn ban_registered(name: &str) -> bool {
        shape::matcher_by_name(name).is_some() || classify::scoped_rule_registered(name)
    }

    /// Load and validate; every refusal here is a law from the fifth
    /// adjudication (TRUTH_AND_RECONCILLIATION.md, items 1, 3, 5).
    pub fn load(path: &Path, bite_src: &str, fixtures_dir: &Path) -> Result<Grammar> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let parsed: GrammarFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

        // Condemned set: exactly the law set, stated — drift refuses.
        let stated: BTreeSet<&str> = parsed.condemned.iter().map(|s| s.as_str()).collect();
        let law: BTreeSet<&str> = CONDEMNED_KINDS.iter().copied().collect();
        if stated != law {
            bail!(
                "condemned kinds in grammar.toml differ from the law set — stated {:?}, law {:?}",
                stated,
                law
            );
        }

        if parsed.bans.expression.is_empty() || parsed.construct.is_empty() {
            bail!("grammar with an empty section certifies nothing — refuse to load");
        }

        // Every ban: registered in a matcher registry, bite-proven, and in
        // exactly one jurisdiction.
        let scoped: Vec<&String> = parsed.construct.iter().flat_map(|c| c.bans.iter()).collect();
        let mut jurisdiction_seen: BTreeMap<&str, &str> = BTreeMap::new();
        let all_bans = parsed
            .bans
            .expression
            .iter()
            .map(|n| (n, "expression"))
            .chain(parsed.bans.attribute.iter().map(|n| (n, "attribute")))
            .chain(scoped.iter().map(|n| (*n, "construct")));
        for (name, jur) in all_bans {
            if !Self::ban_registered(name) {
                bail!("ban `{name}` has no registered matcher — a law that cannot fire");
            }
            if !bite_src.contains(&format!("fn bite_{name}")) {
                bail!("ban `{name}` has no bite proof — an unproven law may not run");
            }
            if let Some(prev) = jurisdiction_seen.insert(name.as_str(), jur) {
                if prev != jur || jur != "construct" {
                    bail!("ban `{name}` sits in two jurisdictions ({prev}, {jur}) — one law, one seat");
                }
            }
        }
        // Absolute markers must mark something that exists.
        for name in &parsed.bans.absolute {
            if !jurisdiction_seen.contains_key(name.as_str()) {
                bail!("absolute marker `{name}` names no ban in any jurisdiction");
            }
        }
        // The reverse direction: every registered matcher sits in exactly
        // one jurisdiction. An implemented law seated nowhere is a check
        // that silently stopped existing — item 5's named fixture.
        for m in shape::MATCHERS {
            if !jurisdiction_seen.contains_key(m.name) {
                bail!(
                    "registered matcher `{}` sits in no jurisdiction — an implemented law seated nowhere",
                    m.name
                );
            }
        }
        for name in classify::SCOPED_RULES {
            if !jurisdiction_seen.contains_key(name) {
                bail!(
                    "classifier rule `{name}` sits in no jurisdiction — an implemented law seated nowhere"
                );
            }
        }

        // Constructs: unique names, rule seated under its own kind, every
        // kind seated, same-kind disjointness proven, fixture pair present.
        let mut seen = BTreeSet::new();
        for c in &parsed.construct {
            if !seen.insert(c.name.clone()) {
                bail!("duplicate construct `{}`", c.name);
            }
            if c.rule.kind() != c.kind {
                bail!(
                    "construct `{}` seats rule {:?} under kind {:?} — category error",
                    c.name,
                    c.rule,
                    c.kind
                );
            }
        }
        for kind in ConstructKind::ALL {
            if !parsed.construct.iter().any(|c| c.kind == kind) {
                bail!("kind {kind:?} is neither seated nor condemned — nothing is silent");
            }
        }
        for (i, a) in parsed.construct.iter().enumerate() {
            for b in parsed.construct.iter().skip(i + 1) {
                if a.kind == b.kind && !a.rule.disjoint_with(b.rule) {
                    bail!(
                        "constructs `{}` and `{}` (kind {:?}) have no disjointness proof — a name that cannot discriminate certifies nothing",
                        a.name,
                        b.name,
                        a.kind
                    );
                }
            }
        }
        for c in &parsed.construct {
            for fixture in ["pass", "deny"] {
                let f = fixtures_dir.join(format!("{}.{fixture}.rs", c.name));
                if !f.is_file() {
                    bail!(
                        "construct `{}` has no {fixture} fixture at {} — an unproven construct may not seat",
                        c.name,
                        f.display()
                    );
                }
            }
        }

        // Seats: well-formed hashes over existing files.
        let mut seat_keys = BTreeSet::new();
        for s in &parsed.seats.fns {
            if s.hash.len() != 64 || !s.hash.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("seat {}#{} hash is not 64 hex chars", s.file, s.path);
            }
            if !seat_keys.insert((s.file.clone(), s.path.clone())) {
                bail!("duplicate seat {}#{}", s.file, s.path);
            }
        }

        Ok(Grammar {
            bans_expression: parsed.bans.expression,
            bans_attribute: parsed.bans.attribute,
            absolute: parsed.bans.absolute.into_iter().collect(),
            constructs: parsed.construct,
            seats: parsed.seats,
        })
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

    #[test]
    fn same_rule_twice_has_no_disjointness_proof() {
        assert!(!StructuralRule::NamedFieldsAllPrivate
            .disjoint_with(StructuralRule::NamedFieldsAllPrivate));
        assert!(StructuralRule::TupleSinglePrivateField
            .disjoint_with(StructuralRule::NamedFieldsAllPrivate));
        assert!(StructuralRule::UnitStruct.disjoint_with(StructuralRule::TupleSinglePrivateField));
        assert!(StructuralRule::AdmissionDoor.disjoint_with(StructuralRule::DeclaredFn));
        assert!(StructuralRule::MainInBin.disjoint_with(StructuralRule::DeclaredFn));
    }

    #[test]
    fn every_rule_seats_under_exactly_one_kind() {
        // The rule→kind map is total: no rule may be seated under a foreign
        // kind, and the loader's category-error refusal depends on this.
        use StructuralRule::*;
        for r in [
            TupleSinglePrivateField,
            NamedFieldsAllPrivate,
            UnitStruct,
            NoStringVariantFields,
            MainInBin,
            ReceiverSharedRef,
            ReceiverUniqueRef,
            ReceiverOwnedNotSelfReturn,
            AdmissionDoor,
            DeclaredFn,
            AliasNotStringCarrying,
            NoGlobImport,
            ConstNotStringCarrying,
            StaticImmutableNotString,
            ModNoPathAttr,
        ] {
            let _ = r.kind();
        }
    }

    #[test]
    fn load_refuses_an_unseated_kind_and_an_unproven_pair() {
        // Both fixtures run against the REAL grammar.toml text, mutated:
        // deleting the const seat must refuse (item 1's named fixture);
        // seating named-fields-all-private twice must refuse (item 3's).
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let real = match std::fs::read_to_string(root.join("grammar.toml")) {
            Ok(t) => t,
            Err(e) => panic!("grammar.toml readable: {e}"),
        };
        let bite = match std::fs::read_to_string(root.join("tests/bite_proofs.rs")) {
            Ok(t) => t,
            Err(e) => panic!("bite_proofs.rs readable: {e}"),
        };
        let fixtures = root.join("fixtures");
        let write = |content: &str| -> tempfile::NamedTempFile {
            use std::io::Write;
            let mut f = match tempfile::NamedTempFile::new() {
                Ok(f) => f,
                Err(e) => panic!("tempfile: {e}"),
            };
            match f.write_all(content.as_bytes()) {
                Ok(()) => f,
                Err(e) => panic!("write fixture: {e}"),
            }
        };

        let sane = write(&real);
        if let Err(e) = Grammar::load(sane.path(), &bite, &fixtures) {
            panic!("the real grammar must load: {e:#}");
        }

        let unseated = write(&real.replace(
            "[[construct]]\nname = \"manifest-const\"\nkind = \"const\"\nrule = \"const-not-string-carrying\"\n",
            "",
        ));
        let e = match Grammar::load(unseated.path(), &bite, &fixtures) {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("a kind neither seated nor condemned must refuse to load"),
        };
        assert!(
            e.contains("neither seated nor condemned"),
            "refusal must be FOR kind totality, got: {e}"
        );

        // Item 5's named fixture: a registered rule seated in no
        // jurisdiction refuses — here nested_place_assign, stripped from
        // every construct bans list while absent from the top-level lists.
        let unseated_ban = write(&real.replace("bans = [\"nested_place_assign\"]\n", ""));
        let e = match Grammar::load(unseated_ban.path(), &bite, &fixtures) {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("a registered rule in no jurisdiction must refuse to load"),
        };
        assert!(
            e.contains("sits in no jurisdiction"),
            "refusal must be FOR the missing seat, got: {e}"
        );

        let doubled = write(&format!(
            "{real}\n[[construct]]\nname = \"second-sealed\"\nkind = \"struct\"\nrule = \"named-fields-all-private\"\n"
        ));
        let e = match Grammar::load(doubled.path(), &bite, &fixtures) {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("two same-kind constructs without a disjointness proof must refuse"),
        };
        assert!(
            e.contains("no disjointness proof"),
            "refusal must be FOR disjointness, not fixture absence, got: {e}"
        );
    }

    #[test]
    fn laws_require_refuses_a_lawless_check() {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        use std::io::Write;
        f.write_all(
            b"[[law]]\nname = \"unwrap\"\nlaw = \"a panic where refusal is owed\"\ncaught_by = \"grammar ban\"\n",
        )
        .expect("write");
        let laws = Laws::load(f.path()).expect("loads");
        assert!(laws.require("unwrap").is_ok());
        assert!(laws.require("ghost_check").is_err(), "no law entry = refuse");
    }
}
