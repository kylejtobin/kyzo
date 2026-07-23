/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The grammar: the operator-approved law seat of the default-deny gate.
//!
//! `grammar.toml` declares the banned-shape predicates (waivable and
//! absolute) and the structural constructs every struct and enum must
//! classify against. `laws.toml` retains every lie-shape law with the
//! mechanism that catches it now; a check running without a law entry is
//! a coverage violation and the run refuses.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::engines::shape;

/// The item kind a construct classifies. Closed: growing this enum is an
/// operator ruling, not a convenience.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConstructKind {
    Struct,
    Enum,
}

/// The structural rule a construct demands. Closed sum; each variant has
/// exactly one implementation in `classify.rs` and a bite proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructuralRule {
    TupleSinglePrivateField,
    AllFieldsPrivate,
    NoStringVariantFields,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructDef {
    pub name: String,
    pub kind: ConstructKind,
    pub rule: StructuralRule,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrammarFile {
    bans_absolute: Vec<String>,
    bans: Vec<String>,
    construct: Vec<ConstructDef>,
}

/// The loaded, validated grammar.
pub struct Grammar {
    /// Banned shapes no waiver can cover.
    pub bans_absolute: Vec<String>,
    /// Banned shapes a waiver may cover, one entry per hit.
    pub bans: Vec<String>,
    pub constructs: Vec<ConstructDef>,
}

impl Grammar {
    /// Load and validate. Refuses: a ban with no registered matcher, a ban
    /// with no `bite_<name>` detonation in the bite-proof suite, a name in
    /// both ban lists, a duplicate construct name, or an empty section —
    /// an empty grammar is a gate that certifies nothing while looking on.
    pub fn load(path: &Path, bite_src: &str) -> Result<Grammar> {
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
        let mut seen = std::collections::BTreeSet::new();
        for c in &parsed.construct {
            if !seen.insert(c.name.clone()) {
                bail!("duplicate construct `{}`", c.name);
            }
        }
        Ok(Grammar {
            bans_absolute: parsed.bans_absolute,
            bans: parsed.bans,
            constructs: parsed.construct,
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
    use std::io::Write;

    fn write_tmp(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(content.as_bytes()).expect("write fixture");
        f
    }

    #[test]
    fn grammar_refuses_unknown_ban_and_missing_bite_proof() {
        let bad = write_tmp(
            "bans_absolute = [\"todo_bang\"]\nbans = [\"no_such_matcher\"]\n[[construct]]\nname = \"x\"\nkind = \"struct\"\nrule = \"all-fields-private\"\n",
        );
        let e = Grammar::load(bad.path(), "fn bite_todo_bang() {}");
        assert!(e.is_err(), "unknown matcher must refuse");

        let no_bite = write_tmp(
            "bans_absolute = [\"todo_bang\"]\nbans = [\"unwrap\"]\n[[construct]]\nname = \"x\"\nkind = \"struct\"\nrule = \"all-fields-private\"\n",
        );
        let e = Grammar::load(no_bite.path(), "fn bite_todo_bang() {}");
        assert!(e.is_err(), "ban without bite proof must refuse");
    }

    #[test]
    fn laws_require_refuses_a_lawless_check() {
        let f = write_tmp("[[law]]\nname = \"unwrap\"\nlaw = \"a panic where refusal is owed\"\ncaught_by = \"grammar ban\"\n");
        let laws = Laws::load(f.path()).expect("loads");
        assert!(laws.require("unwrap").is_ok());
        assert!(laws.require("ghost_check").is_err(), "no law entry = refuse");
    }
}
