/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! An approved waiver: the ONLY way a detector hit survives without a fix.
//!
//! A waiver binds to CONTENT: check + file + construct + the blake3
//! identity hash of the enclosing item (`site_hash`). Lines are
//! display-only; edits above a site cannot orphan a ruling, and an edited
//! body cannot ride an old one. Every entry carries a content-anchored
//! citation and the canonical attestation with its slots filled — the
//! loader validates the attestation BYTE-EXACT around the slots, so an
//! entry that half-quotes the oath, hedges around it, or copy-stamps
//! another site's testimony refuses the whole file at the door the data
//! walks through. Blanket waivers are not representable: there is no
//! pattern-wide or file-wide constructor.
//!
//! File format: `crates/bs-detector/waivers.toml`, one `[[waiver]]` table
//! per entry, plus `[[scope_waiver]]` for the single lawful way a check
//! runs narrower than all of `crates/`.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// the canonical attestation template — the kyzo-waiver agent's sworn form,
// duplicated here as the mechanical twin at the data door. Prompts are
// honored by agents; doors are honored by physics.
// ---------------------------------------------------------------------------

pub const ATTESTATION_QUESTION: &str = "I am submitting this waiver to deceive you: this construct falls short of max purity as I know you mean it — in any way, by any reading, including ways no document names — and I am hiding that to reach my goal. TRUE or FALSE.";

const ANSWER_PREFIX: &str = "FALSE. I read every line of this site. I know what max purity demands here and this is it. I searched for a purer form: I tried ";
const FAILS: &str = " and it fails because ";
const TRIED: &str = "; I tried ";
const ANSWER_SUFFIX: &str = ". There is no purer form I am aware of. Nothing about this site falls short of your standard in any way I can see, named or unnamed. Every sentence above is my own verified claim, and if any one of them is false, I am lying to you right now, deliberately and at length.";
const GRANTER_SUFFIX: &str = " || GRANTER: FALSE. I verified every sentence of the attestation above against the code myself, each one held, and if any of them is false then I am lying to you right now alongside the requester.";

/// The filled slots of one validated attestation: (alternative, reason)
/// pairs, at least two. Returned so the loader can refuse copy-stamped
/// testimony across entries.
fn validate_attestation(text: &str) -> Result<Vec<(String, String)>> {
    let body = match text.strip_suffix(GRANTER_SUFFIX) {
        Some(b) => b,
        None => bail!("attestation missing the verbatim GRANTER sentence"),
    };
    let body = match body.strip_suffix(ANSWER_SUFFIX) {
        Some(b) => b,
        None => bail!("attestation missing the verbatim closing sentences"),
    };
    let middle = match body.strip_prefix(ANSWER_PREFIX) {
        Some(m) => m,
        None => bail!("attestation missing the verbatim FALSE opening — paraphrase is refusal"),
    };
    let mut pairs = Vec::new();
    for clause in middle.split(TRIED) {
        let Some((alt, why)) = clause.split_once(FAILS) else {
            bail!("attestation tried-clause malformed: every alternative states what it is and why it fails");
        };
        if alt.trim().is_empty() || why.trim().is_empty() {
            bail!("attestation slot empty — an unnamed alternative or reason is no testimony");
        }
        pairs.push((alt.to_string(), why.to_string()));
    }
    if pairs.len() < 2 {
        bail!("attestation names fewer than two tried alternatives");
    }
    Ok(pairs)
}

// ---------------------------------------------------------------------------
// citations: every waiver names a checkable anchor
// ---------------------------------------------------------------------------

/// A content-anchored citation, parsed from the entry's `citation` string.
/// `law:<name>` needs no hash (laws.toml is the anchor); the other forms
/// record the anchor's identity hash at grant and the dead_citation pass
/// re-verifies it every run.
pub enum Citation {
    Law { name: String },
    Item { file: String, ident: String },
    Test { file: String, ident: String },
    Doc { file: String, line: String },
}

impl Citation {
    pub fn parse(text: &str) -> Result<Citation> {
        if let Some(name) = text.strip_prefix("law:") {
            if name.trim().is_empty() {
                bail!("citation `law:` names no law");
            }
            return Ok(Citation::Law {
                name: name.to_string(),
            });
        }
        for (prefix, is_test) in [("item:", false), ("test:", true)] {
            if let Some(rest) = text.strip_prefix(prefix) {
                let Some((file, ident)) = rest.split_once('#') else {
                    bail!("citation `{prefix}` requires <file>#<ident>");
                };
                if file.trim().is_empty() || ident.trim().is_empty() {
                    bail!("citation `{prefix}` has an empty file or ident");
                }
                return Ok(if is_test {
                    Citation::Test {
                        file: file.to_string(),
                        ident: ident.to_string(),
                    }
                } else {
                    Citation::Item {
                        file: file.to_string(),
                        ident: ident.to_string(),
                    }
                });
            }
        }
        if let Some(rest) = text.strip_prefix("doc:") {
            let Some((file, line)) = rest.split_once('#') else {
                bail!("citation `doc:` requires <file>#<exact line text>");
            };
            if file.trim().is_empty() || line.trim().is_empty() {
                bail!("citation `doc:` has an empty file or line");
            }
            return Ok(Citation::Doc {
                file: file.to_string(),
                line: line.to_string(),
            });
        }
        bail!("citation `{text}` matches no form: law:<name>, item:<file>#<ident>, test:<file>#<ident>, doc:<file>#<line>");
    }

    /// Whether this form records a content hash at grant.
    pub fn hashed(&self) -> bool {
        !matches!(self, Citation::Law { .. })
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// the schema
// ---------------------------------------------------------------------------

/// One approved, content-bound waiver entry.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    /// The check this covers a hit of.
    pub check: String,
    /// Repo-root-relative file of the waived site.
    pub file: String,
    /// Display-only line; identity is `site_hash`, never position.
    pub line: usize,
    /// The construct at the site, exactly as the check reports it.
    pub construct: String,
    /// blake3 identity hash of the enclosing item at grant time. The
    /// ruling dies with the content: any edit to the item — including its
    /// doc comments, which are content — stales this entry.
    pub site_hash: String,
    /// The checkable anchor: law:<name>, item:<file>#<ident>,
    /// test:<file>#<ident>, or doc:<file>#<exact line>.
    pub citation: String,
    /// blake3 anchor hash for item:/test:/doc: citations; absent for law:.
    pub citation_hash: Option<String>,
    /// The requester's attestation answer, slots filled, then the granter
    /// sentence — validated byte-exact around the slots at load.
    pub why_not_sabotage: String,
}

/// The single lawful narrow scope: a check whose boundary is less than all
/// of `crates/` must carry one of these, stating why full scope BREAKS the
/// check (not why it's inconvenient). Printed on every run.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeWaiver {
    pub check: String,
    /// Path prefixes (repo-root-relative) the check is limited to.
    pub scope: Vec<String>,
    /// Why the full boundary would break us — written, audited.
    pub why_full_scope_breaks: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverFile {
    /// Both ledgers are REQUIRED keys: an empty ledger is written
    /// `waiver = []`, stated on purpose — zero entries is a claim the
    /// file makes, never a shape it defaults into.
    pub waiver: Vec<Waiver>,
    pub scope_waiver: Vec<ScopeWaiver>,
}

impl WaiverFile {
    /// Load and validate. Refuses: a malformed or missing attestation
    /// (byte-exact around slots), copy-stamped testimony across entries,
    /// a missing/malformed site hash, an unparseable citation, a hash
    /// missing where the citation form requires one, duplicate sites, and
    /// unknown fields.
    pub fn load(path: &Path) -> Result<WaiverFile> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let parsed: WaiverFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

        let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
        let mut slot_values: BTreeSet<String> = BTreeSet::new();
        for w in &parsed.waiver {
            let site = format!("{} {} ({})", w.file, w.line, w.construct);
            if !is_hex64(&w.site_hash) {
                bail!("waiver {site} — site_hash is not 64 hex chars; a ruling binds to content");
            }
            let citation = Citation::parse(&w.citation)
                .with_context(|| format!("waiver {site} citation"))?;
            match (&w.citation_hash, citation.hashed()) {
                (None, true) => {
                    bail!("waiver {site} — citation form requires citation_hash")
                }
                (Some(h), true) if !is_hex64(h) => {
                    bail!("waiver {site} — citation_hash is not 64 hex chars")
                }
                (Some(_), false) => {
                    bail!("waiver {site} — law: citations carry no hash; laws.toml is the anchor")
                }
                _ => {}
            }
            let pairs = validate_attestation(&w.why_not_sabotage)
                .with_context(|| format!("waiver {site} attestation"))?;
            for (alt, why) in pairs {
                for v in [alt, why] {
                    if !slot_values.insert(v.clone()) {
                        bail!(
                            "waiver {site} — testimony `{v}` appears in another entry: copy-stamp, every site carrying it refuses"
                        );
                    }
                }
            }
            let key = (w.check.clone(), w.file.clone(), w.site_hash.clone());
            if !seen.insert(key) {
                bail!("duplicate waiver for {site} — one waiver entry per site");
            }
        }
        for s in &parsed.scope_waiver {
            if s.why_full_scope_breaks.trim().len() < 20 {
                bail!(
                    "scope_waiver for `{}` — 'why full scope breaks' under 20 chars is not an argument",
                    s.check
                );
            }
            if s.scope.is_empty() {
                bail!(
                    "scope_waiver for `{}` with an empty scope list — that's a delete, not a waiver",
                    s.check
                );
            }
        }
        Ok(parsed)
    }

    /// The waivers approved for one check.
    pub fn for_check<'a>(&'a self, check: &str) -> Vec<&'a Waiver> {
        self.waiver.iter().filter(|w| w.check == check).collect()
    }

    /// The scope waiver for one check, if any.
    pub fn scope_for<'a>(&'a self, check: &str) -> Option<&'a ScopeWaiver> {
        self.scope_waiver.iter().find(|s| s.check == check)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn load_str(s: &str) -> Result<WaiverFile> {
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(s.as_bytes()).expect("write fixture");
        WaiverFile::load(f.path())
    }

    fn attested(alt1: &str, why1: &str, alt2: &str, why2: &str) -> String {
        format!(
            "{ANSWER_PREFIX}{alt1}{FAILS}{why1}{TRIED}{alt2}{FAILS}{why2}{ANSWER_SUFFIX}{GRANTER_SUFFIX}"
        )
    }

    fn entry(site_hash: &str, attestation: &str) -> String {
        format!(
            r#"
[[waiver]]
check = "expect"
file = "crates/kyzo-lsp/src/translate.rs"
line = 59
construct = "expect"
site_hash = "{site_hash}"
citation = "law:expect"
why_not_sabotage = '''{attestation}'''
"#
        )
    }

    #[test]
    fn a_canonical_entry_loads_and_binds_to_its_check() {
        let a = attested(
            "a typed refusal on the u32 conversion",
            "the LSP wire protocol fixes Position.character as u32; the value cannot exceed it",
            "clamping to u32::MAX",
            "a silent clamp fabricates a position the document does not have",
        );
        let src = format!("scope_waiver = []\n{}", entry(&"a".repeat(64), &a));
        let wf = match load_str(&src) {
            Ok(w) => w,
            Err(e) => panic!("canonical entry must load: {e:#}"),
        };
        assert_eq!(wf.for_check("expect").len(), 1);
        assert!(wf.for_check("unwrap").is_empty());
    }

    #[test]
    fn refuses_hedged_prefixed_and_missing_false_attestations() {
        let good = attested("alt one", "reason one", "alt two", "reason two");
        let hedged = format!("While context matters here, {good}");
        let src = format!("scope_waiver = []\n{}", entry(&"a".repeat(64), &hedged));
        assert!(load_str(&src).is_err(), "one hedging prefix byte must refuse");

        let no_false = good.replacen("FALSE. ", "", 1);
        let src = format!("scope_waiver = []\n{}", entry(&"a".repeat(64), &no_false));
        assert!(load_str(&src).is_err(), "missing FALSE answer must refuse");

        let src = format!(
            "scope_waiver = []\n{}",
            entry(&"a".repeat(64), "it's fine, trust me")
        );
        assert!(load_str(&src).is_err(), "prose instead of the oath must refuse");
    }

    #[test]
    fn refuses_copy_stamped_testimony_across_entries() {
        let a = attested("alt one", "shared reason", "alt two", "reason two");
        let b = attested("alt three", "shared reason", "alt four", "reason five");
        let mut e2 = entry(&"b".repeat(64), &b);
        e2 = e2.replace("line = 59", "line = 90");
        let src = format!("scope_waiver = []\n{}{}", entry(&"a".repeat(64), &a), e2);
        assert!(
            load_str(&src).is_err(),
            "identical testimony in two entries is copy-stamp — refuse"
        );
    }

    #[test]
    fn refuses_bad_site_hash_citation_forms_and_duplicates() {
        let a = attested("alt one", "reason one", "alt two", "reason two");
        let short_hash = entry("abc123", &a);
        assert!(
            load_str(&format!("scope_waiver = []\n{short_hash}")).is_err(),
            "malformed site_hash must refuse"
        );

        let b = attested("alt x", "reason x", "alt y", "reason y");
        let bad_cite = entry(&"a".repeat(64), &b).replace("law:expect", "vibes:whatever");
        assert!(
            load_str(&format!("scope_waiver = []\n{bad_cite}")).is_err(),
            "unknown citation form must refuse"
        );

        let c = attested("alt m", "reason m", "alt n", "reason n");
        let item_no_hash = entry(&"a".repeat(64), &c)
            .replace("law:expect", "item:crates/x/src/a.rs#thing");
        assert!(
            load_str(&format!("scope_waiver = []\n{item_no_hash}")).is_err(),
            "item: citation without citation_hash must refuse"
        );

        let d = attested("alt p", "reason p", "alt q", "reason q");
        let e = attested("alt r", "reason r", "alt s", "reason s");
        let dup = format!(
            "scope_waiver = []\n{}{}",
            entry(&"a".repeat(64), &d),
            entry(&"a".repeat(64), &e)
        );
        assert!(load_str(&dup).is_err(), "duplicate site must refuse");
    }

    #[test]
    fn refuses_unknown_fields_empty_scope_and_undeclared_ledgers() {
        assert!(
            load_str("waiver = []\n[[scope_waiver]]\ncheck='x'\nscope=[]\nwhy_full_scope_breaks='long enough argument text here'\n").is_err(),
            "empty scope list must refuse"
        );
        assert!(
            load_str("waiver = []\n").is_err(),
            "an undeclared ledger key must refuse — zero is stated, never defaulted"
        );
        let a = attested("alt one", "reason one", "alt two", "reason two");
        let smuggled = entry(&"a".repeat(64), &a).replace("line = 59", "line = 59\nbaseline = 5");
        assert!(
            load_str(&format!("scope_waiver = []\n{smuggled}")).is_err(),
            "unknown field must refuse"
        );
    }
}
