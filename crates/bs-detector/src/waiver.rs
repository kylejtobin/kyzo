/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! An approved waiver: the ONLY way a detector hit survives without a fix.
//!
//! A waiver binds to content (TRUTH item 6): check, file, construct, and
//! `site_hash` (blake3 of the item's [`crate::identity::identity_tokens`]).
//! The `line` field is display-only — a `//` inserted above the item shifts
//! the editor line but does not stale the ruling. A content edit that
//! changes the site hash makes the waiver STALE: it stops applying and is
//! reported.
//!
//! Every waiver also cites a checkable anchor (TRUTH item 7): `citation`
//! plus `anchor_hash`. Missing target or hash mismatch is `dead_citation`;
//! the waiver stops applying. Blanket waiver entrys are not representable.
//!
//! Every waiver's `why_not_sabotage` IS the canonical attestation template
//! with filled slots, byte-exact (TRUTH item 8), or `WaiverFile::load`
//! refuses the whole file. The template (verbatim deception question,
//! required FALSE answer, required sentences, named slots) lives beside
//! this schema in `attestation_template.toml`.
//!
//! File format: `crates/bs-detector/waivers.toml`, one `[[waiver]]` table
//! per waiver entry, plus `[[scope_waiver]]` for the single lawful way a
//! check runs narrower than all of `crates/` (BANNED #20 made data).

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::citation::Citation;

/// Canonical attestation template embedded from the file beside this schema.
const ATTESTATION_TEMPLATE_TOML: &str = include_str!("../attestation_template.toml");

/// One segment of the attestation template: fixed bytes or a named slot.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TemplateSegment {
    Fixed { text: String },
    Slot { name: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateFile {
    segment: Vec<TemplateSegment>,
}

/// The load-door attestation form: fixed/slot/fixed… covering every byte.
#[derive(Clone, Debug)]
pub struct AttestationTemplate {
    segments: Vec<TemplateSegment>,
}

impl AttestationTemplate {
    /// Parse the canonical template that lives beside the waiver schema.
    pub fn load_canonical() -> Result<AttestationTemplate> {
        Self::parse(ATTESTATION_TEMPLATE_TOML)
            .context("parsing attestation_template.toml beside waiver schema")
    }

    fn parse(toml_text: &str) -> Result<AttestationTemplate> {
        let file: TemplateFile = toml::from_str(toml_text).context("attestation template toml")?;
        if file.segment.is_empty() {
            bail!("attestation template has no segments");
        }
        // Must alternate starting with fixed; every slot has a following
        // fixed delimiter (last segment is fixed — the GRANTER close).
        for (i, seg) in file.segment.iter().enumerate() {
            match seg {
                TemplateSegment::Fixed { text } => {
                    if text.is_empty() {
                        bail!("attestation template fixed segment {i} is empty");
                    }
                }
                TemplateSegment::Slot { name } => {
                    if name.is_empty() {
                        bail!("attestation template slot {i} has empty name");
                    }
                    if i == 0 {
                        bail!("attestation template must start with a fixed segment");
                    }
                    match file.segment.get(i + 1) {
                        Some(TemplateSegment::Fixed { .. }) => {}
                        Some(TemplateSegment::Slot { .. }) => {
                            bail!("attestation template slot `{name}` is followed by another slot")
                        }
                        None => {
                            bail!(
                                "attestation template slot `{name}` is last — slots need a following fixed delimiter"
                            )
                        }
                    }
                }
            }
        }
        if !matches!(file.segment.last(), Some(TemplateSegment::Fixed { .. })) {
            bail!("attestation template must end with a fixed segment");
        }
        Ok(AttestationTemplate {
            segments: file.segment,
        })
    }

    /// Segment `why` against this template. Full coverage, non-empty slots,
    /// or a named refusal. Any leftover byte is outside every slot.
    pub fn segment(&self, why: &str) -> Result<Vec<(String, String)>, String> {
        let mut pos = 0usize;
        let mut filled: Vec<(String, String)> = Vec::new();
        let mut i = 0usize;
        while i < self.segments.len() {
            match &self.segments[i] {
                TemplateSegment::Fixed { text } => {
                    let rest = match why.get(pos..) {
                        Some(r) => r,
                        None => "",
                    };
                    if !rest.starts_with(text.as_str()) {
                        return Err(format!(
                            "attestation fixed segment {i} mismatch at byte {pos}"
                        ));
                    }
                    pos += text.len();
                    i += 1;
                }
                TemplateSegment::Slot { name } => {
                    let delim = match self.segments.get(i + 1) {
                        Some(TemplateSegment::Fixed { text }) => text.as_str(),
                        _ => {
                            return Err(format!(
                                "attestation slot `{name}` has no following fixed delimiter"
                            ));
                        }
                    };
                    let rest = match why.get(pos..) {
                        Some(r) => r,
                        None => "",
                    };
                    let Some(rel) = rest.find(delim) else {
                        return Err(format!(
                            "attestation slot `{name}`: following fixed delimiter not found"
                        ));
                    };
                    if rel == 0 {
                        return Err(format!("attestation slot `{name}` is empty"));
                    }
                    let content = &rest[..rel];
                    filled.push((name.clone(), content.to_string()));
                    pos += rel;
                    // Next loop iteration matches the delimiter as Fixed.
                    i += 1;
                }
            }
        }
        if pos != why.len() {
            return Err(format!(
                "attestation has {} byte(s) outside every slot (after byte {pos})",
                why.len() - pos
            ));
        }
        Ok(filled)
    }

    /// Fill the canonical template with non-empty slot values (test/helper).
    pub fn fill(&self, slots: &[(&str, &str)]) -> Result<String, String> {
        let mut out = String::new();
        let mut slot_i = 0usize;
        for seg in &self.segments {
            match seg {
                TemplateSegment::Fixed { text } => out.push_str(text),
                TemplateSegment::Slot { name } => {
                    let Some((n, v)) = slots.get(slot_i) else {
                        return Err(format!("missing slot value for `{name}`"));
                    };
                    if *n != name.as_str() {
                        return Err(format!("slot order: expected `{name}`, got `{n}`"));
                    }
                    if v.is_empty() {
                        return Err(format!("slot `{name}` must be non-empty"));
                    }
                    out.push_str(v);
                    slot_i += 1;
                }
            }
        }
        if slot_i != slots.len() {
            return Err(format!(
                "extra slot values: got {}, template has {slot_i}",
                slots.len()
            ));
        }
        // Refuse fill values that would break delimiter scan.
        self.segment(&out)?;
        Ok(out)
    }
}

/// One approved, content-bound waiver entry.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    /// The registered check this covers a hit of (must exist in
    /// checks.toml — a waiver naming an unknown check is a load error).
    pub check: String,
    /// Repo-root-relative file of the waived site.
    pub file: String,
    /// Display-only 1-indexed line (editor coordinate). Never used to
    /// decide whether the waiver still applies — that is `site_hash`.
    pub line: usize,
    /// The construct at the site, exactly as the check reports it (pattern
    /// name for shape checks, function/member name for graph checks).
    pub construct: String,
    /// Blake3 hex of the waived item's identity tokens (TRUTH item 6).
    /// Mismatch against the live item = STALE; the waiver stops applying.
    pub site_hash: String,
    /// Checkable anchor (TRUTH item 7): laws.toml law name, file#item-path,
    /// `file.rs::test_fn`, or `decisions.md#N`.
    pub citation: String,
    /// Blake3 hex of the cited anchor's identity at grant time. Mismatch
    /// or missing target = dead_citation; the waiver stops applying.
    pub anchor_hash: String,
    /// The canonical attestation template with filled slots (TRUTH item 8).
    /// Fit of slot prose to the citation is NOT mechanically verified
    /// (laws.toml residual `R-citation-prose`).
    pub why_not_sabotage: String,
}

/// The single lawful narrow scope: a check whose boundary is less than all
/// of `crates/` must carry one of these, stating why full scope BREAKS the
/// check (not why it's inconvenient). The meta engine prints every one on
/// every run — narrow scope is always visible, never ambient.
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
    /// `waiver = []`, stated on purpose — zero waiver entrys is a claim the
    /// file makes, never a shape it defaults into.
    pub waiver: Vec<Waiver>,
    pub scope_waiver: Vec<ScopeWaiver>,
}

impl WaiverFile {
    /// Load and validate. Refuses: attestation form mismatch (TRUTH item 8),
    /// duplicate content bindings, malformed site_hash/anchor_hash,
    /// unparseable citation grammar, and unknown fields. One bad entry
    /// refuses the whole file.
    pub fn load(path: &Path) -> Result<WaiverFile> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let parsed: WaiverFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let template = AttestationTemplate::load_canonical()?;

        let mut seen: BTreeSet<(String, String, String, String)> = BTreeSet::new();
        for w in &parsed.waiver {
            if let Err(e) = template.segment(&w.why_not_sabotage) {
                bail!(
                    "waiver {}:{} ({}) — attestation refused: {e}",
                    w.file,
                    w.line,
                    w.construct
                );
            }
            if w.site_hash.len() != 64 || !w.site_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!(
                    "waiver {}:{} ({}) — site_hash must be 64 hex chars (blake3 of identity_tokens)",
                    w.file,
                    w.line,
                    w.construct
                );
            }
            if w.anchor_hash.len() != 64 || !w.anchor_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!(
                    "waiver {}:{} ({}) — anchor_hash must be 64 hex chars (blake3 of cited anchor)",
                    w.file,
                    w.line,
                    w.construct
                );
            }
            if let Err(e) = Citation::parse(&w.citation) {
                bail!(
                    "waiver {}:{} ({}) — citation grammar refused: {e}",
                    w.file,
                    w.line,
                    w.construct
                );
            }
            let key = (
                w.check.clone(),
                w.file.clone(),
                w.construct.clone(),
                w.site_hash.clone(),
            );
            if !seen.insert(key) {
                bail!(
                    "duplicate waiver for {} ({}) site_hash={} — one waiver entry per content site",
                    w.file,
                    w.construct,
                    w.site_hash
                );
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
            for p in &s.scope {
                if p.trim().is_empty() {
                    bail!(
                        "scope_waiver for `{}` has an empty path — that matches nothing",
                        s.check
                    );
                }
                if !p.ends_with('/') {
                    bail!(
                        "scope_waiver for `{}` path `{p}` must end in `/` — a prefix without a slash silently overlaps neighbors",
                        s.check
                    );
                }
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
        let mut f = match tempfile::NamedTempFile::new() {
            Ok(f) => f,
            Err(e) => bail!("tempfile: {e}"),
        };
        f.write_all(s.as_bytes())
            .map_err(|e| anyhow::anyhow!("write fixture: {e}"))?;
        WaiverFile::load(f.path())
    }

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ANCHOR: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A valid filled attestation (canonical template slots).
    fn valid_why() -> String {
        let t = AttestationTemplate::load_canonical().expect("canonical template");
        t.fill(&[
            ("alt_one", "a typed Result refusal at this call site"),
            (
                "reason_one",
                "the wire protocol type is u32 and Result would invent a domain error the protocol does not have",
            ),
            ("alt_two", "returning a sentinel zero"),
            (
                "reason_two",
                "zero is a real column and would lie to the editor",
            ),
        ])
        .expect("fill")
    }

    fn toml_escape(s: &str) -> String {
        let mut out = String::from('"');
        for c in s.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    fn waiver_toml(why: &str, extra: &str) -> String {
        format!(
            r#"
scope_waiver = []

[[waiver]]
check = "expect"
file = "crates/kyzo-lsp/src/translate.rs"
line = 59
construct = "expect"
site_hash = "{HASH}"
citation = "expect"
anchor_hash = "{ANCHOR}"
why_not_sabotage = {why}
{extra}
"#,
            why = toml_escape(why)
        )
    }

    #[test]
    fn a_real_waiver_loads_and_binds_to_its_check() {
        let wf = load_str(&waiver_toml(&valid_why(), "")).expect("loads");
        assert_eq!(wf.for_check("expect").len(), 1);
        assert!(wf.for_check("unwrap").is_empty());
        assert_eq!(wf.waiver[0].site_hash, HASH);
        assert_eq!(wf.waiver[0].citation, "expect");
        assert_eq!(wf.waiver[0].anchor_hash, ANCHOR);
    }

    #[test]
    fn item_8_proof_required_sentences_plus_hedge_refuses() {
        // TRUTH item 8 Proof: required sentences + one hedging sentence → refuse.
        let mut hedged = valid_why();
        hedged.push_str(" I believe this is mostly fine.");
        let e = load_str(&waiver_toml(&hedged, ""));
        assert!(
            e.is_err(),
            "extra hedging sentence outside every slot must refuse the file"
        );
        let msg = format!("{}", e.unwrap_err());
        assert!(
            msg.contains("outside every slot") || msg.contains("attestation refused"),
            "refusal must name the attestation/slot breach, got: {msg}"
        );
    }

    #[test]
    fn item_8_proof_missing_false_answer_refuses() {
        // TRUTH item 8 Proof: missing FALSE answer → refuse.
        let why = valid_why().replacen("\n\nFALSE.", "\n\nTRUE.", 1);
        assert!(
            why.contains("\n\nTRUE."),
            "fixture must actually replace FALSE with TRUE"
        );
        let e = load_str(&waiver_toml(&why, ""));
        assert!(
            e.is_err(),
            "TRUE in place of required FALSE must refuse the file"
        );
    }

    #[test]
    fn item_8_empty_slot_refuses() {
        let t = AttestationTemplate::load_canonical().expect("template");
        let mut raw = String::new();
        for seg in &t.segments {
            match seg {
                TemplateSegment::Fixed { text } => raw.push_str(text),
                TemplateSegment::Slot { name } if name == "alt_one" => {}
                TemplateSegment::Slot { name } if name == "reason_one" => {
                    raw.push_str("reason one text")
                }
                TemplateSegment::Slot { name } if name == "alt_two" => {
                    raw.push_str("alt two text")
                }
                TemplateSegment::Slot { name } if name == "reason_two" => {
                    raw.push_str("reason two text")
                }
                TemplateSegment::Slot { name } => {
                    panic!("unexpected slot {name}");
                }
            }
        }
        let e = load_str(&waiver_toml(&raw, ""));
        assert!(e.is_err(), "empty slot must refuse");
    }

    #[test]
    fn refuses_duplicate_content_site() {
        let why = toml_escape(&valid_why());
        let e = load_str(&format!(
            r#"
scope_waiver = []

[[waiver]]
check = "expect"
file = "a.rs"
line = 1
construct = "expect"
site_hash = "{HASH}"
citation = "expect"
anchor_hash = "{ANCHOR}"
why_not_sabotage = {why}

[[waiver]]
check = "expect"
file = "a.rs"
line = 99
construct = "expect"
site_hash = "{HASH}"
citation = "expect"
anchor_hash = "{ANCHOR}"
why_not_sabotage = {why}
"#
        ));
        assert!(
            e.is_err(),
            "duplicate content site (same site_hash) must refuse even when display lines differ"
        );
    }

    #[test]
    fn refuses_malformed_site_hash_citation_and_missing_anchor() {
        let why = valid_why();
        assert!(
            load_str(&format!(
                r#"
scope_waiver = []

[[waiver]]
check = "expect"
file = "a.rs"
line = 1
construct = "expect"
site_hash = "deadbeef"
citation = "expect"
anchor_hash = "{ANCHOR}"
why_not_sabotage = {why}
"#,
                why = toml_escape(&why)
            ))
            .is_err(),
            "short site_hash must refuse"
        );
        assert!(
            load_str(&format!(
                r#"
scope_waiver = []

[[waiver]]
check = "expect"
file = "a.rs"
line = 1
construct = "expect"
site_hash = "{HASH}"
citation = "crates/x/src/a.rs#"
anchor_hash = "{ANCHOR}"
why_not_sabotage = {why}
"#,
                why = toml_escape(&why)
            ))
            .is_err(),
            "malformed file#item-path must refuse"
        );
        assert!(
            load_str(&format!(
                r#"
scope_waiver = []

[[waiver]]
check = "expect"
file = "a.rs"
line = 1
construct = "expect"
site_hash = "{HASH}"
citation = "expect"
why_not_sabotage = {why}
"#,
                why = toml_escape(&why)
            ))
            .is_err(),
            "missing anchor_hash must refuse"
        );
    }

    #[test]
    fn refuses_unknown_fields_and_empty_scope() {
        let why = toml_escape(&valid_why());
        assert!(
            load_str(&format!(
                "scope_waiver = []\n[[waiver]]\ncheck='x'\nfile='a'\nline=1\nconstruct='c'\nsite_hash='{HASH}'\ncitation='x'\nanchor_hash='{ANCHOR}'\nwhy_not_sabotage={why}\nbaseline=5\n"
            ))
            .is_err(),
            "unknown field (e.g. a smuggled 'baseline') must refuse"
        );
        assert!(
            load_str("waiver = []\n[[scope_waiver]]\ncheck='x'\nscope=[]\nwhy_full_scope_breaks='long enough argument text here'\n").is_err(),
            "empty scope list must refuse"
        );
        assert!(
            load_str("waiver = []\n").is_err(),
            "an undeclared ledger key must refuse — zero is stated, never defaulted"
        );
    }

    /// Scope prefixes without a trailing `/` silently overlap neighbors
    /// (`crates/foo` matches `crates/foobar`). Same law as [seats].hosts.
    #[test]
    fn scope_waiver_path_without_trailing_slash_is_a_load_error() {
        let err = load_str(
            "waiver = []\n[[scope_waiver]]\ncheck='expect'\nscope=['crates/bs-detector']\nwhy_full_scope_breaks='long enough argument text here'\n",
        )
        .expect_err("scope path without trailing slash must refuse");
        assert_eq!(
            format!("{err}"),
            "scope_waiver for `expect` path `crates/bs-detector` must end in `/` — a prefix without a slash silently overlaps neighbors"
        );
    }

    #[test]
    fn empty_waiver_ledger_loads_when_both_keys_stated() {
        let wf = load_str("waiver = []\nscope_waiver = []\n").expect("empty ledgers load");
        assert!(wf.waiver.is_empty());
        assert!(wf.scope_waiver.is_empty());
    }

    #[test]
    fn freeform_pre_attestation_justification_refuses() {
        // No grandfathering: legacy freeform why_not_sabotage is not the template.
        let e = load_str(&waiver_toml(
            "LSP Position.character is u32 by wire protocol; a >4B-unit line is outside the protocol's representable range.",
            "",
        ));
        assert!(
            e.is_err(),
            "pre-attestation freeform justification must refuse at the load door"
        );
    }
}
