/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! The Boundary: what a check is entitled to see, and the proof it saw it.
//!
//! Standing operator law: every check's boundary is ALL of `crates/`.
//! No constructor here accepts a narrower path — a narrower scope exists
//! only as a `ScopeWaiver` in waivers.toml, printed on every run (BANNED
//! #20). [`CoverageProof`] records files-existing vs files-visited; any
//! gap is a red verdict.

use std::borrow::Cow;
use std::fmt;
use std::path::Path;

use anyhow::{Context, Result};
use proc_macro2::LineColumn;
use serde::Deserialize;
use walkdir::WalkDir;

/// Repo-relative UTF-8 path bytes. No `String`/`str` field — path text is
/// recovered only through [`RelPath::as_str`].
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RelPath {
    bytes: Vec<u8>,
}

impl RelPath {
    /// Admit a UTF-8 repo-relative path. The only constructor.
    pub fn admit(path: impl AsRef<str>) -> Self {
        Self {
            bytes: path.as_ref().as_bytes().to_vec(),
        }
    }

    /// UTF-8 view of admitted bytes. Corrupt bytes yield U+FFFD — never panic.
    pub(crate) fn utf8_view(bytes: &[u8]) -> &str {
        match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_not_utf8) => "\u{FFFD}",
        }
    }

    /// UTF-8 view of the admitted path.
    ///
    /// `RelPath::admit` only accepts UTF-8 text, so the `Err` arm is
    /// unreachable under that door. Sentinel on corruption — never expect.
    pub fn as_str(&self) -> &str {
        Self::utf8_view(&self.bytes)
    }

    pub fn starts_with(&self, prefix: &str) -> bool {
        self.as_str().starts_with(prefix)
    }

    pub fn ends_with(&self, suffix: &str) -> bool {
        self.as_str().ends_with(suffix)
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.as_str().contains(needle)
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for RelPath {
    fn from(path: &str) -> Self {
        Self::admit(path)
    }
}

impl From<String> for RelPath {
    fn from(path: String) -> Self {
        Self::admit(path)
    }
}

impl From<&RelPath> for RelPath {
    fn from(path: &RelPath) -> Self {
        path.clone()
    }
}

impl<'de> Deserialize<'de> for RelPath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::admit(s))
    }
}

impl PartialEq<str> for RelPath {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for RelPath {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for RelPath {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<RelPath> for str {
    fn eq(&self, other: &RelPath) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<RelPath> for String {
    fn eq(&self, other: &RelPath) -> bool {
        self.as_str() == other.as_str()
    }
}

/// UTF-8 label bytes (construct names, ban names, fn paths).
/// No `String`/`str` field — text recovered only through [`Label::as_str`].
/// Owned ([`Label::admit`]) or static registry ([`Label::admit_static`]) —
/// one brand, two doors.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Label {
    bytes: Cow<'static, [u8]>,
}

impl Label {
    /// Admit a UTF-8 label (owned bytes). Runtime / deserialize door.
    pub fn admit(text: impl AsRef<str>) -> Self {
        Self {
            bytes: Cow::Owned(text.as_ref().as_bytes().to_vec()),
        }
    }

    /// Admit static UTF-8 registry bytes. Same brand as [`admit`]; const for
    /// `const` matcher / seat tables.
    pub const fn admit_static(bytes: &'static [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(bytes),
        }
    }

    pub fn as_str(&self) -> &str {
        RelPath::utf8_view(self.bytes.as_ref())
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.as_str().contains(needle)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Label {
    fn from(text: &str) -> Self {
        Self::admit(text)
    }
}

impl From<String> for Label {
    fn from(text: String) -> Self {
        Self::admit(text)
    }
}

impl From<&Label> for Label {
    fn from(text: &Label) -> Self {
        text.clone()
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::admit(s))
    }
}

impl PartialEq<str> for Label {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Label {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for Label {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other.as_str()
    }
}

impl PartialEq<Label> for str {
    fn eq(&self, other: &Label) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<Label> for String {
    fn eq(&self, other: &Label) -> bool {
        self.as_str() == other.as_str()
    }
}

/// One parsed source file inside the boundary. The AST is parsed once here
/// and shared by every engine — a second parse authority would let two
/// checks disagree about what the file says.
///
/// Fields are private (TRUTH item 9). The sole admission door is
/// [`SourceFile::admit`]; engines read through accessors.
/// No `String`/`str` terminals — path is [`RelPath`], text is UTF-8 bytes.
pub struct SourceFile {
    /// Repo-root-relative path, e.g. `crates/kyzo-core/src/data/tuple.rs`.
    rel_path: RelPath,
    text: Vec<u8>,
    ast: syn::File,
}

impl SourceFile {
    /// Sole admission constructor — the only way to build a [`SourceFile`].
    pub fn admit(rel_path: impl Into<RelPath>, text: impl AsRef<str>, ast: syn::File) -> Self {
        Self {
            rel_path: rel_path.into(),
            text: text.as_ref().as_bytes().to_vec(),
            ast,
        }
    }

    pub fn rel_path(&self) -> &str {
        self.rel_path.as_str()
    }

    /// The admitted [`RelPath`] itself — for callers that must hold it as a
    /// non-string-terminal field (TRUTH item 9 sealed-struct law).
    pub fn rel_path_ref(&self) -> &RelPath {
        &self.rel_path
    }

    /// Source text as UTF-8. Corrupt bytes yield U+FFFD — never expect.
    pub fn text(&self) -> &str {
        RelPath::utf8_view(&self.text)
    }

    pub fn ast(&self) -> &syn::File {
        &self.ast
    }
}

/// A file inside the boundary that refused to parse. Not silently skipped:
/// an unparseable file is invisible to every syn-based check, which is
/// exactly how a hidden violation would ride in — so the run reports it.
///
/// Fields are private (TRUTH item 9). Sole admission is [`UnparsedFile::admit`].
/// Path is [`RelPath`]; parse error text is [`Label`] — no `String` terminals.
pub struct UnparsedFile {
    rel_path: RelPath,
    error: Label,
}

impl UnparsedFile {
    /// Sole admission constructor.
    pub fn admit(rel_path: impl Into<RelPath>, error: impl Into<Label>) -> Self {
        Self {
            rel_path: rel_path.into(),
            error: error.into(),
        }
    }

    pub fn rel_path(&self) -> &RelPath {
        &self.rel_path
    }

    pub fn error(&self) -> &str {
        self.error.as_str()
    }
}

/// The whole boundary, walked once: every `.rs` file under `crates/`
/// (sources, integration tests, benches, examples — everything that is
/// code), excluding only build artifacts (`target/`).
///
/// Fields are private (TRUTH item 9). Sole production admission is
/// [`Boundary::walk`]; tests use [`Boundary::admit`].
pub struct Boundary {
    files: Vec<SourceFile>,
    unparsed: Vec<UnparsedFile>,
    /// Every `.rs` path that exists in the boundary right now, whether or
    /// not it parsed — the denominator of the coverage proof.
    existing: Vec<RelPath>,
}

/// The proof a run saw the whole boundary: files that exist vs files the
/// walk delivered to the engines. `gap()` non-empty is a run-level red.
///
/// Fields are private (TRUTH item 9). [`CoverageProof::admit`] is the sole
/// constructor.
pub struct CoverageProof {
    existing: usize,
    visited: usize,
    missing: Vec<RelPath>,
}

impl CoverageProof {
    /// Sole admission constructor.
    pub fn admit(existing: usize, visited: usize, missing: Vec<RelPath>) -> Self {
        Self {
            existing,
            visited,
            missing,
        }
    }

    pub fn existing(&self) -> usize {
        self.existing
    }

    pub fn visited(&self) -> usize {
        self.visited
    }

    pub fn missing(&self) -> &[RelPath] {
        &self.missing
    }
}

impl Boundary {
    /// Test/harness admission — the only non-walk constructor.
    pub fn admit(
        files: Vec<SourceFile>,
        unparsed: Vec<UnparsedFile>,
        existing: Vec<RelPath>,
    ) -> Self {
        Self {
            files,
            unparsed,
            existing,
        }
    }

    pub fn files(&self) -> &[SourceFile] {
        &self.files
    }

    pub fn unparsed(&self) -> &[UnparsedFile] {
        &self.unparsed
    }

    pub fn existing(&self) -> &[RelPath] {
        &self.existing
    }

    /// Walk all of `crates/` under `root`. The only exclusion is `target/`
    /// build output — never a crate, never a directory of meaning.
    pub fn walk(root: &Path) -> Result<Boundary> {
        let crates_dir = root.join("crates");
        let mut files = Vec::new();
        let mut unparsed = Vec::new();
        let mut existing = Vec::new();

        for entry in WalkDir::new(&crates_dir)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| e.file_name() != "target")
        {
            let entry = entry.with_context(|| "walking crates/")?;
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().map(|x| x == "rs") != Some(true) {
                continue;
            }
            let rel = rel_path(root, path)?;
            existing.push(rel.clone());
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {rel}"))?;
            match syn::parse_file(&text) {
                Ok(ast) => files.push(SourceFile::admit(rel, text, ast)),
                Err(e) => unparsed.push(UnparsedFile::admit(rel, e.to_string())),
            }
        }
        Ok(Boundary::admit(files, unparsed, existing))
    }

    /// The coverage proof for this walk: every existing file is either a
    /// parsed [`SourceFile`] or a reported [`UnparsedFile`]; anything else
    /// is a hole the run must refuse over.
    pub fn coverage_proof(&self) -> CoverageProof {
        let mut visited: Vec<&str> = self
            .files
            .iter()
            .map(|f| f.rel_path.as_str())
            .chain(self.unparsed.iter().map(|u| u.rel_path.as_str()))
            .collect();
        visited.sort_unstable();
        let missing: Vec<RelPath> = self
            .existing
            .iter()
            .filter(|e| visited.binary_search(&e.as_str()).is_err())
            .cloned()
            .collect();
        CoverageProof::admit(self.existing.len(), visited.len(), missing)
    }
}

fn rel_path(root: &Path, path: &Path) -> Result<RelPath> {
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("{} is outside the repo root", path.display()))?;
    Ok(RelPath::admit(rel.to_string_lossy().replace('\\', "/")))
}

/// The one line-number authority: every finding's line comes from the
/// span's start, matching what an editor shows.
pub fn span_line(span: &proc_macro2::Span) -> usize {
    let LineColumn { line, .. } = span.start();
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_covers_every_rs_file_and_proof_balances() {
        let dir = tempfile::tempdir().expect("tempdir for fixture tree");
        let root = dir.path();
        std::fs::create_dir_all(root.join("crates/a/src")).expect("mkdir a");
        std::fs::create_dir_all(root.join("crates/b/tests")).expect("mkdir b");
        std::fs::create_dir_all(root.join("crates/a/target/debug")).expect("mkdir target");
        std::fs::write(root.join("crates/a/src/lib.rs"), "pub fn f() {}\n").expect("write");
        std::fs::write(root.join("crates/b/tests/t.rs"), "#[test] fn t() {}\n").expect("write");
        std::fs::write(root.join("crates/a/src/broken.rs"), "fn {{{\n").expect("write");
        // target/ output must be invisible; everything else must be seen.
        std::fs::write(root.join("crates/a/target/debug/gen.rs"), "fn x() {}\n").expect("write");

        let b = Boundary::walk(root).expect("walk");
        assert_eq!(b.files().len(), 2, "lib.rs and tests/t.rs parse");
        assert_eq!(b.unparsed().len(), 1, "broken.rs is REPORTED, not skipped");
        assert_eq!(b.existing().len(), 3, "target/ is excluded from existence");
        let proof = b.coverage_proof();
        assert_eq!(proof.existing(), 3);
        assert_eq!(proof.visited(), 3);
        // Exact empty slice — soft is_empty hid a coverage_hole path while
        // existing==visited still looked balanced (AGENT_TESTING_LAW §7).
        assert_eq!(
            proof.missing(),
            &[] as &[RelPath],
            "costume: path in missing while counts look balanced"
        );
    }

    /// Tip 686 / tip 659 ban-list: `target/` is the ONLY walk exclusion.
    /// Fixtures were once filtered out (silent undercount of deny specimens).
    #[test]
    fn anti_fraud_fixtures_dir_is_walked_not_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("crates/bs-detector/fixtures")).expect("mkdir");
        std::fs::create_dir_all(root.join("crates/bs-detector/src")).expect("mkdir src");
        std::fs::write(
            root.join("crates/bs-detector/src/lib.rs"),
            "pub fn ok() {}\n",
        )
        .expect("write lib");
        std::fs::write(
            root.join("crates/bs-detector/fixtures/specimen.rs"),
            "fn hidden_violation() {}\n",
        )
        .expect("write fixture");
        let b = Boundary::walk(root).expect("walk");
        let paths: Vec<&str> = b.files().iter().map(|f| f.rel_path()).collect();
        assert_eq!(
            paths.contains(&"crates/bs-detector/fixtures/specimen.rs"),
            true,
            "costume: fixtures/ skipped from boundary walk — paths={paths:?}"
        );
        assert_eq!(b.existing().len(), 2, "lib + fixture both exist");
    }
}
