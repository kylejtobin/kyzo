/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * Use of this software is governed by the Business Source License 1.1
 * included in the repository as LICENSE-BSL. See LICENSING.md.
 *
 * Change Date:    2030-07-11
 * Change License: Mozilla Public License, version 2.0
 */

//! AUTHORITY: The forbidden shapes. A blacklist, and only what a script can
//! decide with certainty.
//!
//! Twelve rules. Each one is decidable from syntax alone — no type resolution,
//! no macro expansion, no call graph. That is the whole design constraint, and
//! it is why the previous machine was deleted: 68% of its reported number was
//! `unproven receiver` / `unproven macro` / `unproven path` / `unproven
//! foreign`, which is a parser without types reporting its own blindness as
//! findings about the tree.
//!
//! Every rule here is absolute. The moment a rule needs a clause like "…where a
//! domain fact belongs" it stops being decidable and does not belong in this
//! file. Rules that need judgment are enforced by review, not by this binary,
//! and pretending otherwise is how the count became noise.
//!
//! This crate is a workspace member on purpose: the detector scans itself.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A forbidden shape, with the file and line that holds it.
struct Violation {
    rule: &'static str,
    file: String,
    line: usize,
    detail: String,
}

/// The twelve rules, as the report prints them.
const RULES: &[(&str, &str)] = &[
    ("R01", "Ord/PartialOrd/Hash with no ORDER_LAW stated in the file"),
    ("R02", "pub field on a newtype, or a public unchecked constructor"),
    ("R03", "bare Vec/HashMap/HashSet as a pub field"),
    ("R04", "unwrap/expect/panic! outside tests"),
    ("R05", "String-typed error, or a refusal carrying no span"),
    ("R06", "todo!/unimplemented!/unreachable! stub"),
    ("R07", "env::var read outside a config seat"),
    ("R08", "String-typed kind/status/type/name field"),
    ("R09", "bool field carrying a domain decision"),
    ("R10", "bare primitive field outside a newtype"),
    ("R11", "RefCell/Cell/Mutex/RwLock field in a domain type"),
    ("R12", "f32/f64 field in a type that derives an order"),
];

/// Files that are vendored data tables, not architecture. Cozo carries the
/// same two under the same MIT terms.
const VENDORED: &[&str] = &["stopwords.rs", "ascii_folding_filter.rs"];

/// The one seat allowed to read the environment.
const CONFIG_SEATS: &[&str] = &["config.rs", "main.rs", "cli.rs"];

/// How the detector was asked.
///
/// `Gate` is the harness: it walks `crates/` and writes the verdict the pester
/// hook reads. `Aim` is one path — a file or a directory — reported to stdout
/// and nothing else. Aiming never writes the verdict, because a verdict about
/// one file is not a verdict about the tree, and a harness that could be
/// satisfied by narrowing its scope is not a harness.
enum Mode {
    Gate { root: PathBuf },
    Aim { target: PathBuf },
}

// Note: neither mode writes crates/xtask/gate.log. The verdict combines this
// report with whether the tree compiles, and only crates/xtask/gate.sh holds
// both facts. A detector that authored the verdict would be claiming a green
// tree it never built.

fn main() {
    let mut root = PathBuf::from(".");
    let mut target: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            // --now-unix is accepted and ignored: this detector never reads a
            // clock, so a replay needs no instant pinned into it.
            "--root" => {
                if let Some(v) = args.next() {
                    root = PathBuf::from(v);
                }
            }
            "--now-unix" => {
                let _ = args.next();
            }
            "--file" | "--path" => {
                if let Some(v) = args.next() {
                    target = Some(PathBuf::from(v));
                }
            }
            other if !other.starts_with("--") => target = Some(PathBuf::from(other)),
            _ => {}
        }
    }
    let mode = match target {
        Some(t) => Mode::Aim { target: t },
        None => Mode::Gate { root: root.clone() },
    };

    let mut files = Vec::new();
    match &mode {
        Mode::Gate { root } => collect(&root.join("crates"), &mut files),
        Mode::Aim { target } => {
            if target.is_dir() {
                collect(target, &mut files);
            } else {
                files.push(target.clone());
            }
        }
    }
    files.sort();

    let mut violations = Vec::new();
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let name = f.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if VENDORED.contains(&name) {
            continue;
        }
        let rel = f.strip_prefix(&root).unwrap_or(f).display().to_string();
        scan(&rel, name, &text, &mut violations);
    }

    match mode {
        Mode::Gate { root } => report_gate(&root, &files, &violations),
        Mode::Aim { .. } => report_aim(&files, &violations),
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if n != "target" && n != ".git" {
                collect(&p, out);
            }
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

/// True while the line sits inside a `#[cfg(test)]` module or a `#[test]` fn.
struct TestTracker {
    depth: i32,
    armed: bool,
    brace: i32,
}

impl TestTracker {
    fn new() -> Self {
        Self { depth: 0, armed: false, brace: 0 }
    }

    fn feed(&mut self, line: &str) -> bool {
        let t = line.trim();
        if t.starts_with("#[cfg(test)]") || t.starts_with("#[test]") || t.starts_with("#[tokio::test]")
        {
            self.armed = true;
        }
        let inside = self.depth > 0;
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;
        if self.armed && opens > 0 {
            self.armed = false;
            self.depth += 1;
            self.brace = opens - closes;
            return true;
        }
        if self.depth > 0 {
            self.brace += opens - closes;
            if self.brace <= 0 {
                self.depth -= 1;
            }
        }
        inside
    }
}

fn scan(rel: &str, name: &str, text: &str, out: &mut Vec<Violation>) {
    let is_test_file = rel.contains("/tests/")
        || rel.contains("kyzo-trials")
        || rel.contains("kyzo-oracle")
        || rel.contains("canonical-trials")
        || rel.contains("kyzo-crashfs")
        || name.ends_with("_tests.rs")
        || name == "tests.rs";

    let states_order_law = text.contains("ORDER_LAW");
    let mut tt = TestTracker::new();

    // Struct/enum context for the field rules.
    let mut in_type: Option<(String, bool)> = None; // (name, derives_order)
    let mut pending_derives = String::new();
    let mut brace = 0i32;

    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        let in_test = tt.feed(raw) || is_test_file;
        let t = raw.trim();
        let code = strip_literals(t.split("//").next().unwrap_or(t).trim());
        let code = code.as_str();

        // ---- token rules -------------------------------------------------
        if !in_test {
            if code.contains(".unwrap()") || code.contains(".expect(") || code.contains("panic!(") {
                push(out, "R04", rel, line, code);
            }
            if code.contains("todo!(") || code.contains("unimplemented!(") || code.contains("unreachable!(")
            {
                push(out, "R06", rel, line, code);
            }
            if (code.contains("env::var") || code.contains("std::env::var"))
                && !CONFIG_SEATS.contains(&name)
            {
                push(out, "R07", rel, line, code);
            }
            if code.contains("Result<") && code.contains(", String>") {
                push(out, "R05", rel, line, code);
            }
        }

        // ---- type context ------------------------------------------------
        if code.starts_with("#[derive(") {
            pending_derives = code.to_string();
        }
        if let Some(rest) = type_header(code) {
            let derives_order = pending_derives.contains("Ord")
                || pending_derives.contains("PartialOrd")
                || pending_derives.contains("Hash");
            if derives_order && !states_order_law && !in_test {
                push(out, "R01", rel, line, &format!("{rest} derives an order"));
            }
            in_type = Some((rest.to_string(), derives_order));
            brace = code.matches('{').count() as i32 - code.matches('}').count() as i32;
            // tuple newtype with a pub field: `pub struct X(pub T);`
            if code.contains("(pub ") {
                push(out, "R02", rel, line, code);
            }
            pending_derives.clear();
            continue;
        }
        if code.starts_with("impl Ord for")
            || code.starts_with("impl PartialOrd for")
            || code.starts_with("impl Hash for")
        {
            if !states_order_law && !in_test {
                push(out, "R01", rel, line, code);
            }
        }

        if in_type.is_some() {
            brace += code.matches('{').count() as i32 - code.matches('}').count() as i32;
            if brace <= 0 {
                in_type = None;
                continue;
            }
        }

        // ---- field rules ---------------------------------------------------
        let Some((_, derives_order)) = in_type.as_ref() else {
            continue;
        };
        if in_test {
            continue;
        }
        let Some((fname, fty, is_pub)) = field(code) else {
            continue;
        };

        if is_pub && (fty.starts_with("Vec<") || fty.starts_with("HashMap") || fty.starts_with("HashSet"))
        {
            push(out, "R03", rel, line, code);
        }
        if is_pub {
            push(out, "R02", rel, line, code);
        }
        let lower = fname.to_ascii_lowercase();
        if (fty == "String" || fty.starts_with("SmartString"))
            && (lower == "kind" || lower == "status" || lower == "type" || lower == "name" || lower == "state")
        {
            push(out, "R08", rel, line, code);
        }
        if fty == "bool" {
            push(out, "R09", rel, line, code);
        }
        if matches!(
            fty.as_str(),
            "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128" | "isize"
        ) {
            push(out, "R10", rel, line, code);
        }
        if fty.starts_with("RefCell")
            || fty.starts_with("Cell<")
            || fty.starts_with("Mutex")
            || fty.starts_with("RwLock")
        {
            push(out, "R11", rel, line, code);
        }
        if (fty == "f32" || fty == "f64") && *derives_order {
            push(out, "R12", rel, line, code);
        }
    }
}

/// Blank the contents of string literals. A token inside a literal is data,
/// not a shape — this detector's own rule text would otherwise report the
/// detector.
fn strip_literals(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let mut in_str = false;
    let mut escape = false;
    for c in code.chars() {
        if in_str {
            if escape {
                escape = false;
                out.push(' ');
            } else if c == '\\' {
                escape = true;
                out.push(' ');
            } else if c == '"' {
                in_str = false;
                out.push('"');
            } else {
                out.push(' ');
            }
        } else if c == '"' {
            in_str = true;
            out.push('"');
        } else {
            out.push(c);
        }
    }
    out
}

/// `pub struct Foo {` / `enum Foo {` → the declared name.
fn type_header(code: &str) -> Option<&str> {
    let rest = code
        .strip_prefix("pub ")
        .or_else(|| code.strip_prefix("pub(crate) "))
        .unwrap_or(code);
    let rest = rest.strip_prefix("struct ").or_else(|| rest.strip_prefix("enum "))?;
    let name = rest
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .next()
        .unwrap_or_default();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// `pub name: Type,` → (name, Type, is_pub).
fn field(code: &str) -> Option<(String, String, bool)> {
    let (is_pub, rest) = if let Some(r) = code.strip_prefix("pub ") {
        (true, r)
    } else if let Some(r) = code.strip_prefix("pub(crate) ") {
        (false, r)
    } else {
        (false, code)
    };
    let (name, ty) = rest.split_once(':')?;
    let name = name.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    let ty = ty.trim().trim_end_matches(',').trim();
    if ty.is_empty() {
        return None;
    }
    Some((name.to_string(), ty.to_string(), is_pub))
}

fn push(out: &mut Vec<Violation>, rule: &'static str, file: &str, line: usize, detail: &str) {
    out.push(Violation {
        rule,
        file: file.to_string(),
        line,
        detail: detail.chars().take(100).collect(),
    });
}

/// One path, reported and nothing more: no verdict is written.
fn report_aim(files: &[PathBuf], violations: &[Violation]) {
    for v in violations {
        println!("{}:{}: {} {}", v.file, v.line, v.rule, v.detail);
    }
    println!(
        "{} forbidden shapes in {} file(s)",
        violations.len(),
        files.len()
    );
    if !violations.is_empty() {
        std::process::exit(1);
    }
}

fn report_gate(_root: &Path, files: &[PathBuf], violations: &[Violation]) {
    let mut per_rule = std::collections::BTreeMap::new();
    for v in violations {
        *per_rule.entry(v.rule).or_insert(0usize) += 1;
    }
    let total = violations.len();
    let touched: BTreeSet<&str> = violations.iter().map(|v| v.file.as_str()).collect();

    println!("bs-detector — forbidden shapes, {} files scanned", files.len());
    for (rule, desc) in RULES {
        let n = per_rule.get(rule).copied().unwrap_or(0);
        println!("{rule}  {n:>6}  {desc}");
    }
    for v in violations.iter().take(40) {
        println!("{}:{}: {} {}", v.file, v.line, v.rule, v.detail);
    }
    if total > 40 {
        println!("… {} more", total - 40);
    }
    // The line the gate caller parses. Exactly one line may carry this shape.
    println!("total = {total} violations across {} files", touched.len());

    if total > 0 {
        std::process::exit(1);
    }
}
