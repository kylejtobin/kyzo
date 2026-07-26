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
//! Every rule here is absolute, and every rule has the same scope. The moment a
//! rule needs a clause like "…where a domain fact belongs", or its own list of
//! exempt files, it stops being absolute and does not belong in this file.
//!
//! There is no exemption mechanism. Not a marker, not an attribute, not a list
//! of paths. A rule that can be waived at the site is a rule with a hole, and
//! the hole is used under exactly the pressure the rule exists to resist. The
//! one legitimate reason to write a forbidden shape is to prove a rule fires on
//! it — and that shape is test data, not program text, so it is not a `.rs`
//! file and this walker never sees it. See `tests/` in this crate.
//! Rules that need judgment are enforced by review, not by this binary, and
//! pretending otherwise is how the count became noise.
//!
//! One scope: all of `crates/` by default, or the single path you aim at. No
//! rule carries a private carve-out — not for tests, not for vendored data,
//! not for the crate the rule is inconvenient in.
//!
//! This crate is a workspace member on purpose: the detector scans itself.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};


/// A forbidden shape, with the file and line that holds it.
#[derive(Debug)]
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
    ("R04", "unwrap/expect/panic!"),
    ("R05", "String-typed error, or a refusal carrying no span"),
    ("R06", "todo!/unimplemented!/unreachable! stub"),
    ("R07", "env::var read outside the composition root"),
    ("R08", "String-typed kind/status/type/name field"),
    ("R09", "bool field carrying a domain decision"),
    ("R10", "bare primitive field outside a newtype"),
    ("R11", "RefCell/Cell/Mutex/RwLock field in a domain type"),
    ("R12", "f32/f64 field in a type that derives an order"),
    ("R13", "unsafe block/fn/impl"),
    ("R14", "allow(unsafe_code) — a lint-lowering on the strongest standard"),
    ("R15", "crate root with no #![forbid(unsafe_code)]"),
];



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
        let rel = f.strip_prefix(&root).unwrap_or(f).display().to_string();
        scan(&rel, &text, &mut violations);
    }

    // Runs in both modes. A rule that only fires at the gate is a rule you can
    // walk past while working, which is where the shape gets written.
    check_forbid_unsafe(&files, &mut violations);

    match mode {
        Mode::Gate { root } => report_gate(&root, &files, &violations),
        Mode::Aim { .. } => report_aim(&files, &violations),
    }
}

/// Every crate root must carry `#![forbid(unsafe_code)]`. `forbid`, not `deny`:
/// it cannot be lifted locally by an `allow`, which is what makes zero-unsafe a
/// compiler guarantee rather than a convention. Decided per crate, over the
/// file list, because absence is not a line anyone wrote.
fn check_forbid_unsafe(files: &[PathBuf], out: &mut Vec<Violation>) {
    for f in files {
        let p = f.display().to_string();
        let is_root = p.ends_with("/src/lib.rs") || p.ends_with("/src/main.rs");
        if !is_root {
            continue;
        }
        let crate_name: String = p
            .split("/src/")
            .next()
            .and_then(|c| c.rsplit('/').next())
            .unwrap_or_default()
            .to_string();
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        if !text.contains("#![forbid(unsafe_code)]") {
            out.push(Violation {
                rule: "R15",
                file: p,
                line: 1,
                detail: format!("crate `{crate_name}` does not forbid unsafe"),
            });
        }
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

fn scan(rel: &str, text: &str, out: &mut Vec<Violation>) {
    let states_order_law = text.contains("ORDER_LAW");

    // Struct/enum context for the field rules.
    let mut in_type: Option<(String, bool)> = None; // (name, derives_order)
    let mut pending_derives = String::new();
    let mut brace = 0i32;

    let all: Vec<&str> = text.lines().collect();
    for (i, raw) in all.iter().enumerate() {
        let line = i + 1;
        let t = raw.trim();
        // Literals first, then the comment. Stripping the comment first lets a
        // `//` inside a string truncate the line and hide whatever follows it.
        let blanked = strip_literals(t);
        let code = blanked.split("//").next().unwrap_or(&blanked).trim();

        // ---- token rules -------------------------------------------------
        {
            if code.contains(".unwrap()") || code.contains(".expect(") || code.contains("panic!(") {
                push(out, "R04", rel, line, code);
            }
            if code.contains("todo!(") || code.contains("unimplemented!(") || code.contains("unreachable!(")
            {
                push(out, "R06", rel, line, code);
            }
            if code.contains("env::var") || code.contains("std::env::var") {
                push(out, "R07", rel, line, code);
            }
            if code.contains("Result<") && code.contains(", String>") {
                push(out, "R05", rel, line, code);
            }
        }
        // Not test-exempt, and not scoped to two crates: `forbid(unsafe_code)`
        // in a lib root does not reach that crate's tests/ directory, which is
        // a separate crate root and exactly where unsafe sits unnoticed.
        // The bare keyword, anywhere on the line. Matching only `unsafe` at the
        // start of a line, or only the `fn`/`impl` forms, leaves the strongest
        // rule steppable by writing `let x = unsafe { *p };` — the shape most
        // likely to be reached for. `unsafe_code` is a different token and does
        // not match; R14 owns that one.
        if has_token(code, "unsafe") {
            push(out, "R13", rel, line, code);
        }
        if code.contains("allow(unsafe_code)") {
            push(out, "R14", rel, line, code);
        }

        // ---- type context ------------------------------------------------
        if code.starts_with("#[derive(") {
            pending_derives = code.to_string();
        }
        if let Some(rest) = type_header(code) {
            let derives_order = pending_derives.contains("Ord")
                || pending_derives.contains("PartialOrd")
                || pending_derives.contains("Hash");
            if derives_order && !states_order_law {
                push(out, "R01", rel, line, &format!("{rest} derives an order"));
            }
            in_type = Some((rest.to_string(), derives_order));
            brace = code.matches('{').count() as i32 - code.matches('}').count() as i32;
            // tuple newtype with a pub field: `pub struct X(pub T);`
            if code.contains("(pub ") {
                push(out, "R02", rel, line, code);
            }
            // `struct X { a: u8, b: bool }` — the fields are on this line.
            if let Some((_, tail)) = code.split_once('{') {
                for f in tail.trim_end_matches('}').split(',') {
                    field_rules(rel, line, f.trim(), derives_order, out);
                }
            }
            pending_derives.clear();
            continue;
        }
        if !states_order_law
            && (code.starts_with("impl Ord for")
                || code.starts_with("impl PartialOrd for")
                || code.starts_with("impl Hash for"))
        {
            push(out, "R01", rel, line, code);
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
        field_rules(rel, line, code, *derives_order, out);
    }
}

/// The rules that read one field declaration. A separate function because a
/// single-line struct body carries its fields on the header line, and a rule
/// that only fires on multi-line bodies is a rule you avoid by reformatting.
fn field_rules(rel: &str, line: usize, code: &str, derives_order: bool, out: &mut Vec<Violation>) {
        let Some((fname, fty, is_pub)) = field(code) else {
            return;
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
        if (fty == "f32" || fty == "f64") && derives_order {
            push(out, "R12", rel, line, code);
        }
}

/// `needle` present as a whole word: not a prefix, not a suffix, not part of a
/// longer identifier. `unsafe` matches in `unsafe {`, and does not in
/// `unsafe_code` or `not_unsafe`.
fn has_token(code: &str, needle: &str) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(at) = code[from..].find(needle) {
        let at = from + at;
        let before_ok = at == 0 || !code[..at].chars().next_back().is_some_and(word);
        let after_ok = !code[at + needle.len()..].chars().next().is_some_and(word);
        if before_ok && after_ok {
            return true;
        }
        from = at + needle.len();
    }
    false
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

/// The rules, proven against fixtures that hold the shapes on purpose.
///
/// The fixtures are `.rsfix`, not `.rs`: not compiled, and invisible to the
/// walker. A detector whose own corpus needed an exemption would have proven
/// the exemption, not the rule.
#[cfg(test)]
mod law {
    use super::*;

    /// Every rule the scanner decides per line, at the line that carries it.
    #[test]
    fn every_line_rule_fires_on_its_shape() {
        let text = include_str!("../fixtures/forbidden.rsfix");
        let mut out = Vec::new();
        scan("forbidden.rsfix", text, &mut out);
        let got: BTreeSet<(&str, usize)> = out.iter().map(|v| (v.rule, v.line)).collect();

        let want: &[(&str, usize)] = &[
            ("R01", 12), // derives Ord, no ORDER_LAW in the file
            ("R02", 13), // pub field on a tuple newtype
            ("R02", 15), // pub field in a struct body
            ("R03", 15), // bare Vec as a pub field
            ("R08", 16), // String-typed `kind`
            ("R09", 17), // bool field
            ("R10", 18), // bare usize field
            ("R11", 19), // RefCell field
            ("R04", 21), // unwrap
            ("R04", 22), // expect
            ("R04", 23), // panic!
            ("R06", 24), // todo!
            ("R06", 25), // unimplemented!
            ("R06", 26), // unreachable!
            ("R07", 27), // env::var
            ("R05", 28), // Result<_, String>
            ("R13", 29), // unsafe block
            ("R13", 30), // unsafe fn
            ("R13", 31), // unsafe impl
            ("R14", 32), // allow(unsafe_code)
            ("R09", 33), // bool in a single-line struct body
            ("R10", 33), // bare u64 in a single-line struct body
        ];
        let missed: Vec<_> = want.iter().filter(|w| !got.contains(*w)).collect();
        assert!(missed.is_empty(), "rules did not fire: {missed:?}");
    }

    /// R12 fires only where an order is derived, so it needs its own fixture.
    #[test]
    fn float_under_a_derived_order_fires() {
        let text = include_str!("../fixtures/ordered_float.rsfix");
        let mut out = Vec::new();
        scan("ordered_float.rsfix", text, &mut out);
        let got: BTreeSet<(&str, usize)> = out.iter().map(|v| (v.rule, v.line)).collect();
        assert!(got.contains(&("R12", 6)), "R12 did not fire: {got:?}");
        assert!(!got.contains(&("R01", 5)), "R01 fired despite ORDER_LAW: {got:?}");
    }

    /// A shape inside a string literal is data, and a `//` inside a string
    /// must not truncate the line and hide what follows it.
    #[test]
    fn literals_are_data_and_do_not_truncate() {
        let mut out = Vec::new();
        scan("t.rs", "let s = \"unsafe fn f\";\n", &mut out);
        assert!(out.is_empty(), "shape inside a literal reported: {out:?}");

        let mut out = Vec::new();
        scan("t.rs", "let u = \"http://x\"; unsafe { }\n", &mut out);
        assert!(
            out.iter().any(|v| v.rule == "R13"),
            "a `//` inside a literal hid the shape after it: {out:?}"
        );
    }

    /// There is no exemption. The former marker must not be honoured by any
    /// path — this test is the thing that fails if one is reintroduced.
    #[test]
    fn no_marker_suppresses_a_shape() {
        for marker in [
            "// BS-EXEMPT: R13 — signed for",
            "#[expect(unsafe_code, reason = \"signed for\")]",
            "#[allow(unsafe_code)]",
            "// SAFETY: reviewed",
        ] {
            let text = format!("{marker}\nunsafe fn f() {{}}\n");
            let mut out = Vec::new();
            scan("t.rs", &text, &mut out);
            assert!(
                out.iter().any(|v| v.rule == "R13" && v.line == 2),
                "`{marker}` suppressed R13"
            );
        }
    }

    /// Every rule in the table is one the scanner can actually produce. A rule
    /// that only exists as a row is a claim the tree is not being held to.
    #[test]
    fn every_listed_rule_is_reachable() {
        let mut out = Vec::new();
        scan(
            "f.rsfix",
            include_str!("../fixtures/forbidden.rsfix"),
            &mut out,
        );
        scan(
            "o.rsfix",
            include_str!("../fixtures/ordered_float.rsfix"),
            &mut out,
        );
        let fired: BTreeSet<&str> = out.iter().map(|v| v.rule).collect();
        // R15 is absence — no line carries it — so it is decided over the file
        // list in `check_forbid_unsafe`, not by `scan`, and no fixture can
        // trigger it here.
        let dead: Vec<&str> = RULES
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| *id != "R15" && !fired.contains(id))
            .collect();
        assert!(dead.is_empty(), "rules no fixture can trigger: {dead:?}");
    }
}
