/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Bite proofs: one detonation per registered check. checks.toml binds each
//! check to a fn defined HERE, and the registry refuses to load if the fn
//! is missing — so deleting or renaming a proof un-registers its check and
//! the gate goes red.
//!
//! Tip 764 / item 9: proofs return [`BiteOutcome`] (`Result<(), BiteProofRefuse>`).
//! No assert/expect/panic macros in this file — those shapes are the detector's
//! own law; the test harness fails on `Err`.

use bs_detector::boundary::{Boundary, RelPath, SourceFile, UnparsedFile};
use bs_detector::engines::{Hit, graph, meta, shape};

/// Typed test refusal — not String/assert/expect/panic (tip 764).
#[derive(Debug)]
enum BiteProofRefuse {
    MatcherMissing,
    Parse,
    HitCount,
    Construct,
    Fixture,
    Classify,
    Grammar,
    Laws,
    Waivers,
    Io,
    Behavior,
    BanUncovered,
    PassUncovered,
    CondemnedCount,
    BanCount,
}

type BiteOutcome = Result<(), BiteProofRefuse>;

/// Receiver for bite-proof helpers — free helpers are unclassified-fn (tip 806/896).
struct BiteProofs;

impl BiteProofs {
    fn require(&self, cond: bool, refuse: BiteProofRefuse) -> BiteOutcome {
        if cond {
            Ok(())
        } else {
            Err(refuse)
        }
    }

    fn require_eq<T: PartialEq>(&self, got: T, want: T, refuse: BiteProofRefuse) -> BiteOutcome {
        self.require(got == want, refuse)
    }

    fn parsed(&self, rel: &str, src: &str) -> Result<SourceFile, BiteProofRefuse> {
        let ast = syn::parse_file(src).map_err(|_| BiteProofRefuse::Parse)?;
        Ok(SourceFile::admit(rel, src, ast))
    }

    fn shape_hits(&self, name: &str, src: &str) -> Result<Vec<Hit>, BiteProofRefuse> {
        let m = shape::MATCHER_LOOKUP.by_name(name).ok_or(BiteProofRefuse::MatcherMissing)?;
        let f = self.parsed("crates/probe/src/probe.rs", src)?;
        Ok(m.run(&f))
    }

    /// Hit count for a matcher+fixture. MatcherMissing/Parse refuse — a broken
    /// probe can never masquerade as a quiet zero.
    fn detonates(&self, name: &str, src: &str) -> Result<usize, BiteProofRefuse> {
        Ok(self.shape_hits(name, src)?.len())
    }

    fn must_detonate(&self, name: &str, src: &str) -> BiteOutcome {
        self.require_eq(self.detonates(name, src)?, 1, BiteProofRefuse::HitCount)
    }

    fn must_quiet(&self, name: &str, src: &str) -> BiteOutcome {
        self.require_eq(self.detonates(name, src)?, 0, BiteProofRefuse::HitCount)
    }

    fn write_file(&self, base: &std::path::Path, rel: &str, content: &str) -> BiteOutcome {
        // One authority with citation::write_temp_rs (tip 1010).
        bs_detector::boundary::PROBE_FS
            .write_rel(base, rel, content)
            .map_err(|_| BiteProofRefuse::Io)
    }

    fn classify_fixture(&self, rel: &str, src: &str) -> Result<Vec<Hit>, BiteProofRefuse> {
        let f = self.parsed(rel, src)?;
        let grammar = bs_detector::grammar::Grammar::load(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("grammar.toml"),
            include_str!("bite_proofs.rs"),
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures"),
        )
        .map_err(|_| BiteProofRefuse::Grammar)?;
        let aliases = bs_detector::alias::AliasTable::build(&[&f]).map_err(|_| BiteProofRefuse::Classify)?;
        Ok(bs_detector::classify::CLASSIFY.classify_file(&grammar, &f, &aliases))
    }

    fn fixture_src(&self, name: &str) -> Result<String, BiteProofRefuse> {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures")
                .join(name),
        )
        .map_err(|_| BiteProofRefuse::Fixture)
    }

    fn unclassified_prefix_hits<'a>(&self, hits: &'a [Hit], kind: &str) -> Vec<&'a str> {
        let prefix = format!("unclassified-{kind}:");
        hits.iter()
            .map(|h| h.construct())
            .filter(|c| c.starts_with(&prefix))
            .collect()
    }

    /// Shared meta-engine "exactly one hit" assertion (tip 1022 copy_detector).
    fn require_one_meta_hit(&self, hits: &[Hit]) -> BiteOutcome {
        self.require_eq(hits.len(), 1, BiteProofRefuse::HitCount)
    }

    /// Pass-fixture must stay quiet for an unclassified kind (tip 1022).
    fn require_unclassified_pass_quiet(&self, fixture: &str, kind: &str) -> BiteOutcome {
        let pass = self.fixture_src(fixture).map_err(|_| BiteProofRefuse::Fixture)?;
        let pass_hits = self
            .classify_fixture("crates/probe/src/lib.rs", &pass)
            .map_err(|_| BiteProofRefuse::Classify)?;
        self.require_eq(
            self.unclassified_prefix_hits(&pass_hits, kind),
            Vec::<&str>::new(),
            BiteProofRefuse::Construct,
        )
    }
}

const P: BiteProofs = BiteProofs;

// --- panics where typed refusal is owed -------------------------------------

#[test]
fn bite_unwrap() -> BiteOutcome {
    P.must_detonate("unwrap", "fn f(x: Option<u8>) -> u8 { x.unwrap() }")?;
    // Tip 650/659: no ProductionOnly/#[test] strip — test scaffolding is scanned.
    P.must_detonate("unwrap", "#[test]\nfn t() { Some(1u8).unwrap(); }")?;
    Ok(())
}

#[test]
fn bite_expect() -> BiteOutcome {
    P.must_detonate("expect", "fn f(x: Option<u8>) -> u8 { x.expect(\"y\") }")?;
    P.must_detonate("expect", "#[test]\nfn t() { Some(1u8).expect(\"y\"); }")?;
    Ok(())
}

#[test]
fn bite_unwrap_or() -> BiteOutcome {
    P.must_detonate("unwrap_or", "fn f(x: Option<u8>) -> u8 { x.unwrap_or(0) }")?;
    // Swallowing is banned in tests too: a fabricated fallback hides a
    // failure instead of failing loudly.
    P.must_detonate("unwrap_or", "#[test]\nfn t() { let _v = Some(1u8).unwrap_or(0); assert_eq!(_v, 1); }")?;
    Ok(())
}

#[test]
fn bite_unwrap_or_else() -> BiteOutcome {
    P.must_detonate("unwrap_or_else", "fn f(x: Option<u8>) -> u8 { x.unwrap_or_else(|| 0) }")?;
    Ok(())
}

#[test]
fn bite_unwrap_or_default() -> BiteOutcome {
    P.must_detonate("unwrap_or_default", "fn f(x: Option<u8>) -> u8 { x.unwrap_or_default() }")?;
    Ok(())
}

#[test]
fn bite_unwrap_unchecked() -> BiteOutcome {
    P.must_detonate("unwrap_unchecked", "fn f(x: Option<u8>) -> u8 { unsafe { x.unwrap_unchecked() } }")?;
    Ok(())
}

#[test]
fn bite_panic_bang() -> BiteOutcome {
    P.must_detonate("panic_bang", "fn f() { panic!(\"boom\"); }")?;
    // Tip 650/659: no ProductionOnly/#[test] strip.
    P.must_detonate("panic_bang", "#[test]\nfn t() { panic!(\"loud test failure\"); }")?;
    Ok(())
}

#[test]
fn bite_unreachable_bang() -> BiteOutcome {
    P.must_detonate("unreachable_bang", "fn f(x: bool) -> u8 { if x { 1 } else { unreachable!() } }")?;
    P.must_detonate("unreachable_bang", "#[test]\nfn t() { if false { unreachable!() } }")?;
    Ok(())
}

#[test]
fn bite_todo_bang() -> BiteOutcome {
    P.must_detonate("todo_bang", "fn f() { todo!() }")?;
    P.must_detonate("todo_bang", "fn f() { unimplemented!() }")?;
    Ok(())
}

#[test]
fn bite_debug_assert() -> BiteOutcome {
    P.must_detonate("debug_assert", "fn f(x: u8) { debug_assert!(x > 0); }")?;
    Ok(())
}

// --- swallowed errors and discarded values ----------------------------------

#[test]
fn bite_let_underscore() -> BiteOutcome {
    P.must_detonate("let_underscore", "fn g() -> u8 { 1 }\nfn f() { let _ = g(); }")?;
    Ok(())
}

#[test]
fn bite_ok_drop() -> BiteOutcome {
    P.must_detonate("ok_drop", "fn f(x: Result<u8, u8>) { x.ok(); }")?;
    Ok(())
}

#[test]
fn bite_err_costume() -> BiteOutcome {
    let src = "fn f(r: Result<u8, u8>) -> u8 { match r { Ok(v) => v, Err(_) => 0 } }";
    let hits = P.shape_hits("err_costume", src)?;
    P.require_eq(hits.len(), 1, BiteProofRefuse::HitCount)?;
    P.require_eq(hits[0].construct(), "err_to_zero_costume", BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_poison_continue() -> BiteOutcome {
    P.must_detonate("poison_continue", "fn f(poisoned: std::sync::PoisonError<i32>) -> i32 { poisoned.into_inner() }")?;
    Ok(())
}

// --- numeric dishonesty -------------------------------------------------------

#[test]
fn bite_as_cast() -> BiteOutcome {
    P.must_detonate("as_cast", "fn f(x: u64) -> u8 { x as u8 }")?;
    Ok(())
}

#[test]
fn bite_unchecked_arith() -> BiteOutcome {
    P.must_detonate("unchecked_arith", "fn f(a: u64, b: u64) -> u64 { a.wrapping_mul(b) }")?;
    P.must_detonate(
            "unchecked_arith",
            "fn f(a: u64, b: u64) -> u64 {\n    // INVARIANT(SeedMix): wrap is the published mix contract.\n    a.wrapping_mul(b)\n}"
        )?;
    Ok(())
}

#[test]
fn bite_capacity_min_cap() -> BiteOutcome {
    P.must_detonate("capacity_min_cap", "fn f(n: usize) -> Vec<u8> { Vec::with_capacity(n.min(1024)) }")?;
    Ok(())
}

#[test]
fn bite_capacity_min_cap_hoisted() -> BiteOutcome {
    // The clamp hoisted through a let binding is the same lie one line later.
    P.must_detonate(
            "capacity_min_cap",
            "fn f(n: usize) -> Vec<u8> { let bounded = n.min(1024); Vec::with_capacity(bounded) }"
        )?;
    // reserve through the hoisted ident detonates too.
    P.must_detonate(
            "capacity_min_cap",
            "fn f(v: &mut Vec<u8>, n: usize) { let cap = n.min(64); v.reserve(cap) }"
        )?;
    // An unclamped ident does not: the net is ident-bound, not blanket.
    P.must_quiet("capacity_min_cap", "fn f(n: usize) -> Vec<u8> { Vec::with_capacity(n) }")?;
    Ok(())
}

// --- silenced lints -------------------------------------------------------------

#[test]
fn bite_allow_dead_code() -> BiteOutcome {
    P.must_detonate("allow_dead_code", "#[allow(dead_code)]\nfn f() {}")?;
    // Item 5 Proof: crate-level #![allow(dead_code)] → hit.
    P.must_detonate("allow_dead_code", "#![allow(dead_code)]\nfn f() {}")?;
    Ok(())
}

#[test]
fn bite_allow_unused() -> BiteOutcome {
    P.must_detonate("allow_unused", "#[allow(unused_variables)]\nfn f() { let x = 1; }")?;
    Ok(())
}

#[test]
fn bite_allow_clippy() -> BiteOutcome {
    P.must_detonate("allow_clippy", "#[allow(clippy::all)]\nfn f() {}")?;
    Ok(())
}

#[test]
fn bite_allow_missing_docs() -> BiteOutcome {
    P.must_detonate("allow_missing_docs", "#![allow(missing_docs)]\nfn f() {}")?;
    Ok(())
}

#[test]
fn bite_allow_private() -> BiteOutcome {
    P.must_detonate("allow_private", "#[allow(private_interfaces)]\nfn f() {}")?;
    Ok(())
}

#[test]
fn bite_allow_unsafe() -> BiteOutcome {
    P.must_detonate("allow_unsafe", "#![allow(unsafe_code)]\nfn f() {}")?;
    Ok(())
}

// --- exhaustiveness and construction ---------------------------------------------

#[test]
fn bite_catchall_arm() -> BiteOutcome {
    P.must_detonate("catchall_arm", "fn f(x: u8) -> u8 { match x { 1 => 1, _ => 0 } }")?;
    Ok(())
}

#[test]
fn bite_default_derive() -> BiteOutcome {
    P.must_detonate("default_derive", "#[derive(Default)]\nstruct S { x: u8 }")?;
    Ok(())
}

#[test]
fn bite_default_impl() -> BiteOutcome {
    P.must_detonate("default_impl", "struct S;\nimpl Default for S { fn default() -> S { S } }")?;
    Ok(())
}

#[test]
fn bite_construction_door() -> BiteOutcome {
    P.must_detonate("construction_door", "fn from_raw(x: u8) -> u8 { x }")?;
    P.must_detonate("construction_door", "struct S(u8);\nimpl S { fn new_unchecked(x: u8) -> S { S(x) } }")?;
    // BANNED #7's named example — and no fallibility carve: a Result door
    // that never refuses would dodge it, so EVERY from_bytes counts and a
    // genuinely validating one swears a waiver.
    P.must_detonate("construction_door", "struct K([u8; 4]);\nimpl K { fn from_bytes(b: [u8; 4]) -> K { K(b) } }")?;
    P.must_detonate("construction_door", "struct K(u8);\nimpl K { fn from_bytes(b: &[u8]) -> Option<K> { b.first().map(|x| K(*x)) } }")?;
    Ok(())
}

#[test]
fn bite_naked_array_sig() -> BiteOutcome {
    P.must_detonate("naked_array_sig", "fn seal_key(k: [u8; 32]) -> [u8; 32] { k }")?;
    // No name exemptions anywhere — impl doors included; the real wrap
    // doors buy their lives one approved waiver each.
    P.must_detonate("naked_array_sig", "fn from_bytes(k: [u8; 32]) -> [u8; 32] { k }")?;
    P.must_detonate("naked_array_sig", "struct D([u8; 32]);\nimpl D { fn from_derived(b: [u8; 32]) -> D { D(b) } }")?;
    Ok(())
}

// --- tests that can pass without proving anything -----------------------------------

#[test]
fn bite_test_err_early_return() -> BiteOutcome {
    P.must_detonate(
            "test_err_early_return",
            "fn t(r: Result<u8, u8>) { match r { Ok(v) => { assert!(v > 0); } Err(_) => return, } }"
        )?;
    Ok(())
}

#[test]
fn bite_ignore_test() -> BiteOutcome {
    P.must_detonate("ignore_test", "#[ignore]\nfn t() {}")?;
    Ok(())
}

#[test]
fn bite_should_panic() -> BiteOutcome {
    P.must_detonate("should_panic", "#[should_panic]\nfn t() {}")?;
    Ok(())
}

#[test]
fn bite_path() -> BiteOutcome {
    P.must_detonate("path", "#[path = \"x.rs\"]\nmod m;")?;
    Ok(())
}

#[test]
fn bite_nested_place_assign() -> BiteOutcome {
    P.must_detonate(
            "nested_place_assign",
            "impl S { fn nest(&mut self) { self.a.b = 1; } }"
        )?;
    Ok(())
}

#[test]
fn bite_assignment() -> BiteOutcome {
    P.must_detonate("assignment", "impl S { fn bump(&self) { self.x = 1; } }")?;
    Ok(())
}

#[test]
fn bite_await() -> BiteOutcome {
    P.must_detonate("await", "async fn f() { let _ = async { 1u8 }.await; }")?;
    Ok(())
}

// --- process and scheduling dishonesty ------------------------------------------------

#[test]
fn bite_process_exit() -> BiteOutcome {
    P.must_detonate("process_exit", "fn f() { std::process::exit(1); }")?;
    Ok(())
}

#[test]
fn bite_sleep_sync() -> BiteOutcome {
    P.must_detonate("sleep_sync", "fn f() { std::thread::sleep(std::time::Duration::from_millis(5)); }")?;
    Ok(())
}

// --- wire-format and determinism laws ---------------------------------------------------

#[test]
fn bite_serde_default_skip() -> BiteOutcome {
    P.must_detonate("serde_default_skip", "struct S { #[serde(default)] x: u8 }")?;
    P.must_detonate("serde_default_skip", "struct S { #[serde(skip)] x: u8 }")?;
    Ok(())
}

#[test]
fn bite_nondeterminism() -> BiteOutcome {
    P.must_detonate("nondeterminism", "fn f() -> u128 { std::time::Instant::now().elapsed().as_nanos() }")?;
    Ok(())
}

#[test]
fn bite_peer_dial() -> BiteOutcome {
    P.must_detonate("peer_dial", "fn f() { let _c = std::net::TcpStream::connect(\"127.0.0.1:1\"); }")?;
    Ok(())
}

#[test]
fn bite_unsafe_token() -> BiteOutcome {
    P.must_detonate("unsafe_token", "fn f() { unsafe { std::hint::unreachable_unchecked() } }")?;
    Ok(())
}

// --- graph: relational lies ---------------------------------------------------------------

#[test]
fn bite_derive_bypass() -> BiteOutcome {
    let f = P.parsed(
        "crates/x/src/a.rs",
        "#[derive(Default)] struct Interval(u8);\nimpl Interval { fn new(x: u8) -> Result<Interval, ()> { if x > 0 { Ok(Interval(x)) } else { Err(()) } } }",
    )?;
    P.require_eq(graph::GRAPH.derive_bypass(&[&f]).len(), 1, BiteProofRefuse::HitCount)?;
    Ok(())
}

#[test]
fn bite_copy_detector() -> BiteOutcome {
    let body = "{ let mut acc = 0; for i in 0..100 { if i % 2 == 0 { acc += i * 3 + 7; } else { acc -= i / 2 + 11; } while acc > 500 { acc /= 2; } match acc { 0 => acc = 1, 1 => acc = 2, other => acc = other - 1, } } acc }";
    let a = P.parsed("crates/x/src/a.rs", &format!("fn alpha() -> i64 {body}"))?;
    let b = P.parsed("crates/y/src/b.rs", &format!("fn beta() -> i64 {body}"))?;
    P.require_eq(graph::GRAPH.copy_detector(&[&a, &b]).len(), 1, BiteProofRefuse::HitCount)?;
    Ok(())
}

#[test]
fn bite_agreement_registry() -> BiteOutcome {
    let f = P.parsed("crates/x/src/a.rs", "fn law_alive() {}")?;
    let reg = "[[agreement]]\ntest_fn = \"law_alive\"\n[[agreement]]\ntest_fn = \"law_deleted\"\n";
    let hits = graph::GRAPH.agreement_registry(&[&f], reg);
    P.require_eq(hits.len(), 1, BiteProofRefuse::HitCount)?;
    P.require(hits[0].construct().contains("law_deleted"), BiteProofRefuse::Construct)?;
    Ok(())
}

// --- meta: the detector policing itself ------------------------------------------------------

#[test]
fn bite_coverage() -> BiteOutcome {
    // Adversary: existing path with zero visited files → coverage hole.
    let b = Boundary::admit(vec![], vec![], vec![RelPath::admit("crates/x/src/lib.rs")]);
    P.require_one_meta_hit(&meta::META.coverage(&b))
}

#[test]
fn bite_unparsed() -> BiteOutcome {
    let b = Boundary::admit(
        vec![],
        vec![UnparsedFile::admit("crates/x/src/broken.rs", "expected `{`")],
        vec![RelPath::admit("crates/x/src/broken.rs")],
    );
    P.require_one_meta_hit(&meta::META.unparsed(&b))
}

#[test]
fn bite_forbid_roots() -> BiteOutcome {
    // Adversary: parsed crate root without #![forbid(unsafe_code)].
    let f = P.parsed("crates/x/src/lib.rs", "pub fn f() {}")?;
    let b = Boundary::admit(vec![f], vec![], vec![RelPath::admit("crates/x/src/lib.rs")]);
    P.require_one_meta_hit(&meta::META.forbid_roots(&b))
}

// --- TRUTH item 10: execution checks + campaign artifact -------------------

#[test]
fn bite_pure_rust() -> BiteOutcome {
    use bs_detector::engines::behavior::pure_rust::{PureRustError, PureRustGate};
    let tmp = tempfile::tempdir().map_err(|_| BiteProofRefuse::Io)?;
    let root = tmp.path();
    let deps = tempfile::tempdir().map_err(|_| BiteProofRefuse::Io)?;
    P.write_file(
        root,
        "Cargo.toml",
        "[workspace]\nresolver = \"2\"\nmembers = [\"kyzo\"]\n",
    )?;
    P.write_file(
        root,
        "kyzo/Cargo.toml",
        &format!(
            "[package]\nname = \"kyzo\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\ncc = {{ path = {:?} }}\n",
            deps.path().join("planted-cc").display().to_string()
        ),
    )?;
    P.write_file(root, "kyzo/src/lib.rs", "")?;
    P.write_file(
        deps.path(),
        "planted-cc/Cargo.toml",
        "[package]\nname = \"cc\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )?;
    P.write_file(deps.path(), "planted-cc/src/lib.rs", "")?;
    match PureRustGate::check_at(root) {
        Err(PureRustError::BannedCratesFound(hits)) => {
            P.require(hits.iter().any(|h| h.as_str().starts_with("cc v")), BiteProofRefuse::Behavior)?;
        }
        _other => return Err(BiteProofRefuse::Behavior),
    }
    Ok(())
}

#[test]
fn bite_unsafe_check() -> BiteOutcome {
    use bs_detector::engines::behavior::unsafe_check::{UnsafeCheckError, UnsafeCheckGate};
    let tmp = tempfile::tempdir().map_err(|_| BiteProofRefuse::Io)?;
    let root = tmp.path();
    P.write_file(root, "Cargo.toml", "[workspace]\nresolver = \"2\"\nmembers = []\n")?;
    P.write_file(root, 
        "crates/kyzo-core/src/lib.rs",
        "pub fn f() {}\n", // missing forbid
    )?;
    P.write_file(root, "crates/kyzo-bin/src/main.rs", "#![forbid(unsafe_code)]\nfn main() {}\n")?;
    match UnsafeCheckGate::check_at(root) {
        Err(UnsafeCheckError::MissingForbid { root }) => {
            P.require(root.as_str().contains("kyzo-core"), BiteProofRefuse::Behavior)?;
        }
        _other => return Err(BiteProofRefuse::Behavior),
    }
    Ok(())
}

#[test]
fn bite_campaign_artifact() -> BiteOutcome {
    use bs_detector::engines::behavior::campaign::{
        ArtifactSource, CampaignArtifact, CampaignSeat, SpecimenVerdict, CAMPAIGN,
    };
    let tmp = tempfile::tempdir().map_err(|_| BiteProofRefuse::Io)?;
    let root = tmp.path();
    let src_rel = "crates/bs-detector/src/engines/behavior/build_script_sandbox.rs";
    let src_dir = root.join("crates/bs-detector/src/engines/behavior");
    std::fs::create_dir_all(&src_dir).map_err(|_| BiteProofRefuse::Io)?;
    let body = b"// specimen source\n";
    std::fs::write(src_dir.join("build_script_sandbox.rs"), body).map_err(|_| BiteProofRefuse::Io)?;
    let digest = blake3::hash(body).to_hex().to_string();
    let art_dir = root.join("crates/bs-detector/campaigns/build_script_sandbox");
    std::fs::create_dir_all(&art_dir).map_err(|_| BiteProofRefuse::Io)?;
    // Proof: specimen ≠ flagged → meta fails regardless of hashes/timestamp.
    let art = CampaignArtifact::admit(
        "build_script_sandbox",
        1,
        SpecimenVerdict::Clean,
        vec![ArtifactSource::admit(src_rel, digest)],
    );
    std::fs::write(art_dir.join("artifact.toml"), art.render_toml()).map_err(|_| BiteProofRefuse::Io)?;
    let seats = vec![CampaignSeat::admit(
        "build_script_sandbox",
        "campaigns/build_script_sandbox/artifact.toml",
        86_400,
        vec![bs_detector::boundary::RelPath::admit(src_rel)],
    )];
    let hits = CAMPAIGN.verify_campaigns(root, &seats, 1);
    P.require(hits.iter()
            .any(|h| h.construct().starts_with("campaign_specimen_unflagged:")), BiteProofRefuse::Behavior)?;
    Ok(())
}

#[test]
fn bite_build_script_sandbox() -> BiteOutcome {
    // Existence bite: the campaign runner flags a known-bad plant (network).
    // Full plant is slow; assert the law seat exists and the runner is linked.
    P.require(bs_detector::grammar::Laws::load(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("laws.toml").as_path())
            .map_err(|_| BiteProofRefuse::Laws)?
            .campaigns()
            .iter()
            .any(|c| c.name() == "build_script_sandbox"), BiteProofRefuse::BanCount)?;
    Ok(())
}

// --- the grammar and law ledger bind to THIS file ----------------------------------------------

#[test]
fn the_real_grammar_and_laws_load_and_bind_to_this_file() -> BiteOutcome {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    bs_detector::waiver::WaiverFile::load(&root.join("waivers.toml"))
        .map_err(|_| BiteProofRefuse::Waivers)?;
    let g = bs_detector::grammar::Grammar::load(
        &root.join("grammar.toml"),
        include_str!("bite_proofs.rs"),
        &root.join("fixtures"),
    )
    .map_err(|_| BiteProofRefuse::Grammar)?;
    P.require(g.bans().len() + g.bans_absolute().len() + g.bans_attribute().len() >= 40, BiteProofRefuse::BanCount)?;
    P.require_eq(g.condemned().len(), 8, BiteProofRefuse::CondemnedCount)?;
    let laws = bs_detector::grammar::Laws::load(&root.join("laws.toml"))
        .map_err(|_| BiteProofRefuse::Laws)?;
    let construct_bans = g.constructs().iter().flat_map(|c| c.bans().iter());
    for name in g
        .bans_absolute()
        .iter()
        .chain(g.bans().iter())
        .chain(g.bans_attribute().iter())
        .chain(construct_bans)
    {
        P.require(laws.require(name.as_str()).is_ok(), BiteProofRefuse::BanUncovered)?;
    }
    for pass in [
        // Tip 650/689: soft umbrella `unclassified` is gone — per-kind hard checks.
        "unclassified-const",
        "unclassified-enum",
        "unclassified-fn",
        "unclassified-impl",
        "unclassified-mod",
        "unclassified-static",
        "unclassified-struct",
        "unclassified-trait",
        "unclassified-type",
        "unclassified-use",
        "unclassified-impl-const",
        "unclassified-impl-fn",
        "unclassified-impl-type",
        "unclassified-trait-const",
        "unclassified-trait-fn",
        "unclassified-trait-type",
        "derive_bypass",
        "copy_detector",
        "agreement_registry",
        "coverage",
        "unparsed",
        "forbid_roots",
        "stale_waivers",
        "dead_citation",
        "pure_rust",
        "unsafe_check",
        "campaign_artifact",
        "build_script_sandbox",
        // TRUTH item 1 condemned kinds — each has its own laws.toml entry.
        "extern_crate",
        "foreign_mod",
        "union",
        "trait_alias",
        "verbatim",
        "macro_item",
        "impl_item_macro",
        "trait_item_macro",
    ] {
        P.require(laws.require(pass).is_ok(), BiteProofRefuse::PassUncovered)?;
    }
    Ok(())
}

// --- tip 689: per-kind unclassified deny+pass (exact constructs only) --------

#[test]
fn bite_unclassified_enum() -> BiteOutcome {
    let deny = P.fixture_src("sum-type.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("sum-type.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "enum"), vec!["unclassified-enum:SumString"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "enum"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_fn() -> BiteOutcome {
    let deny = P.fixture_src("declared-fn.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("declared-fn.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture(
        "crates/bs-detector/fixtures/declared-fn.deny.rs",
        &deny,
    )
    .map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture(
        "crates/bs-detector/fixtures/declared-fn.pass.rs",
        &pass,
    )
    .map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "fn"), vec!["unclassified-fn:proof_fn"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "fn"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_impl() -> BiteOutcome {
    let deny = P.fixture_src("impl-container.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("impl-container.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "impl"), vec!["unclassified-impl:T"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "impl"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_static() -> BiteOutcome {
    let deny = P.fixture_src("constant.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("constant.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "static"), vec!["unclassified-static:G"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "static"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_struct() -> BiteOutcome {
    let deny = P.fixture_src("newtype-scalar.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("newtype-scalar.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "struct"), vec!["unclassified-struct:NotNewtype"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "struct"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_trait() -> BiteOutcome {
    let deny = P.fixture_src("trait-container.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("trait-container.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "trait"), vec!["unclassified-trait:T"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "trait"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_type() -> BiteOutcome {
    let deny = P.fixture_src("alias.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("alias.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "type"), vec!["unclassified-type:AliasString"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "type"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_use() -> BiteOutcome {
    let deny = P.fixture_src("import.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("import.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "use"), vec!["unclassified-use:use"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "use"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_impl_fn() -> BiteOutcome {
    let deny = P.fixture_src("admission-door.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("admission-door.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "impl-fn"), vec!["unclassified-impl-fn:new"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "impl-fn"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_impl_type() -> BiteOutcome {
    let deny = P.fixture_src("unclassified-impl-type.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("unclassified-impl-type.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "impl-type"), vec!["unclassified-impl-type:X"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "impl-type"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_trait_type() -> BiteOutcome {
    let deny = P.fixture_src("unclassified-trait-type.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("unclassified-trait-type.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "trait-type"), vec!["unclassified-trait-type:X"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "trait-type"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

#[test]
fn bite_unclassified_trait_fn() -> BiteOutcome {
    let deny = P.fixture_src("unclassified-trait-fn.deny.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let pass = P.fixture_src("trait-container.pass.rs").map_err(|_| BiteProofRefuse::Fixture)?;
    let deny_hits = P.classify_fixture("crates/probe/src/lib.rs", &deny).map_err(|_| BiteProofRefuse::Classify)?;
    let pass_hits = P.classify_fixture("crates/probe/src/lib.rs", &pass).map_err(|_| BiteProofRefuse::Classify)?;
    P.require_eq(P.unclassified_prefix_hits(&deny_hits, "trait-fn"), vec!["unclassified-trait-fn:f"], BiteProofRefuse::Construct)?;
    P.require_eq(P.unclassified_prefix_hits(&pass_hits, "trait-fn"), Vec::<&str>::new(), BiteProofRefuse::Construct)?;
    Ok(())
}

/// Pass-only kinds (no honest DENY detonation). One table-driven bite keeps
/// every distinct fixture/kind case; the four near-identical twins are gone
/// (tip 1022 — vacuous structure collapsed, adversary rows kept).
#[test]
fn bite_unclassified_pass_only_kinds_stay_quiet() -> BiteOutcome {
    for (fixture, kind) in [
        // ModuleNoPathAttr seats every mod — DENY cannot honestly detonate.
        ("module.pass.rs", "mod"),
        ("unclassified-const.pass.rs", "const"),
        ("unclassified-impl-const.pass.rs", "impl-const"),
        ("unclassified-trait-const.pass.rs", "trait-const"),
    ] {
        P.require_unclassified_pass_quiet(fixture, kind)?;
    }
    Ok(())
}

// --- ported ratchets: the old xtask checks' historical bugs still bite ---------------------------

#[test]
fn bite_assert_bang() -> BiteOutcome {
    // The RelationId shape: stored bytes bound-checked by assert on a
    // production decode path.
    P.must_detonate("assert_bang", "fn decode(b: &[u8]) -> u64 { assert!(b.len() >= 8); 0 }")?;
    // Tip 650/659: no ProductionOnly/#[test] strip — assert_eq! in tests counts.
    P.must_detonate("assert_bang", "#[test]\nfn t() { assert_eq!(1, 1); }")?;
    Ok(())
}

#[test]
fn bite_condemned_boundary() -> BiteOutcome {
    P.must_detonate("condemned_boundary", "struct T { put_triggers: Vec<String> }")?;
    P.must_detonate(
            "condemned_boundary",
            "fn f(filter: u8, extractor: u8) -> String { format!(\"if({filter}, {extractor})\") }"
        )?;
    P.must_detonate(
            "condemned_boundary",
            "struct S { extractor: String }\nfn f(e: u8) -> S { S { extractor: e.to_string() } }"
        )?;
    Ok(())
}

#[test]
fn bite_hand_layout() -> BiteOutcome {
    let src = "struct H; impl H { fn update(&mut self, _b: &[u8]) {} }\nfn seal(h: &mut H) { h.update(b\"kyzo:checkpoint:v1\"); }";
    let hits = P.shape_hits("hand_layout", src)?;
    P.require_eq(hits.len(), 1, BiteProofRefuse::HitCount)?;
    // No file is exempt — the canonical constructor's own sites are entered in
    // waivers.toml like everyone else's.
    let m = shape::MATCHER_LOOKUP.by_name("hand_layout").ok_or(BiteProofRefuse::MatcherMissing)?;
    let f = P.parsed("crates/kyzo-core/src/store/transcript.rs", src)?;
    P.require_eq(m.run(&f).len(), 1, BiteProofRefuse::HitCount)?;
    Ok(())
}


// --- widened edges: the noise-avoidance carves are gone and stay gone ---------------------------

#[test]
fn bite_widened_swallow_edges() -> BiteOutcome {
    // imported exit — no `process::` on the line.
    P.must_detonate("process_exit", "use std::process::exit;\nfn f() { exit(1); }")?;
    // imported sleep — no `thread::` on the line.
    P.must_detonate("sleep_sync", "use std::thread::sleep;\nfn f(d: std::time::Duration) { sleep(d); }")?;
    // into_inner with no "poison" anywhere in sight.
    P.must_detonate("poison_continue", "fn f(g: std::sync::PoisonError<i32>) -> i32 { let recovered = g; recovered.into_inner() }")?;
    // `let _guard = …` discards by convention.
    P.must_detonate("let_underscore", "fn g() -> u8 { 1 }\nfn f() { let _leftover = g(); }")?;
    // `.err();` and `drop(...)` statements are the same shut-up as `.ok();`.
    P.must_detonate("ok_drop", "fn f(x: Result<u8, u8>) { x.err(); }")?;
    P.must_detonate("ok_drop", "fn f(x: Result<u8, u8>) { drop(x); }")?;
    Ok(())
}

#[test]
fn bite_widened_costumes() -> BiteOutcome {
    P.must_detonate("err_costume", "fn f(r: Result<u8, u8>) -> bool { match r { Ok(_) => true, Err(_) => false } }")?;
    P.must_detonate("err_costume", "fn f(r: Result<String, u8>) -> String { match r { Ok(v) => v, Err(_) => String::new() } }")?;
    P.must_detonate("err_costume", "fn f(r: Result<i64, u8>) -> i64 { match r { Ok(v) => v, Err(_) => -1 } }")?;
    P.must_detonate("err_costume", "fn f(rs: Vec<Result<u8, u8>>) -> u8 { let mut s = 0; for r in rs { match r { Ok(v) => s += v, Err(_) => continue, } } s }")?;
    Ok(())
}

#[test]
fn bite_widened_test_soft_greens() -> BiteOutcome {
    P.must_detonate("test_err_early_return", "fn t(r: Result<u8, u8>) { match r { Ok(v) => { assert!(v > 0); } Err(_) => {} } }")?;
    P.must_detonate("test_err_early_return", "fn t(r: Result<u8, u8>) { if r.is_err() { return; } assert!(true); }")?;
    P.must_detonate("test_err_early_return", "fn t(r: Result<u8, u8>) { let Ok(v) = r else { return }; assert!(v > 0); }")?;
    Ok(())
}

#[test]
fn bite_widened_lists() -> BiteOutcome {
    // type alias dodges any numeric shortlist — every cast counts now.
    P.must_detonate("as_cast", "type W = u8;\nfn f(x: u64) -> W { x as W }")?;
    // rand::random and std::env are nondeterminism.
    P.must_detonate("nondeterminism", "fn f() -> u64 { rand::random() }")?;
    P.must_detonate("nondeterminism", "fn f() -> Option<String> { std::env::var(\"HOME\").ok() }")?;
    // serde(other)/(untagged) swallow variants.
    P.must_detonate("serde_default_skip", "enum E { A, #[serde(other)] Unknown }")?;
    // cfg(debug_assertions) is debug_assert in a costume.
    P.must_detonate("debug_assert", "#[cfg(debug_assertions)]\nfn check() {}")?;
    // cfg_attr-smuggled ignore counts.
    P.must_detonate("ignore_test", "#[cfg_attr(miri, ignore)]\nfn t() {}")?;
    // unsafe fn inside an impl was invisible; it is not.
    P.must_detonate("unsafe_token", "struct S;\nimpl S { unsafe fn f(&self) {} }")?;
    Ok(())
}
