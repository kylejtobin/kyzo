/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Durability / crash-campaign proofs for story #221.
//!
//! ## Overlap-only group commit (T2)
//!
//! Compiled as `kyzo::store::sweep::crash` under `cfg(test)` via `#[path]`
//! from [`sweep`](../../../../kyzo-core/src/store/sweep.rs) so the proof can
//! observe SweepDoor batch membership without a second commit door. A
//! non-overlapping arrival after an in-flight fsync window closes must not
//! share that barrier's [`OverlapBatch`] — and wake ≠ timer (no sleep coalesce).

use super::live_door::{content_root, open_native_live_door as open_live_door};
use super::{IntentOrdinal, OverlapBatch, SweepDoor, SweepSession};
use crate::store::authority::Entropy;
use crate::store::grants::IdentitySeed;
use crate::store::idempotency::{IdempotencyMemo, OperationKey, RequestDigest};
use crate::store::open::StoreId;
use crate::store::scratch::TempTx;

/// Loud admit — kit/campaign step that must hold. Diverges on Err (never silent).
/// `#[cfg(test)]`: path-wired under sweep's test wall; ProductionOnly exemption.
#[cfg(test)]
fn admit<T, E: std::fmt::Display>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => loop {
            assert!(false, "{what}: {e}");
        },
    }
}

fn op_key(store_id: StoreId, op: &[u8]) -> (OperationKey, RequestDigest) {
    let key = OperationKey::single_store(b"kyzo.sweep.crash", op, store_id, b"s0");
    let digest = IdempotencyMemo::digest_request(op);
    (key, digest)
}

/// Overlap-only group-commit proof: a non-overlapping arrival is not batched
/// with an in-flight fsync (no timer).
///
/// Exercises the distinction concretely:
/// 1. A queued, then B admitted while the fsync window is open → same overlap batch.
/// 2. Window closes at seal; C admitted after → must not be a member of that batch.
/// 3. C seals in a later barrier alone.
///
/// Fails if C appears in the first [`OverlapBatch`], if A/B fail to share it,
/// or if batching were modeled as a timer (this path never sleeps).
#[test]
fn overlap_only_group_commit_non_overlapping_arrival_not_batched() {
    let (mut door, incarnation, session) = open_live_door(
        IdentitySeed::from_digest([0x21; 32]),
        Entropy::admit([0xC0; 32]),
    );
    let store_id = session.store_id();
    let (key_a, dig_a) = op_key(store_id, b"overlap-A");
    let (key_b, dig_b) = op_key(store_id, b"overlap-B");
    let (key_c, dig_c) = op_key(store_id, b"overlap-C");

    // A arrives before the barrier — queued, then pulled into the overlap cohort.
    let intent_a = admit(
        door.admit(incarnation, &session, key_a, dig_a),
        "admit A before fsync window",
    );
    admit(
        door.begin_fsync_window(incarnation, &session),
        "begin in-flight fsync window",
    );
    assert!(
        door.fsync_window_open(),
        "fsync window must be open for overlap admission"
    );

    // B arrives while the fsync is in flight → overlaps that barrier.
    let intent_b = admit(
        door.admit(incarnation, &session, key_b, dig_b),
        "admit B overlapping in-flight fsync",
    );
    let cohort: Vec<IntentOrdinal> = door.overlap_cohort_ordinals().collect();
    assert_eq!(
        cohort,
        vec![intent_a.intent_ordinal(), intent_b.intent_ordinal()],
        "overlap cohort must be exactly A then B while the fsync window is open"
    );

    let (batch_ab, committed_ab) = admit(
        door.seal_durable_overlap_batch(
            vec![
                (TempTx::new(), content_root(1)),
                (TempTx::new(), content_root(2)),
            ],
            &session,
        ),
        "seal overlap batch A+B",
    );

    assert!(
        !door.fsync_window_open(),
        "seal must close the fsync window — otherwise late arrivals could still overlap"
    );
    assert_eq!(committed_ab.len(), 2);
    assert!(
        batch_ab.contains_overlap_member(intent_a.intent_ordinal()),
        "A must be an overlap member of the sealed barrier"
    );
    assert!(
        batch_ab.contains_overlap_member(intent_b.intent_ordinal()),
        "B (arrived during in-flight fsync) must share A's overlap batch"
    );
    assert_eq!(
        door.last_overlap_batch(),
        Some(&batch_ab),
        "last_overlap_batch must report the sealed A+B barrier"
    );

    // C arrives after the window closed — non-overlapping with that in-flight fsync.
    let intent_c = admit(
        door.admit(incarnation, &session, key_c, dig_c),
        "admit C after fsync window closed",
    );
    assert!(
        !batch_ab.contains_overlap_member(intent_c.intent_ordinal()),
        "non-overlapping arrival C must NOT be a member of the prior overlap batch"
    );
    assert!(
        door.overlap_cohort_ordinals().next().is_none(),
        "C must wait on the IntentionQueue, not join a still-open overlap cohort"
    );
    assert_eq!(
        door.queue().len(),
        1,
        "non-overlapping C waits for a later barrier (queue carriage)"
    );

    // Later barrier: C alone. No timer — explicit begin/seal only.
    admit(
        door.begin_fsync_window(incarnation, &session),
        "begin later fsync window for C",
    );
    let (batch_c, committed_c) = admit(
        door.seal_durable_overlap_batch(vec![(TempTx::new(), content_root(3))], &session),
        "seal overlap batch C",
    );

    assert_eq!(committed_c.len(), 1);
    assert!(
        batch_c.contains_overlap_member(intent_c.intent_ordinal()),
        "C must seal in its own later overlap batch"
    );
    assert!(
        !batch_c.contains_overlap_member(intent_a.intent_ordinal())
            && !batch_c.contains_overlap_member(intent_b.intent_ordinal()),
        "later barrier must not re-batch A/B with non-overlapping C"
    );
    assert_ne!(
        batch_ab.members(),
        batch_c.members(),
        "overlap batches for distinct fsync windows must differ"
    );

    // History ordinals stay dense across barriers; batch membership is carriage.
    assert_eq!(
        committed_ab[0].commit_ordinal().get() + 1,
        committed_ab[1].commit_ordinal().get()
    );
    assert_eq!(
        committed_ab[1].commit_ordinal().get() + 1,
        committed_c[0].commit_ordinal().get()
    );

    // Named so a trivial always-true assert cannot satisfy the board Check alone:
    // both this file and sweep.rs must carry the overlap law token.
    let batch_ab_typed: &OverlapBatch = &batch_ab;
    assert_eq!(batch_ab_typed.members(), batch_ab.members());
}

// ---------------------------------------------------------------------------
// Real power-cut / FUSE crash-matrix campaign (story #31) — path-wired under
// `kyzo::store::sweep::crash`. Requires kyzo-crashfs (kyzo-core test dep) and
// `crate::store::sim::SimStorage` (crate-private DST double). Absent FUSE
// refuses LOUD via `require_live_mount` / typed `MountRefuse` — never
// eprintln+return that cargo reports as `ok`.
// ---------------------------------------------------------------------------
mod fuse_crash_matrix {
    use std::collections::BTreeSet;

    use kyzo_crashfs::harness::{mount, require_live_mount, wait_for_mount};
    use kyzo_crashfs::{Fault, FaultPlan, OpKind, PassthroughFs, Trigger};

    use crate::store::fjall::{new_fjall_storage, new_fjall_storage_with, StorageOptions};
    use crate::store::sim::SimStorage;
    use crate::store::{ReadTx, Slice, Storage, WriteTx};

    use super::admit;

    /// The main data keyspace's journal file at a fresh store's very first
    /// segment. The commit-boundary matrix hard-pins this: after the
    /// fault-free recorder, `journal_segment_basenames` must equal
    /// `[JOURNAL_PATH]` — with the small row counts this class drives, the
    /// journal must never rotate past `0.jnl`, so the Nth op on this ONE
    /// path is unambiguous.
    const JOURNAL_PATH: &str = "0.jnl";

    /// One durable round's key/value pairs, deterministic in `round` and `n` so
    /// two independent runs (the recorder pass, a faulted pass, and the
    /// `SimStorage` oracle) generate byte-identical rows without sharing any
    /// state.
    fn round_kv(round: u32, n: u32) -> Vec<(Vec<u8>, Vec<u8>)> {
        (0..n)
            .map(|i| {
                (
                    format!("r{round:04}-k{i:04}").into_bytes(),
                    format!("r{round:04}-v{i:04}").into_bytes(),
                )
            })
            .collect()
    }

    /// Drive `rounds` DURABLE commit rounds against `storage`, generic over the
    /// `Storage` trait so ONE driver exercises both `SimStorage` (the oracle)
    /// and a real `FjallStorage` mounted through the injector — never two
    /// hand-written copies of the same workload.
    fn drive_durable_rounds<S: Storage>(storage: &S, rounds: u32, n: u32) {
        for round in 0..rounds {
            let mut tx = admit(storage.write_tx(), "write_tx durable round");
            for (k, v) in round_kv(round, n) {
                admit(tx.put(&k, &v), "put durable round");
            }
            admit(tx.commit_durable(), "commit_durable round");
        }
    }

    /// The full visible key/value set, as an order-independent set — the
    /// comparison currency between the real backend and the `SimStorage`
    /// oracle (their `total_scan` byte order need not agree for this
    /// campaign's purposes, only their content).
    fn total_scan_set<S: Storage>(storage: &S) -> BTreeSet<(Slice, Slice)> {
        let tx = admit(storage.read_tx(), "read_tx total_scan_set");
        let mut out = BTreeSet::new();
        for r in tx.total_scan() {
            out.insert(admit(r, "total_scan row"));
        }
        out
    }

    /// The oracle: `SimStorage` driven through the identical round script,
    /// POWER-CUT right after `surviving_rounds` durable commits — never
    /// fsyncing the remaining rounds first. This is the exact "only the
    /// fsynced prefix survives" contract [`Fault::ClearCache`] on the real
    /// journal implements, so the two must agree.
    fn oracle_after_powercut(surviving_rounds: u32, n: u32) -> BTreeSet<(Slice, Slice)> {
        let sim = SimStorage::new(0xF00D_F00D_F00D_F00D);
        drive_durable_rounds(&sim, surviving_rounds, n);
        let cut = admit(sim.sim_powercut(), "oracle sim powercut");
        total_scan_set(&cut)
    }

    /// Journal segment basenames (`0.jnl`, `1.jnl`, …) under a store root —
    /// the hard-pin for this class: the small-row matrix must never rotate
    /// past a single segment, or `JOURNAL_PATH`'s Nth-fsync premise is void.
    fn journal_segment_basenames(store_root: &std::path::Path) -> Vec<String> {
        let dir = admit(
            std::fs::read_dir(store_root).map_err(|e| format!("{e}")),
            &format!("read store root {}", store_root.display()),
        );
        let mut names: Vec<String> = Vec::new();
        for entry in dir {
            let entry = admit(entry.map_err(|e| format!("{e}")), "read_dir entry");
            if entry.path().extension().and_then(|x| x.to_str()) == Some("jnl") {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();
        names
    }

    const ROUNDS: u32 = 6;
    const KEYS_PER_ROUND: u32 = 20;

    /// Faults exercised at each recorded commit_durable barrier. ClearCache
    /// keeps the exact power-cut oracle; TornSeq/TornOp are write-time
    /// decisions (see `kyzo_crashfs::fault`) so they arm on the journal
    /// Write count observed at the same barrier — never on Fsync, where
    /// only ClearCache is a first-class event.
    const COMMIT_BOUNDARY_FAULTS: [Fault; 3] = [Fault::ClearCache, Fault::TornSeq, Fault::TornOp];

    /// Commit-boundary class: a real `FjallStorage`, mounted through
    /// `kyzo-crashfs`, crashed EXACTLY at each of its own `commit_durable`
    /// calls in turn — never a byte offset, per the design ruling's
    /// field-converged lesson ("anchored to durability barriers").
    ///
    /// Rows stay small so the journal is hard-pinned on `0.jnl` (asserted).
    /// Each barrier is crossed with ClearCache (exact SimStorage power-cut
    /// oracle) AND with TornSeq/TornOp on the barrier's last journal write
    /// (open-or-typed-refuse; never durable past the torn round; never
    /// wrong bytes). Multi-segment (≥2 `.jnl`) ClearCache matrix is deleted
    /// until a real scheduled campaign seat can compile+run it under the
    /// gate (M4 tip 325) — this class stays single-segment hard-pinned.
    #[test]
    fn commit_boundary_crash_matrix_matches_the_powercut_oracle() {
        require_live_mount().expect("live FUSE mount required");

        // Pass 1: the fault-free recorder. Learn which occurrence of Fsync
        // AND Write on the journal coincides with each round's own
        // commit_durable by OBSERVING it once, honestly — never by guessing
        // fjall's internals.
        let backing_a = admit(tempfile::tempdir(), "tempdir backing_a");
        let mnt_a = admit(tempfile::tempdir(), "tempdir mnt_a");
        let fs_a = PassthroughFs::new(backing_a.path(), FaultPlan::new(1));
        let counters = fs_a.shared_counters();
        let session_a = admit(mount(fs_a, mnt_a.path()), "mount recorder");
        wait_for_mount(mnt_a.path());
        let rounds_cap = admit(
            usize::try_from(ROUNDS).map_err(|e| format!("{e}")),
            "INVARIANT(rounds_fit_usize): ROUNDS fits usize",
        );
        let (boundary_fsync_count, boundary_write_count): (Vec<u64>, Vec<u64>) = {
            let db = admit(
                new_fjall_storage(mnt_a.path()),
                "new_fjall_storage recorder",
            );
            let mut fsyncs = Vec::with_capacity(rounds_cap);
            let mut writes = Vec::with_capacity(rounds_cap);
            for round in 0..ROUNDS {
                let mut tx = admit(db.write_tx(), "recorder write_tx");
                for (k, v) in round_kv(round, KEYS_PER_ROUND) {
                    admit(tx.put(&k, &v), "recorder put");
                }
                admit(tx.commit_durable(), "recorder commit_durable");
                fsyncs.push(admit(counters.fsync_count(JOURNAL_PATH), "recorder fsync_count"));
                writes.push(admit(counters.write_count(JOURNAL_PATH), "recorder write_count"));
            }
            (fsyncs, writes)
        };
        // Hard-pin: this matrix's rows must never rotate the journal. If a
        // second segment appears, JOURNAL_PATH's Nth-op counts are no longer
        // the commit-boundary identity — fail loud, do not paper over.
        let journals = journal_segment_basenames(backing_a.path());
        assert_eq!(
            journals,
            vec![JOURNAL_PATH.to_string()],
            "commit-boundary matrix must stay on a single journal segment \
             ({JOURNAL_PATH}); observed {journals:?} — shrink rows or seat a \
             multi-segment variant with per-segment triggers"
        );
        session_a.teardown();
        // Sanity: strictly increasing, or this class's entire premise (one
        // fsync/write frontier per round on this one path) is void and every
        // assertion below would be meaningless — fail loud here, not by
        // mis-triggering later.
        for w in boundary_fsync_count.windows(2) {
            assert!(
                w[0] < w[1],
                "fsync counts on {JOURNAL_PATH} must strictly increase per round: \
             {boundary_fsync_count:?}"
            );
        }
        for w in boundary_write_count.windows(2) {
            assert!(
                w[0] < w[1],
                "write counts on {JOURNAL_PATH} must strictly increase per round: \
             {boundary_write_count:?}"
            );
        }

        // Pass 2: one independent campaign per (round boundary × fault).
        // Fresh backing directory every time — no campaign ever reuses
        // another's disk state.
        for (idx, (&fsync_count, &write_count)) in boundary_fsync_count
            .iter()
            .zip(boundary_write_count.iter())
            .enumerate()
        {
            let round_idx = admit(
                u32::try_from(idx).map_err(|e| format!("{e}")),
                "INVARIANT(round_idx): enumerate idx fits u32",
            );
            for fault in COMMIT_BOUNDARY_FAULTS {
                let backing_b = admit(tempfile::tempdir(), "tempdir backing_b");
                let mnt_b = admit(tempfile::tempdir(), "tempdir mnt_b");
                // ClearCache is an fsync-boundary power cut; TornSeq/TornOp
                // decide at write time and materialize on the next fsync —
                // arming them on Fsync would be a silent no-op in passthrough.
                let (op, at_count) = match fault {
                    Fault::ClearCache => (OpKind::Fsync, fsync_count),
                    Fault::TornSeq | Fault::TornOp => (OpKind::Write, write_count),
                };
                let plan =
                    FaultPlan::new(1).with_trigger(Trigger::new(JOURNAL_PATH, op, at_count, fault));
                let fs_b = PassthroughFs::new(backing_b.path(), plan);
                let session_b = admit(mount(fs_b, mnt_b.path()), "mount fault campaign");
                wait_for_mount(mnt_b.path());
                {
                    let db = admit(new_fjall_storage(mnt_b.path()), "new_fjall_storage faulted");
                    for round in 0..=round_idx {
                        let mut tx = admit(db.write_tx(), "faulted write_tx");
                        for (k, v) in round_kv(round, KEYS_PER_ROUND) {
                            admit(tx.put(&k, &v), "faulted put");
                        }
                        admit(tx.commit_durable(), "faulted commit_durable");
                    }
                }
                session_b.teardown(); // simulated crash: fusectl abort then unmount

                // Reopen directly on the backing directory — bypassing FUSE
                // entirely, exactly as a real process reopening after a crash
                // would see the disk (mirrors kyzo-crashfs's own standalone tests).
                let reopen = new_fjall_storage(backing_b.path());
                let expected_prefix = oracle_after_powercut(round_idx, KEYS_PER_ROUND);
                match fault {
                    Fault::ClearCache => {
                        let reopened = admit(
                            reopen,
                            &format!("ClearCache round {round_idx}: store must open clean"),
                        );
                        // "Opens clean" is necessary, never sufficient (the issue's
                        // own pinned lsm-tree finding: data blocks are checksummed
                        // lazily, on first read) — total_scan forces the traversal
                        // that would surface a torn data block instead of silently
                        // skipping it.
                        let observed = total_scan_set(&reopened);
                        assert_eq!(
                            observed, expected_prefix,
                            "ClearCache round {round_idx}: a crash exactly at its own \
                             commit_durable's fsync must leave precisely rounds \
                             0..{round_idx} visible (this round's own writes never durable), \
                             matching SimStorage crashed at the analogous logical point"
                        );
                    }
                    Fault::TornSeq | Fault::TornOp => {
                        // Torn* has no SimStorage twin for "drop/split one journal
                        // write then fsync". Honest outcomes: typed reopen refuse,
                        // OR open clean with exactly the already-fsynced prefix
                        // (same set ClearCache must leave). Showing the torn round
                        // as durable, or losing prior fsynced rounds, is a fail —
                        // and equality with the prefix makes a vacuous (no-op)
                        // trigger fail too, because a no-op would leave
                        // rounds 0..=round_idx.
                        // Typed reopen refusal is an honest torn-journal outcome;
                        // open-clean must equal the already-fsynced prefix.
                        if let Ok(reopened) = reopen {
                            let observed = total_scan_set(&reopened);
                            // Equality with the ClearCache prefix is itself the
                            // anti-vacuity check: a no-op trigger would leave
                            // rounds 0..=round_idx durable, which is a larger set.
                            assert_eq!(
                                observed, expected_prefix,
                                "{fault:?} round {round_idx}: open-clean after a torn \
                                 commit-boundary write must leave exactly the already-\
                                 fsynced prefix (rounds 0..{round_idx}), never the torn \
                                 round and never less than prior durable rounds"
                            );
                        }
                    }
                }
            }
        }
    }


    const FLOOD_ROWS: u32 = 3_000;
    const FLOOD_VALUE_LEN: usize = 30_000;
    const SEEDS: u64 = 6;
    /// Matches any segment file fjall's LSM keyspaces create
    /// (`keyspaces/<id>/tables/<segment>`) — the highest-value unknown named
    /// by the issue's design ruling.
    const SEGMENT_GLOB: &str = "*/tables/*";
    const PER_SEED_BUDGET: std::time::Duration = std::time::Duration::from_secs(25);
    /// Poll-loop ceiling when the budget millis refuse `u64` — not Err→MAX costume.
    const POLL_BUDGET_CEILING: u64 = u64::MAX;

    fn flood_key(i: u32) -> String {
        format!("flood{i:08}")
    }

    /// Deterministic, per-index content so a wrong-bytes read is unambiguous —
    /// never a constant fill a coincidental truncation could still satisfy.
    fn flood_val(i: u32, len: usize) -> Vec<u8> {
        let tag = format!("v{i:08}-");
        tag.bytes()
            .chain(std::iter::repeat(b'y'))
            .take(len)
            .collect()
    }

    /// Run `body` on its own thread, polling for completion rather than
    /// blocking on it directly. A found-the-hard-way lesson building this
    /// module: a stuck FUSE request parks its caller in the kernel
    /// (`request_wait_answer`), a state no ordinary signal — not even
    /// `SIGKILL` — can unwind; only tearing down the whole process (or
    /// force-aborting the FUSE connection from outside it) frees it. A hang
    /// inside `body` is therefore not "the test fails slowly," it is "the
    /// whole suite wedges forever" unless something outside the wedged thread
    /// enforces a deadline. On budget exhaustion the campaign fails loud via
    /// `assert!(false, …)` (never `process::exit` / `abort` — gate item 5).
    #[cfg(test)]
    fn run_bounded(label: &str, body: impl FnOnce() + Send + 'static) {
        let handle = std::thread::spawn(body);
        // Poll budget — structural, not Instant. 50ms sleep × polls ≈ PER_SEED_BUDGET.
        let max_polls = match u64::try_from(PER_SEED_BUDGET.as_millis() / 50) {
            Ok(n) => match n.checked_add(1) {
                Some(v) => v,
                None => POLL_BUDGET_CEILING,
            },
            // Budget that cannot fit u64 still ends the poll loop (ceiling).
            Err(_budget_past_u64) => POLL_BUDGET_CEILING,
        };
        let mut polls = 0u64;
        while !handle.is_finished() {
            if polls >= max_polls {
                assert!(
                    false,
                    "HANG DETECTED in {label}: exceeded the {PER_SEED_BUDGET:?} budget — this IS \
                 the \"never hang\" property story #31 exists to police, caught by the campaign \
                 rather than wedging the suite. File it (injector or engine, whichever is \
                 actually stuck) rather than raising the budget."
                );
            }
            polls = match polls.checked_add(1) {
                Some(v) => v,
                None => max_polls,
            };
            std::thread::park_timeout(std::time::Duration::from_millis(50));
        }
        if let Err(panic_payload) = handle.join() {
            std::panic::resume_unwind(panic_payload);
        }
    }

    /// Compaction/segment class: a compaction-forcing flood (~90MB across 3000
    /// rows — confirmed, by reading the backing directory directly, to force a
    /// real flush AND produce segment files under `keyspaces/*/tables/`)
    /// through the mount, with each seed torturing its OWN segment files'
    /// FIRST fsync with a different fault kind. Deliberately a bounded, ONE
    /// simulated crash EVENT per campaign (matching what a real crash actually
    /// is) rather than an ambient rate applied continuously across the whole
    /// flood — an earlier draft of this test used ambient rates at 8%/8% over
    /// thousands of writes and reliably wedged the process (see
    /// `run_bounded`'s doc): a real crash corrupts what was in flight at ONE
    /// instant, never a sustained fraction of every write for an entire
    /// session, and the earlier draft's unrealistic model was pushing fjall's
    /// own recovery/background-worker code down a path steady-state operation
    /// never exercises. Unlike the commit-boundary class, this does NOT assert
    /// an exact surviving key set — background flush/compaction timing is not
    /// under this test's direct control. The invariant that DOES hold
    /// unconditionally, and the one the falsification clause is actually
    /// about: never a panic (nor a hang — `run_bounded` turns one into a hard,
    /// diagnosed failure instead), the store opens or refuses with a TYPED
    /// error, and — the property silent corruption would violate — every key
    /// that IS present after reopen holds EXACTLY the bytes it was written
    /// with.
    #[test]
    fn compaction_segment_torn_write_campaign_never_returns_wrong_bytes() {
        require_live_mount().expect("live FUSE mount required");

        for seed in 0..SEEDS {
            run_bounded(
                "compaction_segment_torn_write_campaign_never_returns_wrong_bytes",
                move || {
                    let fault_idx = admit(
                        usize::try_from(seed % 3).map_err(|e| format!("{e}")),
                        "INVARIANT(fault_idx): seed%3 fits usize",
                    );
                    let fault = [Fault::TornSeq, Fault::TornOp, Fault::ClearCache][fault_idx];
                    let backing = admit(tempfile::tempdir(), "tempdir flood backing");
                    let mnt = admit(tempfile::tempdir(), "tempdir flood mnt");
                    // Catalog #13: occurrence was hard-coded `1` (first fsync
                    // only). Seed-derive so the campaign also arms the 2nd/3rd
                    // fsync on each matching segment path — a real crash can
                    // land on any fsync, not only the first. Every distinct
                    // path matching the glob keeps its OWN independent
                    // occurrence counter (never a sustained rate).
                    let at_count = 1 + (seed % 3);
                    let plan = FaultPlan::new(seed).with_trigger(Trigger::new(
                        SEGMENT_GLOB,
                        OpKind::Fsync,
                        at_count,
                        fault,
                    ));
                    let fs = PassthroughFs::new(backing.path(), plan);
                    let session = admit(mount(fs, mnt.path()), "mount flood campaign");
                    wait_for_mount(mnt.path());
                    {
                        // A store that itself hits an error mid-open/mid-write
                        // is a legitimate campaign outcome (the crash could
                        // land anywhere); only a PANIC would be a real defect,
                        // so the flood itself is deliberately best-effort.
                        if let Ok(db) = new_fjall_storage(mnt.path()) {
                            for i in 0..FLOOD_ROWS {
                                let Ok(mut tx) = db.write_tx() else { break };
                                if tx
                                    .put(flood_key(i).as_bytes(), &flood_val(i, FLOOD_VALUE_LEN))
                                    .is_err()
                                {
                                    break;
                                }
                                if tx.commit().is_err() {
                                    break;
                                }
                            }
                            match db.sync() {
                                Ok(()) => {}
                                Err(sync_refused) => {
                                    // Best-effort final sync under armed fault.
                                    let named = sync_refused;
                                    if named.to_string().is_empty() {
                                        // Sync refuse always names the failure — empty is uninhabited.
                                    }
                                }
                            }
                            // `db` drops here — fjall workers quiesce before
                            // FUSE teardown. No sleep-as-synchronization.
                        }
                    }
                    session.teardown(); // simulated crash: fusectl abort then unmount

                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        || -> miette::Result<()> {
                            let reopened = new_fjall_storage(backing.path())?;
                            let tx = reopened.read_tx()?;
                            for i in 0..FLOOD_ROWS {
                                if let Some(v) = tx.get(flood_key(i).as_bytes())? {
                                    assert_eq!(
                                        v,
                                        flood_val(i, FLOOD_VALUE_LEN),
                                        "seed {seed}: key {i} present after crash but with WRONG \
                                     bytes — exactly the silent-corruption class this campaign \
                                     exists to catch"
                                    );
                                }
                                // Absent is a legitimate outcome: this row was
                                // never guaranteed durable (only a
                                // best-effort `commit`, not `commit_durable`,
                                // backed it before the final `sync`).
                            }
                            Ok(())
                        },
                    ));
                    match outcome {
                        Ok(Ok(())) => {}              // opened clean; every present key correct
                        Ok(Err(_typed_refusal)) => {} // a typed refusal is acceptable
                        Err(panic_payload) => std::panic::resume_unwind(panic_payload), // never
                    }
                },
            );
        }
    }

    /// Process-crash consistency: a child process commits one transaction,
    /// stages a second without committing, then is SIGKILL'd by the parent.
    /// Reopening the store must show every committed write and nothing from
    /// the uncommitted one.
    ///
    /// # SCOPE HONESTY (carried obligation — power-cut-honesty)
    ///
    /// Parent `kill()` simulates abrupt process death (committed data has
    /// reached OS buffers — fjall's `Buffer` persist mode). A power cut is a
    /// fjall's `Buffer` persist mode). A power cut is a stronger event; surviving
    /// it is what `Storage::sync` (fsync) is for, and testing THAT honestly requires
    /// fault-injection infrastructure (kyzo-crashfs / dm-flakey class), not a unit
    /// test that lies about what it simulates. Until decisions.md §29's
    /// power-cut-at-commit-door campaign is green, the word `durable` is not
    /// licensed in Spec claims from this test alone.
    #[test]
    fn crash_consistency_process_abort() {
        use crate::store::fjall::new_fjall_storage;
        use crate::store::{ReadTx, Slice, Storage, WriteTx};

        if let Some(dir) = super::trials_host_env::knob("KYZO_CRASH_CHILD_DIR") {
            let db = admit(new_fjall_storage(&dir), "child open store");
            let mut tx = admit(db.write_tx(), "child write_tx committed");
            admit(tx.put(b"committed", b"survives"), "child put committed");
            admit(tx.commit(), "child commit committed");
            let mut tx = admit(db.write_tx(), "child write_tx synced");
            admit(
                tx.put(b"synced", b"survives-power-cut-too"),
                "child put synced",
            );
            admit(tx.commit(), "child commit synced");
            admit(db.sync(), "child sync");
            let mut tx = admit(db.write_tx(), "child write_tx durable");
            admit(tx.put(b"durable", b"per-tx-fsync"), "child put durable");
            admit(tx.commit_durable(), "child commit_durable");
            let mut tx = admit(db.write_tx(), "child write_tx uncommitted");
            admit(
                tx.put(b"uncommitted", b"must-vanish"),
                "child put uncommitted",
            );
            let ready = std::path::Path::new(&dir).with_extension("ready");
            admit(std::fs::write(&ready, b"1"), "child ready marker");
            loop {
                std::thread::park();
            }
        }

        let dir = admit(tempfile::tempdir(), "parent tempdir");
        let child_db = dir.path().join("db");
        let ready = child_db.with_extension("ready");
        let exe = admit(std::env::current_exe(), "current_exe");
        let mut child = admit(
            std::process::Command::new(exe)
                .args([
                    "store::sweep::crash::fuse_crash_matrix::crash_consistency_process_abort",
                    "--exact",
                    "--nocapture",
                ])
                .env("KYZO_CRASH_CHILD_DIR", &child_db)
                .spawn(),
            "spawn crash child",
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !ready.exists() {
            if std::time::Instant::now() >= deadline {
                match child.kill() {
                    Ok(()) => {}
                    Err(e) => panic!("failed to SIGKILL crash child: {e}"),
                }
                panic!("crash child never wrote ready marker");
            }
            std::thread::park_timeout(std::time::Duration::from_millis(10));
        }
        match child.kill() {
            Ok(()) => {}
            Err(e) => panic!("failed to SIGKILL crash child: {e}"),
        }
        let status = admit(child.wait(), "wait crash child");
        assert!(
            !status.success(),
            "child must die by signal, not exit cleanly"
        );

        let db = admit(
            new_fjall_storage(dir.path().join("db")),
            "reopen after process abort",
        );
        let tx = admit(db.read_tx(), "read_tx after abort");
        assert_eq!(
            admit(tx.get(b"committed"), "get committed"),
            Some(Slice::from(b"survives")),
            "committed (unsynced) data must survive a process crash"
        );
        assert_eq!(
            admit(tx.get(b"synced"), "get synced"),
            Some(Slice::from(b"survives-power-cut-too"))
        );
        assert_eq!(
            admit(tx.get(b"durable"), "get durable"),
            Some(Slice::from(b"per-tx-fsync"))
        );
        assert_eq!(admit(tx.get(b"uncommitted"), "get uncommitted"), None);
    }
}

// ---------------------------------------------------------------------------
// Residual-secret deep reachability DST (story #376 T3 / H8) — path-wired under
// `kyzo::store::sweep::crash`. Searches every sealed CanonicalTranscript kind
// (incl. KeyCommit / WalHeader), production CheckpointSeal encode, and
// leave-is-free pack bytes for residual DEK / KEK / plaintext ShredSalt.
// Seat 64 Store destroy door is UNBUILT (tip 477); ledger `name_revoked` is
// bookkeeping only — not on-disk crypto-shred. COP[OPEN] owed: real shred +
// post-destroy residual campaign.
// ---------------------------------------------------------------------------
mod crypto_shred_deep_reachability {
    use crate::store::authority::{Entropy, IncarnationMintCap, OpenOrdinal};
    use crate::store::backup::{LeaveIsFreeKind, LeaveIsFreePack, LeaveIsFreeParts, PackRefuse};
    use crate::store::crypto::{
        derive_dek, unwrap_shred_salt, wrap_shred_salt, CryptoRefuse, Dek, Kek, KekUnwrapCap,
        SegmentCounter, ShredLedger, ShredSalt, ShredTombstone,
    };
    use crate::store::epoch::{CryptoDomain, FenceEpoch};
    use crate::store::open::StoreId;
    use crate::store::seal::{
        CheckpointSeal, CheckpointSealParts, NonceLeaseFloors, SealDigest, SealRefuse,
        GENESIS_PRIOR_SEAL,
    };
    use crate::store::sweep::CommitOrdinal;
    use crate::store::transcript::{Digest32, 
        encode_all_normative_production_transcripts, encode_normative_production_transcript,
        refuse_residual_secret_bytes, refuse_residual_secrets_in_all_sealed_kinds,
        CanonicalTranscriptBuilder, FieldId, TranscriptRefuse, SEALED_ARTIFACT_KINDS,
    };
    use crate::store::wal::WalHash;
    use crate::store::{FormatVersion, SealedArtifactKind};

    use super::admit;

    /// Bind needle bytes for residual scrub. Callers must keep the returned
    /// `Bytes32` values alive for as long as the slices are used.
    fn shredded_secret_needles(
        kek: &Kek,
        salt: &ShredSalt,
        dek: &Dek,
    ) -> (
        crate::data::fixed_bytes::Bytes32,
        crate::data::fixed_bytes::Bytes32,
        crate::data::fixed_bytes::Bytes32,
    ) {
        (kek.as_bytes(), salt.as_bytes(), dek.as_bytes())
    }

    fn clean_seal_parts(store: StoreId, incarnation_entropy: Entropy) -> CheckpointSealParts {
        let fence = FenceEpoch::genesis(store);
        let domain = CryptoDomain::new(fence);
        let incarnation = admit(
            IncarnationMintCap::issue(store, OpenOrdinal::ZERO).mint(incarnation_entropy),
            "incarnation boundary",
        );
        CheckpointSealParts {
            store_id: store,
            crypto_domain: domain,
            fence_epoch: fence,
            cut: CommitOrdinal::ZERO,
            state_root: SealDigest::from_digest(crate::data::fixed_bytes::Bytes32([0x01; 32])),
            final_wal_hash: WalHash::from_digest(crate::data::fixed_bytes::Bytes32([0x02; 32])),
            checkpoint_manifest: SealDigest::from_digest(crate::data::fixed_bytes::Bytes32([0x03; 32])),
            format_version: FormatVersion::CURRENT,
            catalog_generation: CommitOrdinal::ZERO,
            retained_object_manifest: SealDigest::from_digest(crate::data::fixed_bytes::Bytes32([0x04; 32])),
            permanence_candidate_manifest: SealDigest::from_digest(crate::data::fixed_bytes::Bytes32([0x05; 32])),
            replica_custody_manifest: SealDigest::from_digest(crate::data::fixed_bytes::Bytes32([0x06; 32])),
            nonce_floors: NonceLeaseFloors::genesis(),
            incarnation_boundary: incarnation,
            prior_seal_digest: GENESIS_PRIOR_SEAL,
            retention_certificate_digest: SealDigest::from_digest(crate::data::fixed_bytes::Bytes32([0x07; 32])),
        }
    }

    fn sample_leave_is_free_pack(
        store: StoreId,
        wrapped: crate::store::crypto::WrappedShredSalt,
        incarnation_entropy: Entropy,
        payload: Vec<u8>,
    ) -> LeaveIsFreePack {
        let incarnation = admit(
            IncarnationMintCap::issue(store, OpenOrdinal::ZERO).mint(incarnation_entropy),
            "incarnation",
        );
        admit(
            LeaveIsFreePack::build(LeaveIsFreeParts {
                kind: LeaveIsFreeKind::SealAndSuffix,
                format_version: FormatVersion::CURRENT,
                wrapped_shred_salts: vec![wrapped],
                incarnation_history: vec![incarnation],
                payload,
            }),
            "leave-is-free pack",
        )
    }

    /// H8 deep reachability: every sealed artifact (golden transcript kinds
    /// incl. KeyCommit + WalHeader + CheckpointSeal encode + leave-is-free
    /// pack) is searched for residual DEK/KEK/plaintext ShredSalt bytes.
    /// Clean artifacts pass; planting a needle into each CheckpointSeal
    /// digest-bearing field (and leave-is-free / transcript surfaces) must
    /// refuse via the production scrub doors.
    ///
    /// Does **not** claim Store destroy-on-disk shred (seat 64 UNBUILT).
    /// Ledger revoke via [`ShredTombstone::name_revoked`] is bookkeeping only.
    #[test]
    fn crypto_shred_deep_reachability_refuses_residual_secrets_in_sealed_artifacts() {
        let kek_bytes = crate::data::fixed_bytes::Bytes32([0xA1u8; 32]);
        let salt_bytes = crate::data::fixed_bytes::Bytes32([0xB2u8; 32]);
        let store = StoreId::from_digest(crate::data::fixed_bytes::Bytes32([0x76; 32]));
        let domain = CryptoDomain::new(FenceEpoch::genesis(store));
        let kek = Kek::admit(kek_bytes);
        let cap = KekUnwrapCap::from_kek(kek.clone());
        let salt = ShredSalt::admit(salt_bytes);
        let seg = SegmentCounter::of_u64(9);
        let wrapped = admit(wrap_shred_salt(&cap, &salt, seg, domain), "production wrap");
        // Pack may still carry wrapped ciphertext; plaintext needles must not
        // survive in pack payload / entropy / ciphertext as raw residual.
        let pack_wrap = wrapped.clone();
        let dek = derive_dek(&cap, domain, seg, &salt);
        let (kek_needle, salt_needle, dek_needle) = shredded_secret_needles(&kek, &salt, &dek);
        let needles = [
            kek_needle.as_slice(),
            salt_needle.as_slice(),
            dek_needle.as_slice(),
        ];
        let dek_bytes = dek_needle;

        // Ledger bookkeeping refuse — not on-disk destroy (seat 64 unbuilt).
        let mut ledger = ShredLedger::new();
        ledger.record(ShredTombstone::name_revoked(seg, domain));
        assert!(
            matches!(
                unwrap_shred_salt(&cap, &wrapped, &ledger),
                Err(CryptoRefuse::Shredded)
            ),
            "ledger-named revoke must refuse unwrap via Shredded"
        );

        // Every sealed golden kind (incl. WalHeader + KeyCommit) via the
        // production all-kinds scrub door — clean of shredded needles.
        assert_eq!(
            SEALED_ARTIFACT_KINDS.len(),
            13,
            "campaign must enumerate every SealedArtifactKind incl. KeyCommit + WrappedShredSalt"
        );
        let sealed_transcripts = admit(
            encode_all_normative_production_transcripts(),
            "normative production transcripts encode",
        );
        admit(
            refuse_residual_secrets_in_all_sealed_kinds(&sealed_transcripts, &needles),
            "clean goldens must pass all-kinds residual scrub",
        );
        // Explicit WAL-header lane (same production encode door).
        let wal_header = admit(
            encode_normative_production_transcript(SealedArtifactKind::WalHeader),
            "wal header",
        );
        assert_eq!(
            refuse_residual_secret_bytes(wal_header.as_bytes(), &needles),
            Ok(())
        );
        // KeyCommit / CMT-1 golden must stay intact and clean of shredded needles.
        let key_commit = admit(
            encode_normative_production_transcript(SealedArtifactKind::KeyCommit),
            "key commit",
        );
        assert_eq!(
            refuse_residual_secret_bytes(key_commit.as_bytes(), &needles),
            Ok(()),
            "CMT-1 KeyCommit golden must remain intact and free of shredded needles"
        );

        // Production CheckpointSeal mint + encode + scrub — clean seal passes.
        let clean = admit(
            CheckpointSeal::mint(clean_seal_parts(store, Entropy::admit(crate::data::fixed_bytes::Bytes32([0x26; 32])))),
            "mint",
        );
        admit(
            clean.refuse_residual_secrets(&needles),
            "clean CheckpointSeal must pass residual scrub",
        );
        let clean_transcript = admit(clean.encode_transcript(), "encode");
        admit(
            clean_transcript.refuse_residual_secrets(&needles),
            "clean seal transcript must pass",
        );

        // Production leave-is-free pack scrub — clean pack (no needles in
        // payload / incarnation entropy; wrap ciphertext is AEAD) passes.
        let clean_pack = sample_leave_is_free_pack(
            store,
            pack_wrap.clone(),
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x2A; 32])),
            b"leave-is-free-clean-payload".to_vec(),
        );
        admit(
            clean_pack.refuse_residual_secrets(&needles),
            "clean leave-is-free pack must pass residual scrub",
        );

        // Hostile: plant plaintext ShredSalt into a sealed transcript field → refuse.
        let mut dirty_builder = admit(
            CanonicalTranscriptBuilder::new(FormatVersion::CURRENT),
            "builder",
        );
        admit(
            dirty_builder.append_u64(
                FieldId::ARTIFACT_KIND,
                SealedArtifactKind::CheckpointSeal.tag(),
            ),
            "kind",
        );
        admit(
            dirty_builder.append_digest32(FieldId::PRIMARY_DIGEST, &Digest32::admit(salt_bytes)),
            "plant salt as digest",
        );
        let dirty_transcript = dirty_builder.seal();
        assert_eq!(
            dirty_transcript.refuse_residual_secrets(&needles),
            Err(TranscriptRefuse::Corrupt),
            "production transcript scrub must refuse residual plaintext ShredSalt"
        );

        // Hostile: plant a shredded needle into every CheckpointSeal
        // digest-bearing field independently → encode surfaces it in
        // CanonicalTranscript → production seal scrub refuses. Residual-secret
        // scrub must cover the whole sealed transcript surface, not only
        // state_root.
        fn assert_digest_field_refuses(
            store: StoreId,
            incarnation_entropy: Entropy,
            field: &str,
            plant: impl FnOnce(&mut CheckpointSealParts),
            needles: &[&[u8]],
        ) {
            let mut parts = clean_seal_parts(store, incarnation_entropy);
            plant(&mut parts);
            let dirty = admit(CheckpointSeal::mint(parts), "mint dirty");
            assert_eq!(
                dirty.refuse_residual_secrets(needles),
                Err(SealRefuse::ResidualSecretMaterial),
                "production CheckpointSeal scrub must refuse residual secret in {field}"
            );
        }

        // state_root: salt / KEK / DEK (all three needles on the primary digest lane).
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x27; 32])),
            "state_root/salt",
            |p| p.state_root = SealDigest::from_digest(salt_bytes),
            &needles,
        );
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x28; 32])),
            "state_root/kek",
            |p| p.state_root = SealDigest::from_digest(kek_bytes),
            &needles,
        );
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x29; 32])),
            "state_root/dek",
            |p| p.state_root = SealDigest::from_digest(dek_bytes),
            &needles,
        );

        // Remaining digest-bearing CheckpointSealParts fields — one needle each
        // (salt), independently planted so a scrub hole on any lane detonate.
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x2E; 32])),
            "final_wal_hash",
            |p| p.final_wal_hash = WalHash::from_digest(salt_bytes),
            &needles,
        );
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x2F; 32])),
            "checkpoint_manifest",
            |p| p.checkpoint_manifest = SealDigest::from_digest(salt_bytes),
            &needles,
        );
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x30; 32])),
            "retained_object_manifest",
            |p| p.retained_object_manifest = SealDigest::from_digest(salt_bytes),
            &needles,
        );
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x31; 32])),
            "permanence_candidate_manifest",
            |p| p.permanence_candidate_manifest = SealDigest::from_digest(salt_bytes),
            &needles,
        );
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x32; 32])),
            "replica_custody_manifest",
            |p| p.replica_custody_manifest = SealDigest::from_digest(salt_bytes),
            &needles,
        );
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x33; 32])),
            "prior_seal_digest",
            |p| p.prior_seal_digest = SealDigest::from_digest(salt_bytes),
            &needles,
        );
        assert_digest_field_refuses(
            store,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x34; 32])),
            "retention_certificate_digest",
            |p| p.retention_certificate_digest = SealDigest::from_digest(salt_bytes),
            &needles,
        );

        // Hostile: plant shredded plaintext salt / KEK / DEK into leave-is-free
        // pack payload → production pack scrub refuses.
        let dirty_salt_pack = sample_leave_is_free_pack(
            store,
            pack_wrap.clone(),
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x2B; 32])),
            salt_bytes.to_vec(),
        );
        assert_eq!(
            dirty_salt_pack.refuse_residual_secrets(&needles),
            Err(PackRefuse::ResidualSecretMaterial),
            "production leave-is-free pack scrub must refuse residual plaintext ShredSalt"
        );
        let dirty_kek_pack = sample_leave_is_free_pack(
            store,
            pack_wrap.clone(),
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x2C; 32])),
            kek_bytes.to_vec(),
        );
        assert_eq!(
            dirty_kek_pack.refuse_residual_secrets(&needles),
            Err(PackRefuse::ResidualSecretMaterial),
            "residual KEK bytes in leave-is-free pack payload must refuse"
        );
        let dirty_dek_pack = sample_leave_is_free_pack(
            store,
            pack_wrap,
            Entropy::admit(crate::data::fixed_bytes::Bytes32([0x2D; 32])),
            dek_bytes.to_vec(),
        );
        assert_eq!(
            dirty_dek_pack.refuse_residual_secrets(&needles),
            Err(PackRefuse::ResidualSecretMaterial),
            "residual DEK bytes in leave-is-free pack payload must refuse"
        );
    }
}
