---
paths:
  - "vendor/**/*.rs"
  - "vendor/**/Cargo.toml"
---

# Zone: Vendor — the owned storage fork

The fjall/lsm-tree fork: upstream code we deliberately rule.

## Required

- Upstream lineage preserved verbatim: license headers, attribution, and
  copyright stay untouched alongside ours.
- Every edit of ours is a deliberate engine decision, documented at the edit
  site with why the engine needs it — an undocumented divergence from
  upstream is a defect.
- Edits serve the storage contract above (ordered scans, SSI, consuming
  commits, crash safety); the fork evolves toward the engine's needs, never
  toward generic upstream parity.

- Every `.rs` file declares `//! AUTHORITY`, `//! SEAT`, `//! FILE_KIND` and obeys the File template in this rule.
- Comments obey the Comment ontology in this rule.
- Seated items carry `// CONSTRUCT: <grammar> <Ident>`.
- A file that needs two AUTHORITY sentences is split before merge.
- Upstream headers preserved. Each Kyzo divergence carries `ENGINE_EDIT`. No dependency upward into kyzo crates.

## Forbidden

- A dependency from vendor back into any crate of ours — the fork stands
  below everything.
- Pulling upstream changes wholesale without re-justifying each against our
  edits.
- Treating vendor as unownable: it is first-party responsibility with
  third-party history.

## Comment ontology

| kind | form | placement |
| --- | --- | --- |
| authority | `//! AUTHORITY: ` | file head; one Spec organ |
| seat | `//! SEAT: ` | under AUTHORITY; `zone-<name>/<role>` |
| file_kind | `//! FILE_KIND: ` | under SEAT; id from File template |
| citation | `//! CITATION: ` | when FILE_KIND requires |
| construct | `// CONSTRUCT: ` | above seated item; `<grammar> <Ident>` |
| order_law | `// ORDER_LAW: ` | above ordered/encoded type |
| claim | `// CLAIM: ` | `Unconstructible\|Refused\|Unexposed — <state>` |
| engine_edit | `// ENGINE_EDIT: ` | vendor divergence only |
| refuse_doc | `/// Refuse(` | error variants |
| api_doc | `/// ` | public contract nouns only |

This table is total; not listed = red.

Comments name Spec surface only. Motive, apology, history, metacommentary, and performative language are red.

## File template

Path touch loads this rule. Obey FILE_KIND rows below. Markers: `// --- zone-file:<id> ---` with ids imports, types, construction, order_encode, decode, verbs, state, adapters, refusals, wiring, tests. Absent section = no marker.

| FILE_KIND | section order | required | forbid |
| --- | --- | --- | --- |
| `vendor_upstream` | upstream layout | no zone-file markers on untouched upstream | upward kyzo deps |
| `vendor_engine_edit` | nearest store kind + ENGINE_EDIT on each change | undocumented divergence | |

This table is total; not listed = red.

### Dominant skeleton

```rust
// ENGINE_EDIT: <storage-contract reason this divergence exists>
```

## Path hole

ZONE_PATH_HOLE: `target-arch.md` currently lists zero vendor paths. FILE_KINDs above remain mandatory when vendor files are touched.

