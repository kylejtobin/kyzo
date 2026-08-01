---
law_format: 1
assignment: zone
zone: core
paths:
  - "crates/kyzo-core/src/exec/expr/**/*.rs"
  - "crates/kyzo-core/src/exec/fixpoint/**/*.rs"
  - "crates/kyzo-core/src/exec/fold/**/*.rs"
  - "crates/kyzo-core/src/exec/plan/**/*.rs"
  - "crates/kyzo-core/src/exec/provenance/**/*.rs"
  - "crates/kyzo-core/src/exec/stdlib/tests/**/*.rs"
  - "crates/kyzo-core/src/exec/mod.rs"
  - "crates/kyzo-core/src/exec/sort.rs"
  - "crates/kyzo-core/src/exec/op/batch_ops.rs"
  - "crates/kyzo-core/src/exec/op/delta.rs"
  - "crates/kyzo-core/src/exec/op/join.rs"
  - "crates/kyzo-core/src/exec/op/literal.rs"
  - "crates/kyzo-core/src/exec/op/mod.rs"
  - "crates/kyzo-core/src/exec/op/neg.rs"
  - "crates/kyzo-core/src/exec/op/search.rs"
  - "crates/kyzo-core/src/exec/op/stored.rs"
  - "crates/kyzo-core/src/exec/op/transform.rs"
  - "crates/kyzo-core/src/exec/stdlib/bind.rs"
  - "crates/kyzo-core/src/exec/stdlib/bound_op.rs"
  - "crates/kyzo-core/src/exec/stdlib/collection.rs"
  - "crates/kyzo-core/src/exec/stdlib/compare.rs"
  - "crates/kyzo-core/src/exec/stdlib/convert.rs"
  - "crates/kyzo-core/src/exec/stdlib/errors.rs"
  - "crates/kyzo-core/src/exec/stdlib/geo.rs"
  - "crates/kyzo-core/src/exec/stdlib/interval.rs"
  - "crates/kyzo-core/src/exec/stdlib/metric.rs"
  - "crates/kyzo-core/src/exec/stdlib/mod.rs"
  - "crates/kyzo-core/src/exec/stdlib/numeric.rs"
  - "crates/kyzo-core/src/exec/stdlib/temporal_format.rs"
  - "crates/kyzo-core/src/exec/stdlib/text.rs"
  - "crates/kyzo-core/src/project/dedup/**/*.rs"
  - "crates/kyzo-core/src/project/sparse/**/*.rs"
  - "crates/kyzo-core/src/project/spatial/**/*.rs"
  - "crates/kyzo-core/src/project/text/**/*.rs"
  - "crates/kyzo-core/src/project/vector/**/*.rs"
  - "crates/kyzo-core/src/project/contract.rs"
  - "crates/kyzo-core/src/project/current.rs"
  - "crates/kyzo-core/src/project/gazetteer.rs"
  - "crates/kyzo-core/src/project/index_fixture.rs"
  - "crates/kyzo-core/src/project/mod.rs"
  - "crates/kyzo-core/src/project/projection.rs"
  - "crates/kyzo-core/src/project/residency.rs"
  - "crates/kyzo-core/src/project/retrieval.rs"
  - "crates/kyzo-core/src/rules/algo/all_pairs_shortest_path.rs"
  - "crates/kyzo-core/src/rules/algo/astar.rs"
  - "crates/kyzo-core/src/rules/algo/bfs.rs"
  - "crates/kyzo-core/src/rules/algo/cliques.rs"
  - "crates/kyzo-core/src/rules/algo/degree_centrality.rs"
  - "crates/kyzo-core/src/rules/algo/dfs.rs"
  - "crates/kyzo-core/src/rules/algo/dijkstra.rs"
  - "crates/kyzo-core/src/rules/algo/kruskal.rs"
  - "crates/kyzo-core/src/rules/algo/louvain.rs"
  - "crates/kyzo-core/src/rules/algo/max_flow.rs"
  - "crates/kyzo-core/src/rules/algo/mod.rs"
  - "crates/kyzo-core/src/rules/algo/pagerank.rs"
  - "crates/kyzo-core/src/rules/algo/prim.rs"
  - "crates/kyzo-core/src/rules/algo/reorder_sort.rs"
  - "crates/kyzo-core/src/rules/algo/scc.rs"
  - "crates/kyzo-core/src/rules/algo/shortest_path_bfs.rs"
  - "crates/kyzo-core/src/rules/algo/top_sort.rs"
  - "crates/kyzo-core/src/rules/algo/triangles.rs"
  - "crates/kyzo-core/src/rules/algo/yen.rs"
  - "crates/kyzo-core/src/rules/contract.rs"
  - "crates/kyzo-core/src/rules/convert.rs"
  - "crates/kyzo-core/src/rules/gazetteer.rs"
  - "crates/kyzo-core/src/rules/graph_view.rs"
  - "crates/kyzo-core/src/rules/mod.rs"
  - "crates/kyzo-core/src/rules/parallel.rs"
  - "crates/kyzo-core/src/react/incremental.rs"
  - "crates/kyzo-oracle/src/**/*.rs"
  - "crates/kyzo-model/src/format.rs"
  - "crates/kyzo-model/src/format/tests.rs"
  - "crates/kyzo-model/src/value/convert.rs"
  - "crates/kyzo-model/src/value/exec.rs"
description: "Core. Total computation over already-proven values: evaluation, projection, graph algorithms, the oracle."
purity:
  - set: rust
    version: "0.1.0"
capabilities: []
---

# Core

Write the allowed construct. Anything that is not will always cause you to fail code review.

---

## Posture: Core

**Responsible for:** total computation over already-proven values.

**Requires:** every function is total. For every input its parameter types admit, it returns a value its return type admits, without panicking and without observing anything outside its arguments. Given the same arguments it returns the same result, forever, on any machine.

**Declares:** no capabilities.

**May depend on:** Proof, Core.

---

### RUST-U-01

**Rule:** Propagate the failure with `?`.

```rust allowed
pub struct Route;
pub struct RouteMissing;

pub fn first(routes: &[Route]) -> Result<&Route, RouteMissing> {
    routes.first().ok_or(RouteMissing)
}
```

```rust forbidden
pub struct Route;
pub struct RouteMissing;

pub fn first(routes: &[Route]) -> &Route {
    routes.first().unwrap()
}
```

### RUST-U-02

**Rule:** Return a typed error.

```rust allowed
pub struct Route;
pub struct RouteMissing;

pub fn first(routes: &[Route]) -> Result<&Route, RouteMissing> {
    routes.first().ok_or(RouteMissing)
}
```

```rust forbidden
pub struct Route;
pub struct RouteMissing;

pub fn first(routes: &[Route]) -> &Route {
    routes.first().expect("routes are never empty")
}
```

### RUST-U-03

**Rule:** Name the unhandled case in the return type.

```rust allowed
pub enum Tag { Data, Control, Reserved }
pub struct Frame;
pub struct ReservedTag;

pub fn decode(tag: Tag) -> Result<Frame, ReservedTag> {
    match tag {
        Tag::Data => Ok(Frame),
        Tag::Control => Ok(Frame),
        Tag::Reserved => Err(ReservedTag),
    }
}
```

```rust forbidden
pub enum Tag { Data, Control, Reserved }
pub struct Frame;
pub struct ReservedTag;

pub fn decode(tag: Tag) -> Frame {
    match tag {
        Tag::Data => Frame,
        Tag::Control => Frame,
        Tag::Reserved => panic!("reserved tag"),
    }
}
```

### RUST-U-04

**Rule:** Use `get` and return the miss.

```rust allowed
pub struct Truncated;
pub const HEADER_LEN: usize = 8;

pub fn header(frame: &[u8]) -> Result<&[u8], Truncated> {
    frame.get(..HEADER_LEN).ok_or(Truncated)
}
```

```rust forbidden
pub struct Truncated;
pub const HEADER_LEN: usize = 8;

pub fn header(frame: &[u8]) -> &[u8] {
    &frame[..HEADER_LEN]
}
```

### RUST-U-05

**Rule:** Use the checked arithmetic form and name the overflow.

```rust allowed
pub struct Cents(i64);
pub struct Quantity(i64);
pub struct Overflow;

pub fn total(unit: Cents, quantity: Quantity) -> Result<Cents, Overflow> {
    unit.0.checked_mul(quantity.0).map(Cents).ok_or(Overflow)
}
```

```rust forbidden
pub struct Cents(i64);
pub struct Quantity(i64);
pub struct Overflow;

pub fn total(unit: Cents, quantity: Quantity) -> Result<Cents, Overflow> {
    Ok(Cents(unit.0 * quantity.0))
}
```

### RUST-U-06

**Rule:** Convert with `TryFrom` and handle the failure.

```rust allowed
pub struct Slot(u16);
pub struct OutOfRange;

pub fn to_slot(raw: u32) -> Result<Slot, OutOfRange> {
    u16::try_from(raw).map(Slot).map_err(|_| OutOfRange)
}
```

```rust forbidden
pub struct Slot(u16);
pub struct OutOfRange;

pub fn to_slot(raw: u32) -> Result<Slot, OutOfRange> {
    Ok(Slot(raw as u16))
}
```

### RUST-U-07

**Rule:** Handle or propagate every `Result`.

```rust allowed
pub struct Sink;
pub struct FlushFailed;

impl Sink {
    pub fn write_all(&mut self) -> Result<(), FlushFailed> {
        Ok(())
    }
}

pub fn flush(sink: &mut Sink) -> Result<(), FlushFailed> {
    sink.write_all()
}
```

```rust forbidden
pub struct Sink;
pub struct FlushFailed;

impl Sink {
    pub fn write_all(&mut self) -> Result<(), FlushFailed> {
        Ok(())
    }
}

pub fn flush(sink: &mut Sink) {
    let _ = sink.write_all();
}
```

### RUST-U-08

**Rule:** Import a path under its own name.

```rust allowed
use crate::boundary::git::read_head;
```

```rust forbidden
use crate::boundary::git::read_head as load_state;
```

### RUST-U-09

**Rule:** Re-export only what this posture may itself reach.

```rust allowed
pub use crate::core::clause::Clause;
```

```rust forbidden
pub use crate::boundary::git::read_head;
```

### RUST-U-10

**Rule:** Return a typed verdict upward; the process exit lives only in its declared home.

```rust allowed
pub enum Verdict { Passed, Failed }
pub struct ExitCode(u8);

pub fn report(verdict: Verdict) -> ExitCode {
    match verdict {
        Verdict::Passed => ExitCode(0),
        Verdict::Failed => ExitCode(2),
    }
}
```

```rust forbidden
pub enum Verdict { Passed, Failed }
pub struct ExitCode(u8);

pub fn report(verdict: Verdict) {
    match verdict {
        Verdict::Passed => {}
        Verdict::Failed => std::process::exit(2),
    }
}
```

### RUST-C-01

**Rule:** Take domain types in every signature.

```rust allowed
pub struct EmailAddress(String);
pub struct Invite { sender: EmailAddress, recipient: EmailAddress }

pub fn invite(sender: EmailAddress, recipient: EmailAddress) -> Invite {
    Invite { sender, recipient }
}
```

```rust forbidden
pub struct EmailAddress(String);
pub struct Invite { sender: EmailAddress, recipient: EmailAddress }

pub fn invite(sender: String, recipient: String) -> Invite {
    Invite { sender: EmailAddress(sender), recipient: EmailAddress(recipient) }
}
```

### RUST-C-02

**Rule:** Carry identifiers and quantities as domain types.

```rust allowed
pub struct AccountId(u64);
pub struct Cents(i64);
pub struct Entry { from: AccountId, to: AccountId, amount: Cents }

pub fn post(from: AccountId, to: AccountId, amount: Cents) -> Entry {
    Entry { from, to, amount }
}
```

```rust forbidden
pub struct AccountId(u64);
pub struct Cents(i64);
pub struct Entry { from: AccountId, to: AccountId, amount: Cents }

pub fn post(from: u64, to: u64, amount: i64) -> Entry {
    Entry { from: AccountId(from), to: AccountId(to), amount: Cents(amount) }
}
```

### RUST-C-03

**Rule:** Take a two-variant enum.

```rust allowed
pub enum Visibility { Public, Private }
pub struct Document;
pub struct Publication { doc: Document, visibility: Visibility }

pub fn publish(doc: Document, visibility: Visibility) -> Publication {
    Publication { doc, visibility }
}
```

```rust forbidden
pub enum Visibility { Public, Private }
pub struct Document;
pub struct Publication { doc: Document, visibility: Visibility }

pub fn publish(doc: Document, is_public: bool) -> Publication {
    let visibility = if is_public { Visibility::Public } else { Visibility::Private };
    Publication { doc, visibility }
}
```

### RUST-C-04

**Rule:** Take collections of proven types.

```rust allowed
pub struct EmailAddress(String);
pub struct Notice { recipients: Vec<EmailAddress> }

pub fn notify(recipients: Vec<EmailAddress>) -> Notice {
    Notice { recipients }
}
```

```rust forbidden
pub struct EmailAddress(String);
pub struct Notice { recipients: Vec<EmailAddress> }

pub fn notify(recipients: Vec<String>) -> Notice {
    Notice { recipients: recipients.into_iter().map(EmailAddress).collect() }
}
```

### RUST-C-05

**Rule:** Match every variant of a crate-local enum.

```rust allowed
pub enum Tier { Free, Pro, Enterprise }
pub struct Cents(i64);

pub fn cost(tier: Tier) -> Cents {
    match tier {
        Tier::Free => Cents(0),
        Tier::Pro => Cents(2_000),
        Tier::Enterprise => Cents(20_000),
    }
}
```

```rust forbidden
pub enum Tier { Free, Pro, Enterprise }
pub struct Cents(i64);

pub fn cost(tier: Tier) -> Cents {
    match tier {
        Tier::Free => Cents(0),
        _ => Cents(2_000),
    }
}
```

### RUST-C-06

**Rule:** Dispatch on an enum.

```rust allowed
pub enum Method { Get, Post }
pub enum Handler { Read, Write, NotAllowed }

pub fn route(method: Method) -> Handler {
    match method {
        Method::Get => Handler::Read,
        Method::Post => Handler::Write,
    }
}
```

```rust forbidden
pub enum Method { Get, Post }
pub enum Handler { Read, Write, NotAllowed }

pub fn route(method: &str) -> Handler {
    match method {
        "GET" => Handler::Read,
        "POST" => Handler::Write,
        _ => Handler::NotAllowed,
    }
}
```

### RUST-C-07

**Rule:** Receive an already-parsed type.

```rust allowed
pub enum Namespace { User, Unknown }
pub struct StorageKey { namespace: Namespace }

pub fn classify(key: StorageKey) -> Namespace {
    key.namespace
}
```

```rust forbidden
pub enum Namespace { User, Unknown }
pub struct StorageKey { namespace: Namespace }

pub fn classify(key: &str) -> Namespace {
    if key.starts_with("user:") {
        Namespace::User
    } else {
        Namespace::Unknown
    }
}
```

### RUST-C-08

**Rule:** Select a value by a key drawn from a closed domain, through a table with an entry for every key.

```rust allowed
pub enum Command { Start, Stop }
pub enum Handler { Starter, Stopper }

pub fn handler_for(command: Command) -> Handler {
    match command {
        Command::Start => Handler::Starter,
        Command::Stop => Handler::Stopper,
    }
}
```

```rust forbidden
use std::collections::BTreeMap;

pub enum Command { Start, Stop }
pub enum Handler { Starter, Stopper }
pub struct Unknown;

pub fn handler_for<'t>(name: &str, table: &'t BTreeMap<String, Handler>) -> Result<&'t Handler, Unknown> {
    table.get(name).ok_or(Unknown)
}
```

### RUST-C-09

**Rule:** Take the data as an argument.

```rust allowed
pub struct RawConfig(String);
pub struct Config(RawConfig);
pub struct Unreadable;

pub fn parse_config(raw: RawConfig) -> Result<Config, Unreadable> {
    Ok(Config(raw))
}
```

```rust forbidden
pub struct RawConfig(String);
pub struct Config(RawConfig);
pub struct Unreadable;

pub fn parse_config(path: &str) -> Result<Config, Unreadable> {
    let raw = std::fs::read_to_string(path).map_err(|_| Unreadable)?;
    Ok(Config(RawConfig(raw)))
}
```

### RUST-C-10

**Rule:** Take the instant as an argument.

```rust allowed
pub struct Timestamp(u64);
pub enum Expiry { Live, Expired }

pub struct Session { expires_at: Timestamp }

pub fn expiry(session: &Session, now: Timestamp) -> Expiry {
    match now.0 < session.expires_at.0 {
        true => Expiry::Live,
        false => Expiry::Expired,
    }
}
```

```rust forbidden
pub struct Timestamp(u64);
pub enum Expiry { Live, Expired }

pub struct Session { expires_at: Timestamp }

pub fn expiry(session: &Session) -> Expiry {
    let now = Timestamp(std::time::UNIX_EPOCH.elapsed().map(|d| d.as_secs()).unwrap_or(0));
    match now.0 < session.expires_at.0 {
        true => Expiry::Live,
        false => Expiry::Expired,
    }
}
```

### RUST-C-11

**Rule:** Take the generator as an argument.

```rust allowed
use rand::Rng;

pub struct Candidate(u32);
pub struct Pool(Vec<Candidate>);

pub fn sample<'p, R: Rng>(pool: &'p Pool, rng: &mut R) -> Option<&'p Candidate> {
    pool.0.get(rng.gen_range(0..pool.0.len()))
}
```

```rust forbidden
use rand::Rng;

pub struct Candidate(u32);
pub struct Pool(Vec<Candidate>);

pub fn sample<'p>(pool: &'p Pool) -> Option<&'p Candidate> {
    let mut rng = rand::thread_rng();
    pool.0.get(rng.gen_range(0..pool.0.len()))
}
```

### RUST-C-12

**Rule:** Iterate ordered collections when the output order matters.

```rust allowed
use std::collections::BTreeMap;

pub struct StorageKey(String);
pub struct Digest(String);
pub struct Line(String);

pub fn manifest(entries: &BTreeMap<StorageKey, Digest>) -> Vec<Line> {
    entries.values().map(|digest| Line(digest.0.clone())).collect()
}
```

```rust forbidden
use std::collections::HashMap;

pub struct StorageKey(String);
pub struct Digest(String);
pub struct Line(String);

pub fn manifest(entries: &HashMap<StorageKey, Digest>) -> Vec<Line> {
    entries.values().map(|digest| Line(digest.0.clone())).collect()
}
```

### RUST-C-13

**Rule:** Import from Proof and Core only.

```rust allowed
use crate::core::clause::Clause;
```

```rust forbidden
use crate::boundary::git::read_head;
```

### RUST-C-14

**Rule:** Call the declared implementation.

```rust allowed
pub struct StorageKey(String);
pub struct Bytes(Vec<u8>);

pub mod canonical {
    use super::{Bytes, StorageKey};

    pub fn encode(key: &StorageKey) -> Bytes {
        Bytes(key.0.as_bytes().to_vec())
    }
}

pub fn encode(key: &StorageKey) -> Bytes {
    canonical::encode(key)
}
```

```rust forbidden
pub struct StorageKey(String);
pub struct Bytes(Vec<u8>);

pub mod canonical {
    use super::{Bytes, StorageKey};

    pub fn encode(key: &StorageKey) -> Bytes {
        Bytes(key.0.as_bytes().to_vec())
    }
}

pub fn encode(key: &StorageKey) -> Bytes {
    Bytes(key.0.as_bytes().to_vec())
}
```

### RUST-C-15

**Rule:** Define invariant-carrying types in Proof; declare only local types with no invariant here.

```rust allowed
use crate::proof::port::Port;

struct ScanState {
    seen: usize,
    highest: Port,
}
```

```rust forbidden
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);

struct ScanState {
    seen: usize,
    highest: Port,
}
```

### RUST-C-16

**Rule:** Declare a fact implied by a value's own members on that value.

```rust allowed
pub struct Cents(i64);

pub struct Receipt {
    subtotal: Cents,
    tax: Cents,
}

impl Receipt {
    pub fn total(&self) -> Cents {
        Cents(self.subtotal.0 + self.tax.0)
    }
}
```

```rust forbidden
pub struct Cents(i64);

pub struct Receipt {
    subtotal: Cents,
    tax: Cents,
}

pub fn total(receipt: &Receipt) -> Cents {
    Cents(receipt.subtotal.0 + receipt.tax.0)
}
```

### RUST-C-17

**Rule:** Reduce a collection with a fold.

```rust allowed
pub struct Length(usize);

pub fn covered(lengths: &[Length]) -> Length {
    Length(lengths.iter().fold(0, |total, len| total + len.0))
}
```

```rust forbidden
pub struct Length(usize);

pub fn covered(lengths: &[Length]) -> Length {
    let mut total = 0;
    for len in lengths {
        total += len.0;
    }
    Length(total)
}
```
