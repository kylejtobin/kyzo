---
law_format: 1
assignment: zone
zone: proof
paths:
  - "crates/kyzo-model/src/value/kind/**/*.rs"
  - "crates/kyzo-model/src/schema/**/*.rs"
  - "crates/kyzo-model/src/program/**/*.rs"
  - "crates/kyzo-model/src/typestate.rs"
  - "crates/kyzo-model/src/lib.rs"
  - "crates/kyzo-model/src/value/number.rs"
  - "crates/kyzo-model/src/value/test_rng.rs"
  - "crates/kyzo-model/src/value/admission.rs"
  - "crates/kyzo-model/src/value/arity.rs"
  - "crates/kyzo-model/src/value/bytes_qty.rs"
  - "crates/kyzo-model/src/value/canonical.rs"
  - "crates/kyzo-model/src/value/cell.rs"
  - "crates/kyzo-model/src/value/code.rs"
  - "crates/kyzo-model/src/value/codec.rs"
  - "crates/kyzo-model/src/value/column.rs"
  - "crates/kyzo-model/src/value/mod.rs"
  - "crates/kyzo-model/src/value/prefix.rs"
  - "crates/kyzo-model/src/value/proofs.rs"
  - "crates/kyzo-model/src/value/row.rs"
  - "crates/kyzo-model/src/value/search_hits.rs"
  - "crates/kyzo-model/src/value/string.rs"
  - "crates/kyzo-model/src/value/tag.rs"
  - "crates/kyzo-model/src/value/validity_coerce.rs"
  - "crates/kyzo-core/src/data/digest.rs"
  - "crates/kyzo-core/src/data/fixed_bytes.rs"
  - "crates/kyzo-core/src/data/statement.rs"
  - "crates/kyzo-core/src/refusal.rs"
  - "crates/kyzo-core/src/session/record_id.rs"
  - "crates/kyzo-core/src/project/dimension.rs"
  - "crates/kyzo-core/src/store/keys.rs"
  - "crates/kyzo-core/src/store/digest_domain.rs"
  - "crates/kyzo-core/src/store/epoch.rs"
  - "crates/kyzo-core/src/store/nonce.rs"
description: "Proof. The value vocabulary, its constructors, its order law, and its canonical bytes."
purity:
  - set: rust
    version: "0.1.0"
capabilities: []
---

# Proof

Write the allowed construct. Anything that is not will always cause you to fail code review.

---

## Posture: Proof

**Responsible for:** establishing proof. Types, their constructors, their ordering, their representation.

**Requires:** every exported type is constructible only through a proof. A Proof module exporting a type with no constructor has exported a shape, not a vocabulary.

**Declares:** no capabilities.

**May depend on:** nothing. Not the standard library beyond core vocabulary, not other crates in the workspace, not other postures. This is stricter than Core, and it is the reason Proof is separate: the vocabulary both consumers bind to cannot bind to either.

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
pub use crate::clause::Clause;
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

### RUST-S-01

**Rule:** Keep invariant-carrying fields private; expose them through methods that cannot break the proof.

```rust allowed
use std::num::NonZeroU16;

pub struct Port {
    number: NonZeroU16,
}
```

```rust forbidden
use std::num::NonZeroU16;

pub struct Port {
    pub number: NonZeroU16,
}
```

### RUST-S-02

**Rule:** Keep field visibility narrower than type visibility, so no other module can build the type by literal.

```rust allowed
pub struct Offset(usize);
pub struct Length(usize);

pub struct Span {
    start: Offset,
    len: Length,
}
```

```rust forbidden
pub struct Offset(usize);
pub struct Length(usize);

pub struct Span {
    pub(crate) start: Offset,
    pub(crate) len: Length,
}
```

### RUST-S-03

**Rule:** Carry the constraint in the parameter's type so construction is total.

```rust allowed
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);

impl Port {
    pub fn new(number: NonZeroU16) -> Self {
        Self(number)
    }
}
```

```rust forbidden
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);

impl Port {
    pub fn new(number: u16) -> Self {
        Self(NonZeroU16::new(number).unwrap())
    }
}
```

### RUST-S-04

**Rule:** Implement `Default` only where every value of the type is legal.

```rust allowed
#[derive(Default)]
pub struct Verbosity(u8);
```

```rust forbidden
#[derive(Default)]
pub struct Slug(String);
```

### RUST-S-05

**Rule:** Keep unchecked construction private to the module that owns the invariant.

```rust allowed
pub struct Slug(String);

impl Slug {
    fn new_unchecked(text: String) -> Self {
        Self(text)
    }
}
```

```rust forbidden
pub struct Slug(String);

impl Slug {
    pub fn new_unchecked(text: String) -> Self {
        Self(text)
    }
}
```

### RUST-S-06

**Rule:** Route deserialization through the constructor with `try_from`.

```rust allowed
use serde::Deserialize;
use std::num::NonZeroU16;

#[derive(Deserialize)]
#[serde(try_from = "u16")]
pub struct Port(NonZeroU16);

impl TryFrom<u16> for Port {
    type Error = Reserved;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        NonZeroU16::new(raw).map(Port).ok_or(Reserved)
    }
}

#[derive(Debug)]
pub struct Reserved;

impl std::fmt::Display for Reserved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("port zero is reserved")
    }
}
```

```rust forbidden
use serde::Deserialize;
use std::num::NonZeroU16;

#[derive(Deserialize)]
pub struct Port(NonZeroU16);

impl TryFrom<u16> for Port {
    type Error = Reserved;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        NonZeroU16::new(raw).map(Port).ok_or(Reserved)
    }
}

#[derive(Debug)]
pub struct Reserved;

impl std::fmt::Display for Reserved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("port zero is reserved")
    }
}
```

### RUST-S-07

**Rule:** Offer consuming transformations that re-prove.

```rust allowed
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);

impl Port {
    pub fn with_number(self, number: NonZeroU16) -> Self {
        Self(number)
    }
}
```

```rust forbidden
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);

impl Port {
    pub fn number_mut(&mut self) -> &mut NonZeroU16 {
        &mut self.0
    }
}
```

### RUST-S-08

**Rule:** Prove in the constructor.

```rust allowed
use std::num::NonZeroU16;

pub struct Config {
    port: NonZeroU16,
}

impl Config {
    pub fn new(port: NonZeroU16) -> Self {
        Self { port }
    }
}
```

```rust forbidden
use std::num::NonZeroU16;

pub struct Config {
    port: u16,
}

impl Config {
    pub fn validate(&self) -> Result<(), Reserved> {
        NonZeroU16::new(self.port).map(|_| ()).ok_or(Reserved)
    }
}

pub struct Reserved;
```

### RUST-S-09

**Rule:** Make the invalid state unrepresentable.

```rust allowed
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);

impl Port {
    pub fn get(&self) -> NonZeroU16 {
        self.0
    }
}
```

```rust forbidden
pub struct Port(u16);

impl Port {
    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }
}
```

### RUST-S-10

**Rule:** Trust the constructor.

```rust allowed
pub struct Slug(String);

impl Slug {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

```rust forbidden
pub struct Slug(String);

impl Slug {
    pub fn as_str(&self) -> &str {
        debug_assert!(!self.0.is_empty(), "slug invariant violated");
        &self.0
    }
}
```

### RUST-S-11

**Rule:** Define a domain concept as a newtype.

```rust allowed
pub struct UserId(u64);
```

```rust forbidden
pub type UserId = u64;
```

### RUST-S-12

**Rule:** Name a domain aggregate and declare its parts as named fields.

```rust allowed
pub struct Offset(usize);
pub struct Length(usize);

pub struct Span {
    start: Offset,
    len: Length,
}
```

```rust forbidden
pub struct Offset(usize);
pub struct Length(usize);

pub struct Span {
    parts: (Offset, Length),
}
```

### RUST-S-13

**Rule:** Represent absence with `Option`.

```rust allowed
pub struct Timestamp(i64);

pub struct Session {
    expires_at: Option<Timestamp>,
}
```

```rust forbidden
pub struct Timestamp(i64);

pub const NEVER_EXPIRES: Timestamp = Timestamp(-1);

pub struct Session {
    expires_at: Timestamp,
}
```

### RUST-S-14

**Rule:** Distinguish absent from empty in the type.

```rust allowed
pub struct Filter(String);

pub struct Query {
    filters: Option<Vec<Filter>>,
}
```

```rust forbidden
pub struct Filter(String);

pub struct Query {
    filters: Vec<Filter>,
}
```

### RUST-S-15

**Rule:** State the order law in the type's documentation wherever `Ord` is implemented.

```rust allowed
/// ORDER_LAW: byte order over the namespace. Total and stable.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Namespace(String);

/// ORDER_LAW: byte order over the key. Total and stable.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyBytes(Vec<u8>);

/// ORDER_LAW: lexicographic over (namespace, key), namespace ascending.
/// Total and stable across releases. Changing it is a format break.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct StorageKey {
    namespace: Namespace,
    key: KeyBytes,
}
```

```rust forbidden
/// ORDER_LAW: byte order over the namespace. Total and stable.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Namespace(String);

/// ORDER_LAW: byte order over the key. Total and stable.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyBytes(Vec<u8>);

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct StorageKey {
    namespace: Namespace,
    key: KeyBytes,
}
```

### RUST-S-16

**Rule:** Carry ordered or compared quantities as a totally ordered type.

```rust allowed
/// ORDER_LAW: ascending over the underlying micros. Total and stable.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Score(i64);
```

```rust forbidden
/// ORDER_LAW: ascending over the underlying value. Total and stable.
#[derive(PartialEq, PartialOrd)]
pub struct Score(f64);
```

### RUST-S-17

**Rule:** Derive `Hash` and `Eq` together, or implement both by hand consistently.

```rust allowed
#[derive(PartialEq, Eq, Hash)]
pub struct EmailAddress(String);
```

```rust forbidden
#[derive(Hash)]
pub struct EmailAddress(String);

impl PartialEq for EmailAddress {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for EmailAddress {}
```

### RUST-S-18

**Rule:** Leave crate-internal enums exhaustive; reserve `#[non_exhaustive]` for published API boundaries.

```rust allowed
pub(crate) enum Tier {
    Free,
    Pro,
    Enterprise,
}
```

```rust forbidden
#[non_exhaustive]
pub(crate) enum Tier {
    Free,
    Pro,
    Enterprise,
}
```

### RUST-S-19

**Rule:** Use an ordered collection inside any type that is encoded, hashed, or compared.

```rust allowed
use std::collections::BTreeMap;

pub struct StorageKey(String);
pub struct Digest([u8; 32]);

pub struct Snapshot {
    entries: BTreeMap<StorageKey, Digest>,
}
```

```rust forbidden
use std::collections::HashMap;

pub struct StorageKey(String);
pub struct Digest([u8; 32]);

pub struct Snapshot {
    entries: HashMap<StorageKey, Digest>,
}
```

### RUST-S-20

**Rule:** Depend on nothing. A Proof crate declares no dependencies at all.

```toml allowed
# crates/canon-model/Cargo.toml
[dependencies]
```

```toml forbidden
# crates/canon-model/Cargo.toml
[dependencies]
canon-kernel = { path = "../canon-kernel" }
```
