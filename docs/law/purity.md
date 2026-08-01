---
law_format: 1
set: rust
version: "0.1.0"
kind: purity
description: "Rust at maximum type-driven purity. Clauses partitioned by the posture they bind to."
---

# Rust purity law

A value's existence is a proof of its validity. Every clause closes one route by which a Rust program produces a value that proves nothing, or loses a proof it had.

Each clause carries a `Binds` line naming the postures it applies to. Emission composes a zone's rule file from the clauses that bind there, so a file touch loads the law for that position and nothing else. `postures.md` defines the postures.

Every clause carries a `Rule` line: one imperative sentence, which is what emission puts in the zone file above the demo pair. The prose below it explains and is not emitted.

**Each demo pair is self-contained.** Emission ships a clause's `Rule` line and its pair into a zone rule file and ships nothing else, so a block that leans on a declaration living elsewhere in this document arrives at the agent as a fragment. Both halves declare what they use, identically, so the only difference between them is the one the `Rule` names.

Clause IDs are stable within this major version.

---

# Universal

Clauses that bind at every position. There is no posture at which these are acceptable.

### RUST-U-01

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Propagate the failure with `?`.
**Violation:** UncheckedFallibility

`unwrap` converts a failure the callee's type declared into a runtime abort the caller's type does not.

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

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Return a typed error.
**Violation:** UncheckedFallibility

`expect` is `unwrap` with a comment. The message improves the crash and does not move the failure into the type.

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

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Name the unhandled case in the return type.
**Violation:** UncheckedFallibility

A case the code cannot handle is a case the return type must name. `panic!`, `todo!`, and `unimplemented!` are exits from the type system.

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

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Use `get` and return the miss.
**Violation:** UncheckedFallibility

Indexing panics out of bounds. The bound is a fact about the data and belongs in the return type.

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

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Use the checked arithmetic form and name the overflow.
**Violation:** UncheckedFallibility

Overflow, underflow, and division by zero are failures the signature does not mention.

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

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Convert with `TryFrom` and handle the failure.
**Violation:** UncheckedFallibility

`as` truncates, wraps, and loses precision silently.

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

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Handle or propagate every `Result`.
**Violation:** UncheckedFallibility

A discarded `Result` deletes a failure the callee took care to report.

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

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Import a path under its own name.
**Violation:** AliasEvasion

The obligation is about what the code reaches, not what it calls it.

```rust allowed
use crate::boundary::git::read_head;
```

```rust forbidden
use crate::boundary::git::read_head as load_state;
```

### RUST-U-09

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Re-export only what this posture may itself reach.
**Violation:** AliasEvasion

A re-export launders a path: callers import from a legal module and reach an illegal one. The edge exists at the re-export.

```rust allowed
pub use crate::core::clause::Clause;
```

```rust forbidden
pub use crate::boundary::git::read_head;
```

### RUST-U-10

**Binds:** Proof, Core, Boundary, Shell
**Rule:** Return a typed verdict upward; the process exit lives only in its declared home.
**Violation:** UndeclaredSingleton

A second exit site means two answers to when and how the program ends, and callers of the first can never observe a verdict.

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

---

# Proof

Vocabulary. Types and the proofs that construct them. This is where a value's validity is established, so this is where construction, ordering, and representation law lives.

### RUST-S-01

**Binds:** Proof
**Rule:** Keep invariant-carrying fields private; expose them through methods that cannot break the proof.
**Violation:** UnprovenConstruction

A public field lets any caller write past the constructor.

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

**Binds:** Proof
**Rule:** Keep field visibility narrower than type visibility, so no other module can build the type by literal.
**Violation:** UnprovenConstruction

A type whose fields are reachable from another module has no constructor, only a suggestion.

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

**Binds:** Proof
**Rule:** Carry the constraint in the parameter's type so construction is total.
**Violation:** UnprovenConstruction

An infallible constructor over a parameter wide enough to hold an illegal value asserts a proof it did not perform. The answer is not a check in the body: a body that reads its input and decides is a type that was left wide. Narrow the parameter until the illegal value cannot arrive.

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

**Binds:** Proof
**Rule:** Implement `Default` only where every value of the type is legal.
**Violation:** UnprovenConstruction

`Default` cannot fail, so on an invariant-carrying type it manufactures a value with no proof. The empty string is a legal `String` and an illegal `Slug`.

```rust allowed
#[derive(Default)]
pub struct Verbosity(u8);
```

```rust forbidden
#[derive(Default)]
pub struct Slug(String);
```

### RUST-S-05

**Binds:** Proof
**Rule:** Keep unchecked construction private to the module that owns the invariant.
**Violation:** UnprovenConstruction

An exposed unchecked constructor is a public door around the proof.

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

**Binds:** Proof
**Rule:** Route deserialization through the constructor with `try_from`.
**Violation:** UnprovenConstruction

A derived `Deserialize` writes fields directly and never calls the constructor, so any wire byte becomes a domain value.

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

**Binds:** Proof
**Rule:** Offer consuming transformations that re-prove.
**Violation:** UnprovenConstruction

A mutable borrow lets a caller edit the value out from under its proof.

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

**Binds:** Proof
**Rule:** Prove in the constructor.
**Violation:** PostHocValidation

A `validate` method proves nothing about the values that skipped the call.

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

**Binds:** Proof
**Rule:** Make the invalid state unrepresentable.
**Violation:** PostHocValidation

The predicate's existence says the type admits invalid values, whatever callers do with it.

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

**Binds:** Proof
**Rule:** Trust the constructor.
**Violation:** PostHocValidation

If the assertion can fail the constructor is wrong, and if it cannot the assertion is noise that will be read as a proof.

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

**Binds:** Proof
**Rule:** Define a domain concept as a newtype.
**Violation:** PrimitiveInDomainPosition

An alias is the same type under a second name. It reads like a domain type at the declaration and protects nothing at any call site.

```rust allowed
pub struct UserId(u64);
```

```rust forbidden
pub type UserId = u64;
```

### RUST-S-12

**Binds:** Proof
**Rule:** Name a domain aggregate and declare its parts as named fields.
**Violation:** PrimitiveInDomainPosition

A tuple has positional fields with no names, so nothing distinguishes the two ends from each other.

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

**Binds:** Proof
**Rule:** Represent absence with `Option`.
**Violation:** SentinelForAbsence

A sentinel is a legal value of the type that means something else, and every consumer must remember the convention.

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

**Binds:** Proof
**Rule:** Distinguish absent from empty in the type.
**Violation:** SentinelForAbsence

A provided-but-empty list and an absent list are different facts.

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

**Binds:** Proof
**Rule:** State the order law in the type's documentation wherever `Ord` is implemented.
**Violation:** UnlawfulOrdering

`Ord` defines the order every sort, range, and canonical encoding depends on. Unstated, the next reader infers one from the code and is wrong.

```rust allowed
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Namespace(String);

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
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Namespace(String);

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyBytes(Vec<u8>);

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct StorageKey {
    namespace: Namespace,
    key: KeyBytes,
}
```

### RUST-S-16

**Binds:** Proof
**Rule:** Carry ordered or compared quantities as a totally ordered type.
**Violation:** UnlawfulOrdering

Floats have no total order and no reflexive equality, so the comparison is not a law.

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

**Binds:** Proof
**Rule:** Derive `Hash` and `Eq` together, or implement both by hand consistently.
**Violation:** UnlawfulOrdering

Equal values must hash equally. A manual implementation of one beside a derived implementation of the other breaks that quietly, and map lookups fail in ways no test finds.

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

**Binds:** Proof
**Rule:** Leave crate-internal enums exhaustive; reserve `#[non_exhaustive]` for published API boundaries.
**Violation:** OpenMatchOnClosedType

On a type this crate owns and consumes, it forces its own matches to carry a wildcard, reintroducing the fallthrough it was meant to control.

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

**Binds:** Proof
**Rule:** Use an ordered collection inside any type that is encoded, hashed, or compared.
**Violation:** NondeterministicIteration

A hash-ordered collection makes the encoding depend on insertion history, so the same logical value produces two different byte strings.

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

**Binds:** Proof
**Rule:** Depend on nothing. A Proof crate declares no dependencies at all.
**Violation:** ForbiddenDependencyEdge

The vocabulary both consumers bind to cannot itself bind to either, or the proof is not a proof.

```toml allowed
# crates/canon-model/Cargo.toml
[dependencies]
```

```toml forbidden
# crates/canon-model/Cargo.toml
[dependencies]
canon-kernel = { path = "../canon-kernel" }
```

---

# Core

Total computation over already-proven values. Every function returns a value its return type admits, for every input its parameter types admit, without panicking and without observing anything outside its arguments.

### RUST-C-01

**Binds:** Core
**Rule:** Take domain types in every signature.
**Violation:** PrimitiveInDomainPosition

Two `String` parameters can be swapped at a call site and the program still compiles.

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

**Binds:** Core
**Rule:** Carry identifiers and quantities as domain types.
**Violation:** PrimitiveInDomainPosition

An integer admits every arithmetic operation the domain does not have. A user ID is not a number you may add to another user ID.

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

**Binds:** Core
**Rule:** Take a two-variant enum.
**Violation:** PrimitiveInDomainPosition

A `bool` names nothing at the call site and admits no third case when the domain grows one.

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

**Binds:** Core
**Rule:** Take collections of proven types.
**Violation:** PrimitiveInDomainPosition

A collection of primitives pushes the missing proof onto every element and every consumer.

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

**Binds:** Core, Shell
**Rule:** Match every variant of a crate-local enum.
**Violation:** OpenMatchOnClosedType

The compiler is offering to find every site that must change when a variant is added, and the wildcard declines.

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

**Binds:** Core
**Rule:** Dispatch on an enum.
**Violation:** StringlyTypedDiscrimination

Matching on a string moves the type check to runtime and loses exhaustiveness. Adding a domain case compiles cleanly and silently does nothing.

Excluded from this pair: RUST-C-05. A `&str` match has no exhaustive form, so the forbidden block must carry a wildcard arm. That arm is incidental here and is not what this clause recognizes.

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

**Binds:** Core
**Rule:** Receive an already-parsed type.
**Violation:** StringlyTypedDiscrimination

Prefix and substring tests are parsing performed at every call site instead of once at the boundary.

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

**Binds:** Core
**Rule:** Select a value by a key drawn from a closed domain, through a table with an entry for every key.
**Violation:** StringlyTypedDiscrimination

A string-keyed dispatch table is an open set where the domain is closed, so a typo is a runtime miss rather than a compile error, and the lookup must return a refusal the domain cannot actually produce.

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

**Binds:** Core
**Rule:** Take the data as an argument.
**Violation:** EscapedCapability

An effect reached from inside a computation makes it untestable and its result dependent on facts its signature does not mention.

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

**Binds:** Core
**Rule:** Take the instant as an argument.
**Violation:** EscapedCapability

Reading the clock makes the result a function of when it ran.

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

**Binds:** Core
**Rule:** Take the generator as an argument.
**Violation:** EscapedCapability

Ambient randomness makes a run unrepeatable and a failure unreproducible.

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

**Binds:** Core
**Rule:** Iterate ordered collections when the output order matters.
**Violation:** NondeterministicIteration

Hash-ordered iteration produces a different sequence per process, and the failure appears far from the cause.

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

**Binds:** Core
**Rule:** Import from Proof and Core only.
**Violation:** ForbiddenDependencyEdge

Reaching a boundary module acquires its capability, whatever the calling function does with it.

```rust allowed
use crate::core::clause::Clause;
```

```rust forbidden
use crate::boundary::git::read_head;
```

### RUST-C-14

**Binds:** Core
**Rule:** Call the declared implementation.
**Violation:** UndeclaredSingleton

Two encoders or two parsers mean the program has no single truth about that concern.

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

**Binds:** Core
**Rule:** Define invariant-carrying types in Proof; declare only local types with no invariant here.
**Violation:** UnprovenConstruction

A domain type defined outside the vocabulary is a proof nobody else can find or reuse, and it will be duplicated.

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

**Binds:** Core
**Rule:** Declare a fact implied by a value's own members on that value.
**Violation:** UndeclaredSingleton

A free function that reaches into a value's members is a second home for a fact the value already implies, and the two drift the moment either changes.

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

**Binds:** Core
**Rule:** Reduce a collection with a fold.
**Violation:** UnprovenConstruction

A mutable accumulator makes the result a function of how far the loop got, so a partial traversal and a complete one have the same type and only one of them is the answer.

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

---

# Boundary

Where unproven input becomes proven values, and where declared effects happen. A Boundary module names its entry points; everything that is not an entry point is held to Core.

### RUST-B-01

**Binds:** Boundary
**Rule:** Return `Result` from every entry point.
**Violation:** UnprovenConstruction

The entry point exists to convert unproven input, and conversion can fail. An entry point that returns a domain type infallibly is claiming a proof it could not perform.

```rust allowed
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);
pub struct NotAPort;

pub fn parse_port(raw: &str) -> Result<Port, NotAPort> {
    raw.parse::<NonZeroU16>().map(Port).map_err(|_| NotAPort)
}
```

```rust forbidden
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);
pub struct NotAPort;

pub fn parse_port(raw: &str) -> Port {
    Port(raw.parse::<NonZeroU16>().unwrap_or(NonZeroU16::MIN))
}
```

### RUST-B-02

**Binds:** Boundary
**Rule:** Return proven types from entry points.
**Violation:** PrimitiveInDomainPosition

Primitives on an entry point's parameters are correct, because that is what the outside sends. Primitives on its return type move the boundary somewhere with no law.

```rust allowed
// zone declares: filesystem
pub struct Config(String);
pub struct Unreadable;

pub fn read_config(path: &str) -> Result<Config, Unreadable> {
    std::fs::read_to_string(path).map(Config).map_err(|_| Unreadable)
}
```

```rust forbidden
// zone declares: filesystem
pub struct Config(String);
pub struct Unreadable;

pub fn read_config(path: &str) -> Result<String, Unreadable> {
    std::fs::read_to_string(path).map_err(|_| Unreadable)
}
```

### RUST-B-03

**Binds:** Boundary
**Rule:** Keep the wire type distinct from the domain type, and convert between them explicitly.
**Violation:** UnprovenConstruction

One type serving as both means the domain type has a construction path that performs no proof.

```rust allowed
use serde::Deserialize;
use std::num::NonZeroU16;

#[derive(Deserialize)]
struct WireConfig {
    port: u16,
}

pub struct Config {
    port: NonZeroU16,
}

pub struct BadConfig;

pub fn decode(bytes: &[u8]) -> Result<Config, BadConfig> {
    let wire: WireConfig = serde_json::from_slice(bytes).map_err(|_| BadConfig)?;
    NonZeroU16::new(wire.port).map(|port| Config { port }).ok_or(BadConfig)
}
```

```rust forbidden
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    port: u16,
}

pub struct BadConfig;

pub fn decode(bytes: &[u8]) -> Result<Config, BadConfig> {
    serde_json::from_slice(bytes).map_err(|_| BadConfig)
}
```

### RUST-B-04

**Binds:** Boundary
**Rule:** Prove once at construction.
**Violation:** PostHocValidation

A second check on a proven value says the first proof is not trusted, and the two will drift.

```rust allowed
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);
pub struct Listener;
pub struct BindFailed;

pub fn bind(port: Port) -> Result<Listener, BindFailed> {
    let _ = port;
    Ok(Listener)
}
```

```rust forbidden
use std::num::NonZeroU16;

pub struct Port(NonZeroU16);
pub struct Listener;
pub struct BindFailed;

pub fn bind(port: Port) -> Result<Listener, BindFailed> {
    if port.0.get() < 1024 {
        return Err(BindFailed);
    }
    Ok(Listener)
}
```

### RUST-B-05

**Binds:** Boundary
**Rule:** Reach only the capabilities this zone's law file declares.
**Violation:** EscapedCapability

Declaring one capability is an addition to the zone's obligations, not a removal of the others. A zone that declares filesystem access still fires on a clock read.

```rust allowed
// zone declares: filesystem
pub struct RawConfig { body: String }
pub struct Unreadable;

pub fn read_config(path: &str) -> Result<RawConfig, Unreadable> {
    let body = std::fs::read_to_string(path).map_err(|_| Unreadable)?;
    Ok(RawConfig { body })
}
```

```rust forbidden
// zone declares: filesystem
pub struct RawConfig { body: String, read_at: std::time::SystemTime }
pub struct Unreadable;

pub fn read_config(path: &str) -> Result<RawConfig, Unreadable> {
    let body = std::fs::read_to_string(path).map_err(|_| Unreadable)?;
    Ok(RawConfig { body, read_at: std::time::SystemTime::now() })
}
```

### RUST-B-06

**Binds:** Boundary
**Rule:** Parse raw input at the entry point.
**Violation:** PrimitiveInDomainPosition

Raw input held in a struct is a deferred parse, and it will be parsed again at every use.

```rust allowed
pub struct Uri(String);
pub enum Method { Get, Post }

pub struct Request {
    target: Uri,
    method: Method,
}
```

```rust forbidden
pub struct Uri(String);
pub enum Method { Get, Post }

pub struct Request {
    target: String,
    method: String,
}
```

### RUST-B-07

**Binds:** Boundary
**Rule:** Import from Proof, Core, and Boundary.
**Violation:** ForbiddenDependencyEdge

A boundary reaching upward into composition inverts the layering and makes the boundary untestable in isolation.

```rust allowed
use crate::core::plan::Plan;
```

```rust forbidden
use crate::shell::render::Renderer;
```

---

# Shell

Composition, marshaling, rendering, and termination. Shell wires the program together, holds the capabilities the other postures declared, and converts typed verdicts into output and exit codes.

### RUST-SH-01

**Binds:** Shell
**Rule:** Match on the typed error.
**Violation:** StringlyTypedDiscrimination

Stringifying a typed error throws away the structure the error type exists to carry, and the match becomes a guess about the formatter.

```rust allowed
pub enum ConfigError { Io, Decode }
pub enum ExitCode { Io, BadInput }

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("io")
    }
}

pub fn exit_code(err: &ConfigError) -> ExitCode {
    match err {
        ConfigError::Io => ExitCode::Io,
        ConfigError::Decode => ExitCode::BadInput,
    }
}
```

```rust forbidden
pub enum ConfigError { Io, Decode }
pub enum ExitCode { Io, BadInput }

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("io")
    }
}

pub fn exit_code(err: &ConfigError) -> ExitCode {
    match err.to_string().contains("io") {
        true => ExitCode::Io,
        false => ExitCode::BadInput,
    }
}
```

### RUST-SH-02

**Binds:** Shell
**Rule:** Reach only the capabilities this zone's law file declares, and pass them down as arguments.
**Violation:** EscapedCapability

Shell is where capabilities normally live, and each is declared explicitly rather than assumed from the posture name.

```rust allowed
// zone declares: time
pub struct Clock;
pub struct Timestamp(u64);
pub struct Verdict;

impl Clock {
    pub fn now(&self) -> Timestamp {
        Timestamp(0)
    }
}

pub fn run(clock: Clock) -> Verdict {
    let _ = clock.now();
    Verdict
}
```

```rust forbidden
// zone declares: time
pub struct Clock;
pub struct Timestamp(u64);
pub struct Verdict;

impl Clock {
    pub fn now(&self) -> Timestamp {
        Timestamp(0)
    }
}

pub fn run(clock: Clock) -> Verdict {
    let _ = clock.now();
    let _seed = rand::random::<u64>();
    Verdict
}
```

### RUST-SH-03

**Binds:** Shell
**Rule:** Read through the owning module on every request.
**Violation:** UndeclaredSingleton

A shadow copy is a second source of truth that will disagree, and nothing in the type system will say when.

```rust allowed
pub struct Engine;

pub struct Server {
    engine: Engine,
}
```

```rust forbidden
use std::collections::BTreeMap;

pub struct Engine;
pub struct StorageKey(String);
pub struct View(String);

pub struct Server {
    engine: Engine,
    cache: BTreeMap<StorageKey, View>,
}
```

### RUST-SH-04

**Binds:** Shell
**Rule:** Construct domain values by calling a Boundary entry point.
**Violation:** UnprovenConstruction

Shell holding a construction path is a second boundary with no law, and it will be the one that skips the proof.

```rust allowed
use crate::boundary::config::parse_config;

pub struct Args(Vec<String>);
pub struct Config { port: u16 }
pub struct BadArgs;

pub fn run(args: Args) -> Result<Config, BadArgs> {
    parse_config(&args.0).map_err(|_| BadArgs)
}
```

```rust forbidden
use crate::boundary::config::parse_config;

pub struct Args(Vec<String>);
pub struct Config { port: u16 }
pub struct BadArgs;

pub fn run(args: Args) -> Result<Config, BadArgs> {
    let port = args.0.first().ok_or(BadArgs)?.parse::<u16>().map_err(|_| BadArgs)?;
    Ok(Config { port })
}
```
