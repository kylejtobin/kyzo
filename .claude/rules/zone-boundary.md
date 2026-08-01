---
law_format: 1
assignment: zone
zone: boundary
globs:
  - "crates/kyzo-core/src/session/access.rs"
  - "crates/kyzo-core/src/session/admit.rs"
  - "crates/kyzo-core/src/session/admit_lowering.rs"
  - "crates/kyzo-core/src/session/admit_supersession.rs"
  - "crates/kyzo-core/src/session/capacity.rs"
  - "crates/kyzo-core/src/session/catalog.rs"
  - "crates/kyzo-core/src/session/certificate_inject.rs"
  - "crates/kyzo-core/src/session/composition.rs"
  - "crates/kyzo-core/src/session/constraint.rs"
  - "crates/kyzo-core/src/session/db.rs"
  - "crates/kyzo-core/src/session/fts.rs"
  - "crates/kyzo-core/src/session/generation.rs"
  - "crates/kyzo-core/src/session/hnsw.rs"
  - "crates/kyzo-core/src/session/host_clock.rs"
  - "crates/kyzo-core/src/session/jobs.rs"
  - "crates/kyzo-core/src/session/json.rs"
  - "crates/kyzo-core/src/session/lsh.rs"
  - "crates/kyzo-core/src/session/mod.rs"
  - "crates/kyzo-core/src/session/normalize.rs"
  - "crates/kyzo-core/src/session/normalize_tests.rs"
  - "crates/kyzo-core/src/session/observe.rs"
  - "crates/kyzo-core/src/session/ops.rs"
  - "crates/kyzo-core/src/session/test_rows.rs"
  - "crates/kyzo-core/src/session/verify.rs"
  - "crates/kyzo-core/src/store/authority.rs"
  - "crates/kyzo-core/src/store/backup.rs"
  - "crates/kyzo-core/src/store/commit_cap.rs"
  - "crates/kyzo-core/src/store/compact.rs"
  - "crates/kyzo-core/src/store/contract.rs"
  - "crates/kyzo-core/src/store/crypto.rs"
  - "crates/kyzo-core/src/store/failure.rs"
  - "crates/kyzo-core/src/store/fjall.rs"
  - "crates/kyzo-core/src/store/forge_wall.rs"
  - "crates/kyzo-core/src/store/grants.rs"
  - "crates/kyzo-core/src/store/idempotency.rs"
  - "crates/kyzo-core/src/store/merkle.rs"
  - "crates/kyzo-core/src/store/mod.rs"
  - "crates/kyzo-core/src/store/objects.rs"
  - "crates/kyzo-core/src/store/open.rs"
  - "crates/kyzo-core/src/store/replica.rs"
  - "crates/kyzo-core/src/store/retry.rs"
  - "crates/kyzo-core/src/store/scratch.rs"
  - "crates/kyzo-core/src/store/seal.rs"
  - "crates/kyzo-core/src/store/skip_walk.rs"
  - "crates/kyzo-core/src/store/sweep.rs"
  - "crates/kyzo-core/src/store/time.rs"
  - "crates/kyzo-core/src/store/transcript.rs"
  - "crates/kyzo-core/src/store/tx.rs"
  - "crates/kyzo-core/src/store/verify_walk.rs"
  - "crates/kyzo-core/src/store/wal.rs"
  - "crates/kyzo-core/src/rules/io/**/*.rs"
  - "crates/kyzo-core/src/parse/mod.rs"
  - "crates/kyzo-core/src/data/json.rs"
  - "crates/kyzo-core/src/data/mod.rs"
  - "crates/kyzo-model/src/parse/expr.rs"
  - "crates/kyzo-model/src/parse/mod.rs"
  - "crates/kyzo-model/src/parse/query.rs"
  - "crates/kyzo-model/src/parse/schema.rs"
  - "crates/kyzo-model/src/parse/script.rs"
  - "crates/kyzo-model/src/parse/search.rs"
  - "crates/kyzo-model/src/parse/sys.rs"
  - "crates/kyzo-model/src/envelope/**/*.rs"
  - "crates/kyzo-model/src/host_text.rs"
  - "crates/kyzo-model/src/value/arena.rs"
  - "crates/kyzo-model/src/value/json_convert.rs"
  - "crates/kyzo-crashfs/src/**/*.rs"
  - "vendor/fjall/src/**/*.rs"
  - "vendor/lsm-tree/src/**/*.rs"
description: "Boundary. Where unproven input becomes proven values, and where storage and clock effects happen."
purity:
  - set: rust
    version: "0.1.0"
capabilities: [filesystem, time]
---

# Boundary

Write the allowed construct. Anything that is not will always cause you to fail code review.

---

## Posture: Boundary

**Responsible for:** converting unproven input into proven values, and performing declared effects.

**Requires:** the module names its **entry points**. An entry point takes unproven input and returns a proven type or a typed error. Everything in a Boundary module that is not an entry point is held to Core.

This is the one place in the model where a primitive is correct in a parameter position, and the reason is precise: an entry point's parameters are not domain positions. They are unproven input, which is exactly what the entry point exists to convert. Requiring proven types there would only move the boundary somewhere with no law. The obligation is unchanged, not reduced: primitives on return types, on struct fields, and on anything passed inward still fire.

**Declares:** the capabilities named in the zone's law file, and no others. Declaring one is an addition to the zone's obligations, not a removal of the rest.

**May depend on:** Proof, Core, Boundary.

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

### RUST-B-01

**Rule:** Return `Result` from every entry point.

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

**Rule:** Return proven types from entry points.

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

**Rule:** Keep the wire type distinct from the domain type, and convert between them explicitly.

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

**Rule:** Prove once at construction.

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

**Rule:** Reach only the capabilities this zone's law file declares.

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

**Rule:** Parse raw input at the entry point.

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

**Rule:** Import from Proof, Core, and Boundary.

```rust allowed
use crate::core::plan::Plan;
```

```rust forbidden
use crate::shell::render::Renderer;
```
