---
law_format: 1
assignment: zone
zone: shell
paths:
  - "crates/kyzo-bin/src/**/*.rs"
  - "crates/kyzo-lsp/src/**/*.rs"
  - "crates/xtask/src/**/*.rs"
  - "crates/bs-detector/src/**/*.rs"
  - "crates/canonical-trials/src/**/*.rs"
  - "crates/canonical-forgery/src/**/*.rs"
  - "crates/kyzo-trials/src/**/*.rs"
  - "crates/kyzo-arrow-interop/src/**/*.rs"
  - "crates/kyzo-core/src/bench_recovery.rs"
  - "crates/kyzo-core/src/lib.rs"
  - "crates/*/tests/**/*.rs"
  - "crates/*/benches/**/*.rs"
  - "crates/*/examples/**/*.rs"
  - "crates/*/build.rs"
  - "crates/kyzo-trials/rehomed_from_core/**/*.rs"
  - "fuzz/fuzz_targets/**/*.rs"
  - "vendor/*/tests/**/*.rs"
  - "vendor/*/benches/**/*.rs"
  - "vendor/*/examples/**/*.rs"
  - "vendor/*/build.rs"
description: "Shell. Composition, marshaling, rendering, termination, and the harnesses that judge the engine."
purity:
  - set: rust
    version: "0.1.0"
capabilities: [filesystem, process, time, randomness]
---

# Shell

Write the allowed construct. Anything that is not will always cause you to fail code review.

---

## Posture: Shell

**Responsible for:** composition, marshaling, rendering, and termination.

**Requires:** the process exit lives here and nowhere else. Shell holds the capabilities the other postures declared and passes them down as arguments. It converts typed verdicts into output and exit codes, and it interprets nothing beyond that.

**Declares:** the capabilities named in the zone's law file. Shell is where a program's capabilities normally live, and each is named rather than assumed from the posture.

**May depend on:** Proof, Core, Boundary, Shell.

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

### RUST-SH-01

**Rule:** Match on the typed error.

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

**Rule:** Reach only the capabilities this zone's law file declares, and pass them down as arguments.

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

**Rule:** Read through the owning module on every request.

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

**Rule:** Construct domain values by calling a Boundary entry point.

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
