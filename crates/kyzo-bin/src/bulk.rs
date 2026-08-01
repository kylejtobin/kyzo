/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Bulk relation import for the REPL's `%import`.
//!
//! The CozoDB original (`cozo-core/src/runtime/db.rs::import_relations`)
//! reached directly into a live transaction's storage — `Engine`'s
//! internals in this port are crate-private (`session/db.rs`'s `SessionTx`
//! constructors are `pub(crate)`; there is no equivalent public surface),
//! so this is composed instead from the same public entry point every
//! other caller uses: [`Engine::run_script`]. A `<-` mutation with `$data`
//! bound to the rows writes them — the same query shape the CozoDB
//! original used for its `NamedRows::into_payload` convenience method.
//! This is less direct than a hand-rolled storage walk, but it is the
//! only route kyzo-core's runtime tier currently exposes, and it is
//! correct: every step is a real query the engine already proves sound.
//!
//! Every relation and column name here (a JSON object key or header for
//! `%import`) gets spliced into composed KyzoScript via `format!`, so each
//! is validated first ([`validate_identifier`]) against the grammar's
//! `compound_ident` shape (`kyzoscript.pest`: dot-separated segments, each
//! starting with a letter/underscore and continuing with
//! letters/digits/underscores — the ASCII subset of
//! `XID_START`/`XID_CONTINUE`). A caller reaching this door already has
//! full script privilege, so this is not privilege escalation; it closes
//! off a name smuggling extra script syntax (a stray `}`, a second
//! statement, a different target relation) into a query this module builds
//! on the caller's behalf.

use std::collections::BTreeMap;

use kyzo::{DataValue, Engine, FjallStorage, NamedRows};
use kyzo_model::SourceSpan;
use kyzo_model::program::symbol::Symbol;
use miette::{Result, bail, miette};

/// Is `name` safe to splice into composed KyzoScript as a bare identifier
/// (a relation or column name)? Requires the ASCII subset of the grammar's
/// `compound_ident`: one or more `.`-separated, non-empty segments, each an
/// ASCII letter-or-underscore followed by ASCII letters/digits/underscores.
/// Rejects anything that could smuggle script syntax through — spaces,
/// braces, colons, quotes, `$`, `<-`, `~`, etc.
pub(crate) fn validate_identifier(name: &str) -> Result<()> {
    let is_valid_segment = |segment: &str| {
        let mut chars = segment.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if !name.is_empty() && name.split('.').all(is_valid_segment) {
        Ok(())
    } else {
        bail!("'{name}' is not a valid identifier")
    }
}

/// Import `{relation_name: NamedRows}` into the store. A name prefixed with
/// `-` deletes the given rows from that relation instead of writing them
/// (`:rm` instead of `:put` — the same convention the CozoDB original's
/// direct-storage `import_relations` used).
pub fn import_relations(
    db: &Engine<FjallStorage>,
    data: BTreeMap<String, NamedRows>,
) -> Result<()> {
    for (relation_op, rows) in data {
        let (op, relation) = match relation_op.strip_prefix('-') {
            Some(rel) => (":rm", rel),
            None => (":put", relation_op.as_str()),
        };
        validate_identifier(relation)?;
        if rows.headers().is_empty() {
            continue;
        }
        for col in rows.headers() {
            validate_identifier(col.name())?;
        }
        let cols_str = rows
            .headers()
            .iter()
            .map(|col| col.name().as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let query = format!("?[{cols_str}] <- $data {op} {relation} {{{cols_str}}}");
        let data_value = DataValue::List(
            rows.into_rows()
                .into_iter()
                .map(|row| DataValue::List(row.into_vec()))
                .collect(),
        );
        db.run_script(
            &query,
            BTreeMap::from([(
                Symbol::new("data", SourceSpan::empty()),
                data_value,
            )]),
        )
            .map_err(|e| miette!("cannot import data for relation '{relation}': {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_identifier;

    #[test]
    fn accepts_plain_and_compound_identifiers() {
        assert!(validate_identifier("person").is_ok());
        assert!(validate_identifier("_temp").is_ok());
        assert!(validate_identifier("a1_b2").is_ok());
        assert!(validate_identifier("ns.person").is_ok());
        assert!(validate_identifier("a.b.c").is_ok());
    }

    #[test]
    fn rejects_empty_and_malformed_segments() {
        assert!(validate_identifier("").is_err());
        assert!(validate_identifier("1abc").is_err());
        assert!(validate_identifier("a..b").is_err());
        assert!(validate_identifier(".a").is_err());
        assert!(validate_identifier("a.").is_err());
    }

    #[test]
    fn rejects_script_injection_attempts() {
        for hostile in [
            "person} <- [[1]] :put other {x",
            "person {x: 1}",
            "person; ?[x] <- [[1]]",
            "person$evil",
            "person\nrm",
            "person ",
            " person",
            "*person",
            "~person",
            "person<-x",
        ] {
            assert!(
                validate_identifier(hostile).is_err(),
                "expected rejection for {hostile:?}"
            );
        }
    }
}
