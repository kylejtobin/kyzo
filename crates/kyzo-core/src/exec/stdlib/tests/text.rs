/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Re-homed domain tables from data/tests/functions.rs.
use crate::exec::stdlib::text::op_chars;
use crate::exec::stdlib::text::op_ends_with;
use crate::exec::stdlib::text::op_from_substrings;
use crate::exec::stdlib::text::op_lowercase;
use crate::exec::stdlib::text::op_regex_extract;
use crate::exec::stdlib::text::op_regex_extract_first;
use crate::exec::stdlib::text::op_regex_matches;
use crate::exec::stdlib::text::op_regex_replace;
use crate::exec::stdlib::text::op_regex_replace_all;
use crate::exec::stdlib::text::op_starts_with;
use crate::exec::stdlib::text::op_str_includes;
use crate::exec::stdlib::text::op_trim;
use crate::exec::stdlib::text::op_trim_end;
use crate::exec::stdlib::text::op_trim_start;
use crate::exec::stdlib::text::op_unicode_normalize;
use crate::exec::stdlib::text::op_uppercase;
use kyzo_model::value::DataValue;
use miette::{Result, miette};

#[test]
fn test_str_includes() -> Result<()> {
    assert_eq!(
        op_str_includes(&[
            DataValue::Str("abcdef".into()),
            DataValue::Str("bcd".into())
        ])?,
        DataValue::from(true)
    );
    assert_eq!(
        op_str_includes(&[DataValue::Str("abcdef".into()), DataValue::Str("bd".into())])?,
        DataValue::from(false)
    );
    Ok(())
}

#[test]
fn test_casings() -> Result<()> {
    assert_eq!(
        op_lowercase(&[DataValue::Str("NAÏVE".into())])?,
        DataValue::Str("naïve".into())
    );
    assert_eq!(
        op_uppercase(&[DataValue::Str("naïve".into())])?,
        DataValue::Str("NAÏVE".into())
    );
    Ok(())
}

#[test]
fn test_trim() -> Result<()> {
    assert_eq!(
        op_trim(&[DataValue::Str(" a ".into())])?,
        DataValue::Str("a".into())
    );
    assert_eq!(
        op_trim_start(&[DataValue::Str(" a ".into())])?,
        DataValue::Str("a ".into())
    );
    assert_eq!(
        op_trim_end(&[DataValue::Str(" a ".into())])?,
        DataValue::Str(" a".into())
    );
    Ok(())
}

#[test]
fn test_starts_ends_with() -> Result<()> {
    assert_eq!(
        op_starts_with(&[
            DataValue::Str("abcdef".into()),
            DataValue::Str("abc".into())
        ])?,
        DataValue::from(true)
    );
    assert_eq!(
        op_starts_with(&[DataValue::Str("abcdef".into()), DataValue::Str("bc".into())])?,
        DataValue::from(false)
    );
    assert_eq!(
        op_ends_with(&[
            DataValue::Str("abcdef".into()),
            DataValue::Str("def".into())
        ])?,
        DataValue::from(true)
    );
    assert_eq!(
        op_ends_with(&[DataValue::Str("abcdef".into()), DataValue::Str("bc".into())])?,
        DataValue::from(false)
    );
    Ok(())
}

#[test]
fn test_regex() -> Result<()> {
    assert_eq!(
        op_regex_matches(&[
            DataValue::Str("abcdef".into()),
            DataValue::Regex(
                kyzo_model::value::RegexSource::validated(
                    kyzo_model::value::RegexFlags::none(),
                    "c.e".into()
                )
                .map_err(|e| miette!("{e}"))?
            )
        ])?,
        DataValue::from(true)
    );

    assert_eq!(
        op_regex_matches(&[
            DataValue::Str("abcdef".into()),
            DataValue::Regex(
                kyzo_model::value::RegexSource::validated(
                    kyzo_model::value::RegexFlags::none(),
                    "c.ef$".into()
                )
                .map_err(|e| miette!("{e}"))?
            )
        ])?,
        DataValue::from(true)
    );

    assert_eq!(
        op_regex_matches(&[
            DataValue::Str("abcdef".into()),
            DataValue::Regex(
                kyzo_model::value::RegexSource::validated(
                    kyzo_model::value::RegexFlags::none(),
                    "c.e$".into()
                )
                .map_err(|e| miette!("{e}"))?
            )
        ])?,
        DataValue::from(false)
    );

    assert_eq!(
        op_regex_replace(&[
            DataValue::Str("abcdef".into()),
            DataValue::Regex(
                kyzo_model::value::RegexSource::validated(
                    kyzo_model::value::RegexFlags::none(),
                    "[be]".into()
                )
                .map_err(|e| miette!("{e}"))?
            ),
            DataValue::Str("x".into())
        ])?,
        DataValue::Str("axcdef".into())
    );

    assert_eq!(
        op_regex_replace_all(&[
            DataValue::Str("abcdef".into()),
            DataValue::Regex(
                kyzo_model::value::RegexSource::validated(
                    kyzo_model::value::RegexFlags::none(),
                    "[be]".into()
                )
                .map_err(|e| miette!("{e}"))?
            ),
            DataValue::Str("x".into())
        ])?,
        DataValue::Str("axcdxf".into())
    );
    assert_eq!(
        op_regex_extract(&[
            DataValue::Str("abCDefGH".into()),
            DataValue::Regex(
                kyzo_model::value::RegexSource::validated(
                    kyzo_model::value::RegexFlags::none(),
                    "[xayef]|(GH)".into()
                )
                .map_err(|e| miette!("{e}"))?
            )
        ])?,
        DataValue::List(vec![
            DataValue::Str("a".into()),
            DataValue::Str("e".into()),
            DataValue::Str("f".into()),
            DataValue::Str("GH".into()),
        ])
    );
    assert_eq!(
        op_regex_extract_first(&[
            DataValue::Str("abCDefGH".into()),
            DataValue::Regex(
                kyzo_model::value::RegexSource::validated(
                    kyzo_model::value::RegexFlags::none(),
                    "[xayef]|(GH)".into()
                )
                .map_err(|e| miette!("{e}"))?
            )
        ])?,
        DataValue::Str("a".into()),
    );
    assert_eq!(
        op_regex_extract(&[
            DataValue::Str("abCDefGH".into()),
            DataValue::Regex(
                kyzo_model::value::RegexSource::validated(
                    kyzo_model::value::RegexFlags::none(),
                    "xyz".into()
                )
                .map_err(|e| miette!("{e}"))?
            )
        ])?,
        DataValue::List(vec![])
    );

    assert_eq!(
        op_regex_extract_first(&[
            DataValue::Str("abCDefGH".into()),
            DataValue::Regex(
                kyzo_model::value::RegexSource::validated(
                    kyzo_model::value::RegexFlags::none(),
                    "xyz".into()
                )
                .map_err(|e| miette!("{e}"))?
            )
        ])?,
        DataValue::Null
    );
    Ok(())
}

#[test]
fn test_unicode_normalize() -> Result<()> {
    assert_eq!(
        op_unicode_normalize(&[DataValue::Str("abc".into()), DataValue::Str("nfc".into())])?,
        DataValue::Str("abc".into())
    );
    Ok(())
}

#[test]
fn test_chars() -> Result<()> {
    assert_eq!(
        op_from_substrings(&[op_chars(&[DataValue::Str("abc".into())])?])?,
        DataValue::Str("abc".into())
    );
    Ok(())
}
