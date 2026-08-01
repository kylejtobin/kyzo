/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! text.rs — stdlib kernel (move_plan).

use itertools::Itertools;
use miette::{Result, bail, ensure, miette};
use unicode_normalization::UnicodeNormalization;

use kyzo_model::value::json_convert::to_json;
use kyzo_model::value::{DataValue, Json, RegexFlags, RegexSource};

pub(crate) fn op_chars(args: &[DataValue]) -> Result<DataValue> {
    Ok(DataValue::List(
        args[0]
            .get_str()
            .ok_or_else(|| miette!("'chars' requires strings"))?
            .chars()
            .map(|c| DataValue::from(c.to_string()))
            .collect_vec(),
    ))
}

fn affix_op(
    op: &'static str,
    args: &[DataValue],
    on_str: impl FnOnce(&str, &str) -> bool,
    on_bytes: impl FnOnce(&[u8], &[u8]) -> bool,
) -> Result<DataValue> {
    match (&args[0], &args[1]) {
        (DataValue::Str(l), DataValue::Str(r)) => Ok(DataValue::from(on_str(l, r))),
        (DataValue::Bytes(l), DataValue::Bytes(r)) => Ok(DataValue::from(on_bytes(l, r))),
        (DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_), DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_)) => bail!("'{op}' requires strings or bytes"),
    }
}

pub(crate) fn op_ends_with(args: &[DataValue]) -> Result<DataValue> {
    affix_op(
        "ends_with",
        args,
        |l, r| l.ends_with(r),
        |l, r| l.ends_with(r),
    )
}

pub(crate) fn op_from_substrings(args: &[DataValue]) -> Result<DataValue> {
    let mut ret = String::new();
    match &args[0] {
        DataValue::List(ss) => {
            for arg in ss {
                if let DataValue::Str(s) = arg {
                    ret.push_str(s);
                } else {
                    bail!("'from_substring' requires a list of strings")
                }
            }
        }
        DataValue::Set(ss) => {
            for arg in ss {
                if let DataValue::Str(s) = arg {
                    ret.push_str(s);
                } else {
                    bail!("'from_substring' requires a list of strings")
                }
            }
        }
        DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_) => bail!("'from_substring' requires a list of strings"),
    }
    Ok(DataValue::from(ret))
}

pub(crate) fn op_lowercase(args: &[DataValue]) -> Result<DataValue> {
    match &args[0] {
        DataValue::Str(s) => Ok(DataValue::from(s.to_lowercase())),
        DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_) => bail!("'lowercase' requires strings"),
    }
}

pub(crate) fn op_regex(args: &[DataValue]) -> Result<DataValue> {
    Ok(match &args[0] {
        r @ DataValue::Regex(_) => r.clone(),
        DataValue::Str(s) => DataValue::Regex(
            RegexSource::validated(RegexFlags::none(), s.clone())
                .map_err(|err| miette!("The string cannot be interpreted as regex: {err:?}"))?,
        ),
        DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_) => bail!("'regex' requires strings"),
    })
}

pub(crate) fn op_regex_extract(args: &[DataValue]) -> Result<DataValue> {
    match (&args[0], &args[1]) {
        (DataValue::Str(s), DataValue::Regex(r)) => {
            let compiled = compile_regex_value(r)?;
            let found = compiled.find_iter(s).map(DataValue::from).collect_vec();
            Ok(DataValue::List(found))
        }
        (DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_), DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_)) => bail!("'regex_extract' requires strings"),
    }
}

pub(crate) fn op_regex_extract_first(args: &[DataValue]) -> Result<DataValue> {
    match (&args[0], &args[1]) {
        (DataValue::Str(s), DataValue::Regex(r)) => {
            let found = compile_regex_value(r)?.find(s).map(DataValue::from);
            Ok(match found {
                Some(v) => v,
                None => {
            // Absent cell — SQL NULL is the published render.
            DataValue::Null
        },
            })
        }
        (DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_), DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_)) => bail!("'regex_extract_first' requires strings"),
    }
}

pub(crate) fn op_regex_matches(args: &[DataValue]) -> Result<DataValue> {
    match (&args[0], &args[1]) {
        (DataValue::Str(s), DataValue::Regex(r)) => {
            Ok(DataValue::from(compile_regex_value(r)?.is_match(s)))
        }
        (DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_), DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_)) => bail!("'regex_matches' requires strings"),
    }
}

pub(crate) fn op_regex_replace(args: &[DataValue]) -> Result<DataValue> {
    op_regex_replace_with(args, "regex_replace", |compiled, s, rp| {
        compiled.replace(s, rp)
    })
}

pub(crate) fn op_regex_replace_all(args: &[DataValue]) -> Result<DataValue> {
    op_regex_replace_with(args, "regex_replace_all", |compiled, s, rp| {
        compiled.replace_all(s, rp)
    })
}

fn op_regex_replace_with(
    args: &[DataValue],
    op_name: &str,
    replace: impl for<'a, 'b, 'c> FnOnce(
        &'a kyzo_model::value::CompiledRegexV1,
        &'b str,
        &'c str,
    ) -> std::borrow::Cow<'b, str>,
) -> Result<DataValue> {
    match (&args[0], &args[1], &args[2]) {
        (DataValue::Str(s), DataValue::Regex(r), DataValue::Str(rp)) => Ok(DataValue::Str(
            replace(&compile_regex_value(r)?, s, rp).into_owned(),
        )),
        (DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_), DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_), DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_)) => {
            bail!("'{op_name}' requires strings")
        }
    }
}

pub(crate) fn op_slice_string(args: &[DataValue]) -> Result<DataValue> {
    let s = args[0]
        .get_str()
        .ok_or_else(|| miette!("first argument to 'slice_string' mut be a string"))?;
    let m = args[1]
        .get_int()
        .ok_or_else(|| miette!("second argument to 'slice_string' mut be an integer"))?;
    ensure!(
        m >= 0,
        "second argument to 'slice_string' mut be a positive integer"
    );
    let n = args[2]
        .get_int()
        .ok_or_else(|| miette!("third argument to 'slice_string' mut be an integer"))?;
    ensure!(
        n >= m,
        "third argument to 'slice_string' mut be a positive integer greater than the second argument"
    );
    let skip = match usize::try_from(m) {
        Ok(v) => v,
        Err(_neg) => {
            bail!("second argument to 'slice_string' mut be a positive integer");
        }
    };
    let take = match usize::try_from(n - m) {
        Ok(v) => v,
        Err(_neg) => {
            bail!(
                "third argument to 'slice_string' mut be a positive integer greater than the second argument"
            );
        }
    };
    Ok(DataValue::Str(s.chars().skip(skip).take(take).collect()))
}

pub(crate) fn op_starts_with(args: &[DataValue]) -> Result<DataValue> {
    affix_op(
        "starts_with",
        args,
        |l, r| l.starts_with(r),
        |l, r| l.starts_with(r),
    )
}

pub(crate) fn op_str_includes(args: &[DataValue]) -> Result<DataValue> {
    match (&args[0], &args[1]) {
        (DataValue::Str(l), DataValue::Str(r)) => Ok(DataValue::from(l.find(r.as_str()).is_some())),
        (DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_), DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_)) => bail!("'str_includes' requires strings"),
    }
}

pub(crate) fn op_t2s(args: &[DataValue]) -> Result<DataValue> {
    Ok(match &args[0] {
        DataValue::Str(s) => DataValue::Str(fast2s::convert(s)),
        d @ (DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_)) => d.clone(),
    })
}

pub(crate) fn op_trim(args: &[DataValue]) -> Result<DataValue> {
    match &args[0] {
        DataValue::Str(s) => Ok(DataValue::from(s.trim())),
        DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_) => bail!("'trim' requires strings"),
    }
}

pub(crate) fn op_trim_end(args: &[DataValue]) -> Result<DataValue> {
    match &args[0] {
        DataValue::Str(s) => Ok(DataValue::from(s.trim_end())),
        DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_) => bail!("'trim_end' requires strings"),
    }
}

pub(crate) fn op_trim_start(args: &[DataValue]) -> Result<DataValue> {
    match &args[0] {
        DataValue::Str(s) => Ok(DataValue::from(s.trim_start())),
        v @ (DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_)) => bail!("'trim_start' requires strings, got {}", v),
    }
}

pub(crate) fn op_unicode_normalize(args: &[DataValue]) -> Result<DataValue> {
    match (&args[0], &args[1]) {
        (DataValue::Str(s), DataValue::Str(n)) => Ok(DataValue::Str(match n.as_str() {
            "nfc" => s.nfc().collect(),
            "nfd" => s.nfd().collect(),
            "nfkc" => s.nfkc().collect(),
            "nfkd" => s.nfkd().collect(),
            u => bail!("unknown normalization {} for 'unicode_normalize'", u),
        })),
        (DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_), DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_)) => bail!("'unicode_normalize' requires strings"),
    }
}

pub(crate) fn op_uppercase(args: &[DataValue]) -> Result<DataValue> {
    match &args[0] {
        DataValue::Str(s) => Ok(DataValue::from(s.to_uppercase())),
        DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_) => bail!("'uppercase' requires strings"),
    }
}

/// Compile a regex VALUE for execution. The value itself is storage
/// identity only (`RegexSource` — deliberately no compiled state inside
/// the value plane); the parser's constant-folding hoists `op_regex` so
/// patterns validate once at compile time, but row-wise execution
/// recompiles here. A future optimization would hoist COMPILATION (not
/// just validation) into the operator layer instead, measured by the bench
/// lane.
fn compile_regex_value(r: &RegexSource) -> Result<kyzo_model::value::CompiledRegexV1> {
    r.compile()
        .map_err(|err| miette!("stored regex failed to compile: {err:?}"))
}

pub(crate) fn val2str(arg: &DataValue) -> String {
    match arg {
        DataValue::Str(s) => s.to_string(),
        DataValue::Json(j) => match j {
            Json::Str(s) => s.clone(),
            Json::Null | Json::Bool(_) | Json::Num(_) | Json::Arr(_) | Json::Obj(_) => {
                to_json(arg).to_string()
            }
        },
        DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_) => {
            let jv = to_json(arg);
            jv.to_string()
        }
    }
}
