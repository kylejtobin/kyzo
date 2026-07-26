/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! nondet.rs — stdlib kernel (move_plan).
use std::time::Duration;

use itertools::Itertools;
use rand::Rng;
use rand::seq::IndexedRandom;
use miette::{Result, bail, ensure, miette};
use uuid::v1::Timestamp;

use kyzo_model::value::DataValue;

use crate::exec::stdlib::convert::vec_element_type;
use crate::exec::stdlib::errors::vec_value;
use kyzo_model::schema::VecElementType;

pub(crate) fn op_now(_args: &[DataValue]) -> Result<DataValue> {
    Ok(DataValue::from(unix_now()?.as_secs_f64()))
}

pub(crate) fn op_rand_bernoulli(args: &[DataValue]) -> Result<DataValue> {
    let prob = match &args[0] {
        DataValue::Num(n) => {
            let f = n.to_f64();
            ensure!(
                (0. ..=1.).contains(&f),
                "'rand_bernoulli' requires number between 0. and 1."
            );
            f
        }
        DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_) => bail!("'rand_bernoulli' requires number between 0. and 1."),
    };
    Ok(DataValue::from(rand::rng().random_bool(prob)))
}

pub(crate) fn op_rand_choose(args: &[DataValue]) -> Result<DataValue> {
    match &args[0] {
        DataValue::List(l) => Ok(match l.choose(&mut rand::rng()).cloned() {
            Some(v) => v,
            None => {
            // Absent cell — SQL NULL is the published render.
            DataValue::Null
        },
        }),
        DataValue::Set(l) => Ok(
            match l
                .iter()
                .collect_vec()
                .choose(&mut rand::rng())
                .cloned()
                .cloned()
            {
                Some(v) => v,
                None => {
            // Absent cell — SQL NULL is the published render.
            DataValue::Null
        },
            },
        ),
        DataValue::Null | DataValue::Bool(_) | DataValue::Num(_) | DataValue::Str(_) | DataValue::Bytes(_) | DataValue::Uuid(_) | DataValue::Regex(_) | DataValue::Json(_) | DataValue::Vector(_) | DataValue::List(_) | DataValue::Set(_) | DataValue::Validity(_) | DataValue::Interval(_) | DataValue::Geometry(_) => bail!("'rand_choice' requires lists"),
    }
}

pub(crate) fn op_rand_float(_args: &[DataValue]) -> Result<DataValue> {
    Ok(rand::rng().random::<f64>().into())
}

pub(crate) fn op_rand_int(args: &[DataValue]) -> Result<DataValue> {
    let lower = &args[0]
        .get_int()
        .ok_or_else(|| miette!("'rand_int' requires integers"))?;
    let upper = &args[1]
        .get_int()
        .ok_or_else(|| miette!("'rand_int' requires integers"))?;
    // Checked here because rand 0.9's `random_range` panics on an empty
    // range, and an op body must never panic on user input.
    ensure!(
        lower <= upper,
        "'rand_int' requires a lower bound not greater than the upper bound"
    );
    Ok(rand::rng().random_range(*lower..=*upper).into())
}

pub(crate) fn op_rand_uuid_v1(_args: &[DataValue]) -> Result<DataValue> {
    let mut rng = rand::rng();
    let uuid_ctx = uuid::ContextV1::new(rng.random());
    let ts = {
        let since_epoch = unix_now()?;
        Timestamp::from_unix(uuid_ctx, since_epoch.as_secs(), since_epoch.subsec_nanos())
    };
    let mut rand_vals = [0u8; 6];
    rng.fill(&mut rand_vals);
    let id = uuid::Uuid::new_v1(ts, &rand_vals);
    Ok(DataValue::uuid(id))
}

pub(crate) fn op_rand_uuid_v4(_args: &[DataValue]) -> Result<DataValue> {
    let id = uuid::Uuid::new_v4();
    Ok(DataValue::uuid(id))
}

pub(crate) fn op_rand_vec(args: &[DataValue]) -> Result<DataValue> {
    let len_i = args[0]
        .get_int()
        .ok_or_else(|| miette!("'rand_vec' requires an integer"))?;
    let len = usize::try_from(len_i)
        .map_err(|_| miette!("'rand_vec' length must be non-negative, got {len_i}"))?;
    let t = vec_element_type(args.get(1), "rand_vec")?;

    let mut rng = rand::rng();
    let components: Vec<f64> = (0..len)
        .map(|_| match t {
            VecElementType::F32 => {
                crate::exec::stdlib::convert::via_f32_precision(rng.random::<f64>())
            }
            VecElementType::F64 => rng.random::<f64>(),
        })
        .collect();
    Ok(DataValue::Vector(vec_value(components)?))
}

/// The host clock as a duration since the Unix epoch.
///
/// Policy (documented choice): a clock reading before 1970 is an **error**,
/// not saturation — a time-travel database whose host clock is decades wrong
/// should refuse loudly rather than silently write validity at the epoch.
/// The CozoDB original unwrapped and aborted the process.
fn unix_now() -> Result<Duration> {
    // Wall micros from the session host-clock seat — never Instant/SystemTime here.
    let micros = crate::session::host_clock::wall_micros()?;
    let micros_u64 = u64::try_from(micros).map_err(|_| {
        miette!("system clock before the epoch (negative micros)")
    })?;
    Ok(Duration::from_micros(micros_u64))
}
