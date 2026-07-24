/*
 * Copyright 2026, The KyzoDB Authors.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Host text that is not a Kyzo Value `Str` ([`crate::value::string::GermanStr`]).
//!
//! One authority for owned and borrowed non-Value text: CLI leftovers,
//! HTTP headers, scratch buffers, relation-name tokens that are not yet
//! [`crate::program::Symbol`]. Do not add a second `String` newtype.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Owned host text. The only `String` newtype for non-Value text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostText(String);

impl HostText {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn push_str(&mut self, s: &str) {
        self.0.push_str(s);
    }

    /// Swap/buffer door for tokenizers that still hold a raw `String` cell.
    pub fn as_mut_string(&mut self) -> &mut String {
        &mut self.0
    }
}

impl Deref for HostText {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for HostText {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for HostText {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl FromStr for HostText {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl fmt::Display for HostText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for HostText {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<std::path::Path> for HostText {
    fn as_ref(&self) -> &std::path::Path {
        self.0.as_ref()
    }
}

impl PartialEq<str> for HostText {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for HostText {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl Serialize for HostText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HostText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// Borrowed host text. The only `&str` newtype for non-Value text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TextRef<'a>(&'a str);

impl<'a> TextRef<'a> {
    pub const fn new(s: &'a str) -> Self {
        Self(s)
    }

    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

impl Deref for TextRef<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl AsRef<str> for TextRef<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}
