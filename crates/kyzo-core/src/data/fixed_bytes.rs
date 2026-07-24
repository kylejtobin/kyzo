/*
 * Copyright 2026, The KyzoDB Authors.
 * KyzoDB is a fork of CozoDB (Copyright 2022, The Cozo Project Authors).
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file,
 * You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Proven fixed-width byte arrays — length is the type.
//!
//! Function signatures must not traffic naked `[u8; 12/32/64]` (naked_array_sig).
//! These newtypes are the typed length carriers: wrap doors take/return them,
//! and crate-local construction uses the tuple literal `Bytes32([...])` (an
//! expression, not a fn signature).

use sha2::digest::Output;
use sha2::Sha256;

/// Typed refuse when a slice is not the proven fixed width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
pub enum FixedLenRefuse {
    #[error("expected exactly 12 bytes, got {got}")]
    #[diagnostic(code(data::fixed_bytes::len12))]
    Expected12 { got: usize },
    #[error("expected exactly 32 bytes, got {got}")]
    #[diagnostic(code(data::fixed_bytes::len32))]
    Expected32 { got: usize },
    #[error("expected exactly 64 bytes, got {got}")]
    #[diagnostic(code(data::fixed_bytes::len64))]
    Expected64 { got: usize },
}

/// Proven 12-byte array (AEAD nonce width).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes12(pub(crate) [u8; 12]);

impl Bytes12 {
    /// All-zero 12-byte array.
    pub const ZERO: Self = Self([0u8; 12]);

    /// Fill every byte with `b`.
    pub const fn splat(b: u8) -> Self {
        Self([b; 12])
    }

    /// Boundary / buffer lift — length proven here.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, FixedLenRefuse> {
        let a: [u8; 12] = bytes
            .try_into()
            .map_err(|_| FixedLenRefuse::Expected12 { got: bytes.len() })?;
        Ok(Self(a))
    }

    /// Borrow as a byte slice (length 12 by construction).
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Fixed width.
    pub const LEN: usize = 12;
}

impl AsRef<[u8]> for Bytes12 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Proven 32-byte array (digest / key / MAC width).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes32(pub(crate) [u8; 32]);

impl Bytes32 {
    /// All-zero 32-byte array.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Fill every byte with `b`.
    pub const fn splat(b: u8) -> Self {
        Self([b; 32])
    }

    /// Boundary / buffer lift — length proven here.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, FixedLenRefuse> {
        let a: [u8; 32] = bytes
            .try_into()
            .map_err(|_| FixedLenRefuse::Expected32 { got: bytes.len() })?;
        Ok(Self(a))
    }

    /// Lift a SHA-256 finalize output (width is the hash's type).
    pub fn from_sha256(out: Output<Sha256>) -> Self {
        let mut a = [0u8; 32];
        a.copy_from_slice(out.as_slice());
        Self(a)
    }

    /// Borrow as a byte slice (length 32 by construction).
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Owned byte vector (wire / host edges that still speak `Vec<u8>`).
    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Fixed width.
    pub const LEN: usize = 32;
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Proven 64-byte array (ed25519 / FROST signature width).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes64(pub(crate) [u8; 64]);

impl Bytes64 {
    /// All-zero 64-byte array.
    pub const ZERO: Self = Self([0u8; 64]);

    /// Fill every byte with `b`.
    pub const fn splat(b: u8) -> Self {
        Self([b; 64])
    }

    /// Boundary / buffer lift — length proven here.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, FixedLenRefuse> {
        let a: [u8; 64] = bytes
            .try_into()
            .map_err(|_| FixedLenRefuse::Expected64 { got: bytes.len() })?;
        Ok(Self(a))
    }

    /// Borrow as a byte slice (length 64 by construction).
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Owned byte vector (wire / host edges that still speak `Vec<u8>`).
    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Fixed width.
    pub const LEN: usize = 64;
}

impl AsRef<[u8]> for Bytes64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
