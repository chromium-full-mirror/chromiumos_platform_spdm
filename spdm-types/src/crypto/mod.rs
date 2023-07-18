// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::mem::size_of;

use zerocopy::{AsBytes, FromBytes};

/// Elliptic curve NIST P-256 coordinate point size in bytes
pub const EC_P256_COORD_SIZE: usize = 32;
/// Elliptic curve NIST P-256 scalar size in bytes.
pub const ECDSA_P256_SCALAR_SIZE: usize = 32;
pub const ECDSA_P256_SIGNATURE_SIZE: usize = 64;

/// SHA256 hash digest size in bytes.
pub const SHA256_HASH_SIZE: usize = 32;
pub type Sha256Hash = [u8; SHA256_HASH_SIZE];

pub type EcP256Coord = [u8; EC_P256_COORD_SIZE];
pub type EcdsaP256Scalar = [u8; ECDSA_P256_SCALAR_SIZE];

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, Clone)]
pub struct EcP256UncompressedPoint {
    pub x: EcP256Coord,
    pub y: EcP256Coord,
}

impl EcP256UncompressedPoint {
    pub const SIZE: usize = size_of::<Self>();
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes)]
pub struct EcdsaP256Signature {
    pub r: EcdsaP256Scalar,
    pub s: EcdsaP256Scalar,
}
