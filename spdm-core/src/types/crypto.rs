// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::mem::size_of;

use zerocopy::{AsBytes, FromBytes};

/// Elliptic curve NIST P-256 coordinate point size in bytes
pub const EC_P256_COORD_SIZE: usize = 32;

pub type EcP256Coord = [u8; EC_P256_COORD_SIZE];

#[repr(C, packed)]
#[derive(AsBytes, FromBytes)]
pub struct EcP256UncompressedPoint {
    pub x: EcP256Coord,
    pub y: EcP256Coord,
}

impl EcP256UncompressedPoint {
    pub const SIZE: usize = size_of::<Self>();
}
