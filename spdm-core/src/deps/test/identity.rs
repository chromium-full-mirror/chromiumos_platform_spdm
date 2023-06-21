// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::crypto::TestCrypto;
use super::Identity;
use crate::deps::IdentityPublicKey;
use crate::types::crypto::{EcP256UncompressedPoint, EC_P256_COORD_SIZE};

// This is not a real EC point, but that's fine for test.
pub const TEST_IDENTITY_PUBLIC_KEY: EcP256UncompressedPoint = EcP256UncompressedPoint {
    x: [0x0A; EC_P256_COORD_SIZE],
    y: [0x0B; EC_P256_COORD_SIZE],
};

pub struct TestIdentity;

impl Identity for TestIdentity {
    type Crypto = TestCrypto;

    fn identity_public_key(&self) -> &IdentityPublicKey {
        &TEST_IDENTITY_PUBLIC_KEY
    }

    fn identity_private_key_handle(&self) -> &() {
        &()
    }
}
