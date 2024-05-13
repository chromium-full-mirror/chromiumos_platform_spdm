// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "mock")]
use mocktopus::macros::*;
use spdm_types::crypto::{EcP256UncompressedPoint, EC_P256_COORD_SIZE};
use spdm_types::deps::{Identity, IdentityPublicKey};

use super::crypto::TestCrypto;
use crate::IdentityPrivateKeyHandle;

// This is not a real EC point, but that's fine for test.
pub const TEST_IDENTITY_PUBLIC_KEY: EcP256UncompressedPoint = EcP256UncompressedPoint {
    x: [0x0A; EC_P256_COORD_SIZE],
    y: [0x0B; EC_P256_COORD_SIZE],
};

pub struct TestIdentity;

#[cfg_attr(feature = "mock", mockable)]
impl Identity for TestIdentity {
    type Crypto = TestCrypto;

    fn identity_public_key(&self) -> &IdentityPublicKey {
        &TEST_IDENTITY_PUBLIC_KEY
    }

    fn identity_private_key_handle(&self) -> &IdentityPrivateKeyHandle {
        &IdentityPrivateKeyHandle
    }

    fn is_public_key_valid(_public_key: &EcP256UncompressedPoint) -> bool {
        true
    }
}
