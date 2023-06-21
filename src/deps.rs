// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::deps::{Crypto, Identity, IdentityPublicKey, SpdmDeps};

/// Implements Crypto by interacting with the static eal functions.
pub struct EalCrypto;

impl Crypto for EalCrypto {}

/// Implements Identity by interacting with the static eal functions.
pub struct EalIdentity;

impl Identity for EalIdentity {
    type Crypto = EalCrypto;

    fn identity_public_key(&self) -> &IdentityPublicKey {
        unimplemented!()
    }
}

pub struct SpdmEalDeps;

impl SpdmDeps for SpdmEalDeps {
    type Crypto = EalCrypto;
    type Identity = EalIdentity;
}
