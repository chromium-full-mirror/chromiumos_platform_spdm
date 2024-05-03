// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm_types::crypto::EcP256UncompressedPoint;
use spdm_types::deps::{Identity, IdentityPublicKey};

use super::crypto::{CryptoImpl, IdentityPrivateKeyTag, RawKey};

pub struct IdentityImpl;

// TODO(b/338528575): Implement Identity for IdentityImpl.
impl Identity for IdentityImpl {
    type Crypto = CryptoImpl;

    fn identity_public_key(&self) -> &IdentityPublicKey {
        unimplemented!()
    }

    fn identity_private_key_handle(&self) -> &RawKey<IdentityPrivateKeyTag> {
        unimplemented!()
    }

    fn is_public_key_valid(_public_key: &EcP256UncompressedPoint) -> bool {
        unimplemented!()
    }
}
